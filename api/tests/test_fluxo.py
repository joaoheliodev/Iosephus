"""Fluxo completo: ingestão -> correlação -> incidente -> dashboard -> reconciliação.

Usa um MySQL de verdade (o schema e os GRANTs do repositório) e o mongomock no lugar do MongoDB.
Prepare o banco com:  MYSQL_APP_PASSWORD=teste ./scripts/criar_banco_teste.sh
e rode:               IOSEPHUS_TESTE_MYSQL=1 pytest
"""
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mongomock
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

pytestmark = pytest.mark.skipif(not os.environ.get("IOSEPHUS_TESTE_MYSQL"),
                                reason="precisa de MySQL local (IOSEPHUS_TESTE_MYSQL=1)")

RAIZ = Path(__file__).resolve().parents[2]
CHAVE = "chave-de-teste-do-provedor-com-32-caracteres"
CHAVE_VALE_VERDE = "chave-de-teste-presa-a-organizacao-7"
os.environ.setdefault("MYSQL_URL", "mysql+pymysql://app_soc:teste@127.0.0.1:3306/iosephus?charset=utf8mb4")
os.environ.setdefault("MONGO_URL", "mongodb://nao-usado")
os.environ["INGEST_API_KEY"] = CHAVE
os.environ["INGEST_API_KEYS"] = f"7:{CHAVE_VALE_VERDE}"
os.environ["JWT_SECRET"] = "segredo-de-teste-com-tamanho-suficiente-32"
os.environ["WORKER_ATIVO"] = "false"


def _simulador():
    spec = importlib.util.spec_from_file_location("simulador", RAIZ / "scripts" / "simular_ataque.py")
    sys.argv = ["simular_ataque.py"]
    os.environ["INGEST_API_KEY"] = CHAVE
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def ambiente():
    from fastapi.testclient import TestClient

    from app import db
    from app.auth import gerar_hash
    from app.main import app

    m = mongomock.MongoClient(tz_aware=True)["iosephus"]
    m.indicadores_ameaca.insert_one({"tipo": "ipv4", "valor": "203.0.113.45", "tags": ["rdp-bruteforce"],
                                     "fontes": [{"nome": "AbuseIPDB", "confianca": 90}]})
    db.usar_mongo(m)
    with db.mysql().begin() as c:
        for email in ("analista2@iosephus.local", "analista3@iosephus.local", "ti@valeverde.example",
                      "motor@iosephus.local"):
            c.execute(text("UPDATE usuarios SET senha_hash = :h WHERE email = :e"),
                      {"h": gerar_hash("senha-de-teste-123"), "e": email})
    with TestClient(app) as cliente:
        yield cliente, m


def _login(cliente, email):
    r = cliente.post("/api/auth/login", json={"email": email, "senha": "senha-de-teste-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_ingestao_exige_chave_e_organizacao(ambiente):
    cliente, _ = ambiente
    evento = {"organizacao_id": 7, "fonte": {"tipo": "dns", "produto": "x"},
              "ocorrido_em": "2026-11-21T10:00:00Z", "bruto": "q"}
    assert cliente.post("/api/eventos", json={"eventos": [evento]}).status_code == 401
    r = cliente.post("/api/eventos", json={"eventos": [evento | {"organizacao_id": 999}]},
                     headers={"X-API-Key": CHAVE})
    assert r.status_code == 422


def test_fluxo_completo(ambiente):
    from app import motor

    cliente, m = ambiente
    m.eventos.delete_many({})
    eventos = _simulador().montar_cenario()
    r = cliente.post("/api/eventos", json={"eventos": eventos}, headers={"X-API-Key": CHAVE})
    assert r.status_code == 201 and r.json()["recebidos"] == 45

    # Ingestão: hash calculado e ativo resolvido pelo IP de destino
    doc = m.eventos.find_one({"dados.evento_id": 4624})
    assert doc["ativo_id"] == 42 and len(doc["hash_bruto"]) == 64 and doc["preservado"] is False

    # Correlação: 1 alerta (o ruído da funcionária não dispara) e deduplicação no 2º ciclo
    novos = motor.correlacionar()
    assert len(novos) == 1
    assert motor.correlacionar() == []
    alerta = m.alertas.find_one({"_id": novos[0]})
    assert alerta["severidade"] == "CRITICA"            # sucesso + IP em IoC
    assert alerta["status"] == "PROMOVIDO"
    assert alerta["resumo"]["falhas"] == 37 and alerta["resumo"]["sucessos"] == 1

    # Promoção: incidente com prazos do SLA, 38 evidências, eventos fora do TTL
    with motor.mysql().connect() as c:
        inc = c.execute(text("SELECT * FROM incidentes WHERE alerta_origem_id = :a"),
                        {"a": str(alerta["_id"])}).first()
        n_evid = c.execute(text("SELECT COUNT(*) FROM incidente_evidencia WHERE incidente_id = :i"),
                           {"i": inc.id}).scalar()
    assert inc.severidade == "CRITICA" and inc.status == "ABERTO"
    assert (inc.prazo_resolucao - inc.aberto_em) == timedelta(minutes=240)
    assert n_evid == 38
    assert m.eventos.count_documents({"preservado": True}) == 38

    # Dashboard: fila, detalhe, integridade, vulnerabilidade cruzada
    h = _login(cliente, "analista2@iosephus.local")
    fila = cliente.get("/api/incidentes", headers=h).json()
    assert [i["id"] for i in fila] == [inc.id]
    d = cliente.get(f"/api/incidentes/{inc.id}", headers=h).json()
    assert {e["integridade"] for e in d["evidencias"]} == {"INTEGRA"}
    assert d["vulnerabilidades"][0]["cve_id"] == "CVE-2019-0708"
    assert d["alerta"]["enriquecimento"]["tags"] == ["rdp-bruteforce"]
    assert d["incidente"]["aberto_em"].endswith("Z") or "+00:00" in d["incidente"]["aberto_em"]

    # Adulteração do log bruto no MongoDB é detectada pelo hash guardado no MySQL
    m.eventos.update_one({"_id": doc["_id"]}, {"$set": {"bruto": doc["bruto"].replace("10", "11")}})
    d = cliente.get(f"/api/incidentes/{inc.id}", headers=h).json()
    assert [e["integridade"] for e in d["evidencias"]].count("ADULTERADA") == 1
    m.eventos.update_one({"_id": doc["_id"]}, {"$set": {"bruto": doc["bruto"]}})

    # Assumir: concorrência otimista (o segundo leva 409)
    h3 = _login(cliente, "analista3@iosephus.local")
    assert cliente.post(f"/api/incidentes/{inc.id}/assumir", headers=h).status_code == 200
    assert cliente.post(f"/api/incidentes/{inc.id}/assumir", headers=h3).status_code == 409

    # Status: só o responsável muda, só para frente, com comentário
    corpo = {"status_novo": "CONTIDO", "comentario": "RDP bloqueado no FW-BORDA"}
    assert cliente.post(f"/api/incidentes/{inc.id}/status", json=corpo, headers=h3).status_code == 403
    assert cliente.post(f"/api/incidentes/{inc.id}/status", json=corpo, headers=h).status_code == 200
    volta = {"status_novo": "ABERTO", "comentario": "tentando voltar"}
    assert cliente.post(f"/api/incidentes/{inc.id}/status", json=volta, headers=h).status_code == 422
    fim = {"status_novo": "ENCERRADO", "comentario": "Senha trocada, BlueKeep corrigido"}
    assert cliente.post(f"/api/incidentes/{inc.id}/status", json=fim, headers=h).status_code == 200
    d = cliente.get(f"/api/incidentes/{inc.id}", headers=h).json()
    assert d["incidente"]["encerrado_em"] is not None
    assert [x["status_novo"] for x in d["historico"]] == ["ABERTO", "EM_ANALISE", "CONTIDO", "ENCERRADO"]

    # Gestor do cliente vê, mas não altera
    hg = _login(cliente, "ti@valeverde.example")
    assert cliente.get(f"/api/incidentes/{inc.id}", headers=hg).status_code == 200
    assert cliente.post(f"/api/incidentes/{inc.id}/assumir", headers=hg).status_code == 403


def test_reconciliacao(ambiente):
    from app import motor

    _, m = ambiente
    # Caso 1: caiu depois do COMMIT no MySQL, antes de atualizar o MongoDB
    alerta = m.alertas.find_one({"status": "PROMOVIDO"})
    m.alertas.update_one({"_id": alerta["_id"]},
                         {"$set": {"status": "NOVO", "incidente_id": None,
                                   "criado_em": datetime.now(timezone.utc) - timedelta(minutes=5)}})
    m.eventos.update_many({}, {"$set": {"preservado": False}})
    r = motor.reconciliar()
    assert r["alertas_corrigidos"] == 1 and r["promovidos"] == 0
    assert m.alertas.find_one({"_id": alerta["_id"]})["status"] == "PROMOVIDO"
    assert m.eventos.count_documents({"preservado": True}) == 38
    # Idempotente: rodar de novo não muda nada
    assert motor.reconciliar() == {"promovidos": 0, "alertas_corrigidos": 0, "eventos_preservados": 0}

    # Caso 2: cliente sem SLA para a severidade -> alerta fica SEM_SLA, nenhum incidente nasce
    novo = dict(alerta)
    novo.pop("_id")
    novo.update(organizacao_id=1, status="NOVO", ativo_id=None,
                criado_em=datetime.now(timezone.utc) - timedelta(minutes=5))
    oid = m.alertas.insert_one(novo).inserted_id
    motor.reconciliar()
    assert m.alertas.find_one({"_id": oid})["status"] == "SEM_SLA"


def test_login_negado(ambiente):
    cliente, _ = ambiente
    ruim = {"email": "analista2@iosephus.local", "senha": "errada"}
    assert cliente.post("/api/auth/login", json=ruim).status_code == 401
    assert cliente.post("/api/auth/login", json={"email": "ninguem@x.com", "senha": "x"}).status_code == 401
    servico = {"email": "motor@iosephus.local", "senha": "senha-de-teste-123"}
    assert cliente.post("/api/auth/login", json=servico).status_code == 401   # conta de serviço
    assert cliente.get("/api/incidentes").status_code == 401


def test_app_nao_apaga_evidencia():
    """GRANT: a aplicação só insere em evidência e histórico."""
    engine = create_engine(os.environ["MYSQL_URL"])
    with pytest.raises(OperationalError) as erro, engine.begin() as c:
        c.execute(text("DELETE FROM incidente_evidencia"))
    assert erro.value.orig.args[0] == 1142


def _evento(**extra):
    return {"organizacao_id": 7, "fonte": {"tipo": "dns", "produto": "x"},
            "ocorrido_em": "2026-11-21T10:00:00Z", "bruto": "q"} | extra


def test_chave_presa_a_organizacao(ambiente):
    """A chave entregue a um cliente não grava eventos em nome de outro."""
    cliente, _ = ambiente
    h = {"X-API-Key": CHAVE_VALE_VERDE}
    assert cliente.post("/api/eventos", json={"eventos": [_evento()]}, headers=h).status_code == 201
    outro = {"eventos": [_evento(), _evento(organizacao_id=1)]}
    assert cliente.post("/api/eventos", json=outro, headers=h).status_code == 403
    # A chave do provedor continua valendo para qualquer organização
    r = cliente.post("/api/eventos", json=outro, headers={"X-API-Key": CHAVE})
    assert r.status_code == 201


def test_ativo_de_outra_organizacao(ambiente):
    """ativo_id informado pelo coletor precisa ser da organização do evento."""
    cliente, _ = ambiente
    h = {"X-API-Key": CHAVE}
    for ativo in (42, 999999):  # 42 é da organização 7; 999999 não existe
        r = cliente.post("/api/eventos", json={"eventos": [_evento(organizacao_id=1, ativo_id=ativo)]},
                         headers=h)
        assert r.status_code == 422, r.text
    assert cliente.post("/api/eventos", json={"eventos": [_evento(ativo_id=42)]},
                        headers=h).status_code == 201


def test_limite_de_tentativas_de_login(ambiente):
    from app import auth

    cliente, _ = ambiente
    auth._falhas_por_conta.zerar()
    auth._falhas_por_ip.zerar()
    try:
        errada = {"email": "analista3@iosephus.local", "senha": "errada"}
        for _ in range(5):
            assert cliente.post("/api/auth/login", json=errada).status_code == 401
        certa = {"email": "analista3@iosephus.local", "senha": "senha-de-teste-123"}
        r = cliente.post("/api/auth/login", json=certa)
        assert r.status_code == 429 and "Retry-After" in r.headers
        # Outra conta do mesmo IP ainda entra (o limite por IP é maior)
        _login(cliente, "analista2@iosephus.local")
    finally:
        auth._falhas_por_conta.zerar()
        auth._falhas_por_ip.zerar()


def test_conta_sem_senha_gasta_argon2(ambiente, monkeypatch):
    """Conta com senha_hash "!" não pode responder mais rápido que e-mail inexistente."""
    from app import auth

    cliente, _ = ambiente
    chamadas = []
    original = auth._verificar_senha
    monkeypatch.setattr(auth, "_verificar_senha", lambda h, s: chamadas.append(h) or original(h, s))
    for email in ("admin@iosephus.local", "ninguem@iosephus.local"):  # sem senha / inexistente
        assert cliente.post("/api/auth/login", json={"email": email, "senha": "x"}).status_code == 401
    assert chamadas == [auth._HASH_FALSO, auth._HASH_FALSO]
    auth._falhas_por_conta.zerar()
    auth._falhas_por_ip.zerar()
