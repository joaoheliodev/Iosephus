"""Proteções que não precisam de banco: configuração, chaves, limites e cabeçalhos."""
import os

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

os.environ.setdefault("MYSQL_URL", "mysql+pymysql://app_soc:teste@127.0.0.1:3306/iosephus?charset=utf8mb4")
os.environ.setdefault("MONGO_URL", "mongodb://nao-usado")
os.environ.setdefault("INGEST_API_KEY", "chave-de-teste-do-provedor-com-32-caracteres")
os.environ.setdefault("JWT_SECRET", "segredo-de-teste-com-tamanho-suficiente-32")
os.environ.setdefault("WORKER_ATIVO", "false")

BASE = {"mysql_url": "mysql+pymysql://x", "mongo_url": "mongodb://x",
        "ingest_api_key": "p" * 32, "jwt_secret": "j" * 32}


@pytest.fixture
def cliente():
    from fastapi.testclient import TestClient

    from app.main import app
    return TestClient(app)  # sem "with": não sobe o motor


# ------------------------------------------------------------------ configuração
@pytest.mark.parametrize("campo", ["jwt_secret", "ingest_api_key"])
@pytest.mark.parametrize("valor", ["", "curto-demais"])
def test_segredo_vazio_ou_curto_nao_sobe(campo, valor):
    from app.config import Settings

    with pytest.raises(ValidationError) as erro:
        Settings(_env_file=None, **(BASE | {campo: valor}))
    if valor:
        assert valor not in str(erro.value)  # o segredo não vai para o log


def test_chaves_por_organizacao():
    from app.config import Settings, interpretar_chaves

    a, b = "a" * 32, "b" * 40
    assert interpretar_chaves(f" 7:{a} , 8:{b},") == {a: 7, b: 8}
    for ruim in ("7", f"x:{a}", f"0:{a}", "7:curta", f"7:{a},8:{a}"):
        with pytest.raises(ValueError) as erro:
            interpretar_chaves(ruim)
        assert a not in str(erro.value)
    with pytest.raises(ValidationError):  # a chave do cliente não pode ser a do provedor
        Settings(_env_file=None, **(BASE | {"ingest_api_keys": f"7:{'p' * 32}"}))


def test_chave_coletor(monkeypatch):
    from app import auth
    from app.config import Settings

    cfg = Settings(_env_file=None, **(BASE | {"ingest_api_keys": f"7:{'c' * 32}"}))
    monkeypatch.setattr(auth, "settings", lambda: cfg)
    assert auth.chave_coletor("p" * 32) is None   # provedor: qualquer organização
    assert auth.chave_coletor("c" * 32) == 7      # cliente: só a organização 7
    for ruim in ("", "c" * 31, "x" * 32):
        with pytest.raises(HTTPException) as erro:
            auth.chave_coletor(ruim)
        assert erro.value.status_code == 401


# ------------------------------------------------------------------ limitador
def test_limitador_de_tentativas(monkeypatch):
    from app import limites

    agora = [1000.0]
    monkeypatch.setattr(limites.time, "monotonic", lambda: agora[0])
    lim = limites.LimitadorDeTentativas(max_chaves=3)
    assert all(lim.consumir("ip", 3, 60) for _ in range(3))
    assert not lim.consumir("ip", 3, 60)
    lim.devolver("ip")
    assert lim.consumir("ip", 3, 60)
    agora[0] += 61                                   # janela venceu
    assert lim.consumir("ip", 3, 60)
    for k in ("a", "b", "c", "d"):                   # memória limitada
        lim.consumir(k, 3, 60)
    assert len(lim._registros) <= 3


# ------------------------------------------------------------------ entrada
def test_ip_invalido_recusado():
    from app.ingestao import Rede

    assert Rede(ip_origem="203.0.113.45", ip_destino="2001:db8::1").ip_origem == "203.0.113.45"
    assert Rede(ip_origem="-", ip_destino="").ip_origem is None
    for ruim in ("10.0.0.1\nFALSO alerta", "evil.example", "999.1.1.1"):
        with pytest.raises(ValidationError):
            Rede(ip_origem=ruim)


def test_corpo_grande_recebe_413(cliente):
    r = cliente.post("/api/auth/login", content=b"x" * 100_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    assert r.headers["X-Content-Type-Options"] == "nosniff"

    def em_pedacos():  # sem Content-Length
        for _ in range(100):
            yield b"x" * 1024
    r = cliente.post("/api/auth/login", content=em_pedacos(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_cabecalhos(cliente):
    r = cliente.get("/api/incidentes")
    assert r.status_code == 401 and r.headers["Cache-Control"] == "no-store"
    # Host forjado não tira a CSP do dashboard
    r = cliente.get("/", headers={"Host": "exemplo/api/docs?"})
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
