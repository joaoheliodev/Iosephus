"""Motor: correlaciona eventos (MongoDB), cria alertas e promove a incidente (MySQL).

Ordem que garante consistência entre os dois bancos:
  1. transação no MySQL (incidente + ativo + evidências + histórico) -> COMMIT
  2. só depois atualiza o MongoDB (alerta PROMOVIDO, eventos preservados)
Se cair entre 1 e 2, a reconciliação conserta: ela é idempotente e o UNIQUE de
incidentes.alerta_origem_id impede promover o mesmo alerta duas vezes.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from .config import settings
from .db import mongo, mysql
from .dominio import MAX_REFERENCIAS_ALERTA, severidade_alerta

log = logging.getLogger("iosephus.motor")


class SemSLA(Exception):
    """O cliente não tem política de SLA para a severidade: o incidente não pode nascer sem prazo."""


# ---------------------------------------------------------------------------
# Correlação
# ---------------------------------------------------------------------------
def _regras_ativas() -> list[dict]:
    with mysql().connect() as c:
        rows = c.execute(text("""
            SELECT id, nome, versao, tecnica_mitre, severidade, condicao
              FROM regras_deteccao WHERE ativa""")).all()
    regras = []
    for r in rows:
        cond = r.condicao if isinstance(r.condicao, dict) else json.loads(r.condicao)
        regras.append({"id": r.id, "nome": r.nome, "versao": r.versao,
                       "tecnica_mitre": r.tecnica_mitre, "severidade": r.severidade, "condicao": cond})
    return regras


def _forca_bruta_com_sucesso(regra: dict, agora: datetime) -> list[dict]:
    """N falhas de logon + ao menos 1 sucesso, do mesmo IP contra o mesmo ativo, dentro da janela."""
    c = regra["condicao"]
    inicio = agora - timedelta(minutes=c["janela_min"])
    pipeline = [
        {"$match": {
            "fonte.tipo": "autenticacao",
            "dados.evento_id": {"$in": [c["evento_falha"], c["evento_sucesso"]]},
            "ocorrido_em": {"$gte": inicio, "$lt": agora},
            "rede.ip_origem": {"$ne": None},
        }},
        {"$sort": {"ocorrido_em": 1}},
        {"$group": {
            "_id": {"org": "$organizacao_id", "ip": "$rede.ip_origem", "ativo": "$ativo_id"},
            "falhas":   {"$sum": {"$cond": [{"$eq": ["$dados.evento_id", c["evento_falha"]]}, 1, 0]}},
            "sucessos": {"$sum": {"$cond": [{"$eq": ["$dados.evento_id", c["evento_sucesso"]]}, 1, 0]}},
            "eventos":  {"$push": "$_id"},
            "usuarios": {"$addToSet": "$dados.usuario_alvo"},
            "primeiro": {"$min": "$ocorrido_em"},
            "ultimo":   {"$max": "$ocorrido_em"},
        }},
        {"$match": {"falhas": {"$gte": c["limiar_falhas"]}, "sucessos": {"$gte": 1}}},
    ]
    return list(mongo().eventos.aggregate(pipeline))


DETECTORES = {"forca_bruta_com_sucesso": _forca_bruta_com_sucesso}


def correlacionar(agora: datetime | None = None) -> list[ObjectId]:
    """Roda todas as regras ativas; devolve os alertas novos (já com tentativa de promoção)."""
    agora = agora or datetime.now(timezone.utc)
    m = mongo()
    novos = []
    for regra in _regras_ativas():
        detector = DETECTORES.get(regra["condicao"].get("tipo"))
        if detector is None:
            log.warning("regra %s: tipo de condição desconhecido, ignorada", regra["id"])
            continue
        janela = timedelta(minutes=regra["condicao"]["janela_min"])
        for g in detector(regra, agora):
            org, ip, ativo = g["_id"]["org"], g["_id"]["ip"], g["_id"].get("ativo")
            # Deduplicação: mesmo ataque, mesma regra, ainda dentro da janela -> não repete o alerta
            if m.alertas.find_one({"regra.id": regra["id"], "organizacao_id": org,
                                   "resumo.ip_origem": ip, "ativo_id": ativo,
                                   "criado_em": {"$gte": agora - janela}}):
                continue
            ioc = m.indicadores_ameaca.find_one({"tipo": "ipv4", "valor": ip})
            alerta = {
                "organizacao_id": org,
                # Referência estendida: copia o essencial da regra (o alerta não muda se a regra mudar)
                "regra": {k: regra[k] for k in ("id", "versao", "tecnica_mitre", "nome")},
                "severidade": severidade_alerta(regra["severidade"], ioc is not None),
                "criado_em": agora,
                "ativo_id": ativo,
                "resumo": {"ip_origem": ip, "usuarios_alvo": [u for u in g["usuarios"] if u],
                           "falhas": g["falhas"], "sucessos": g["sucessos"],
                           "primeiro_evento": g["primeiro"], "ultimo_evento": g["ultimo"],
                           "janela_min": regra["condicao"]["janela_min"]},
                "eventos_ids": g["eventos"][-MAX_REFERENCIAS_ALERTA:],
                "enriquecimento": ({"ioc_id": ioc["_id"], "tags": ioc.get("tags", []),
                                    "confianca": (ioc.get("fontes") or [{}])[0].get("confianca")}
                                   if ioc else None),
                "status": "NOVO",
                "incidente_id": None,
            }
            alerta["_id"] = m.alertas.insert_one(alerta).inserted_id
            novos.append(alerta["_id"])
            log.info("alerta %s: regra %s, %s -> ativo %s", alerta["_id"], regra["id"], ip, ativo)
            try:
                promover(alerta)
            except Exception:  # a reconciliação tenta de novo
                log.exception("falha ao promover %s", alerta["_id"])
    return novos


# ---------------------------------------------------------------------------
# Promoção: alerta (MongoDB) -> incidente (MySQL)
# ---------------------------------------------------------------------------
def promover(alerta: dict) -> int:
    m = mongo()
    alerta_id = str(alerta["_id"])
    ids = alerta.get("eventos_ids", [])
    hashes = {d["_id"]: d["hash_bruto"]
              for d in m.eventos.find({"_id": {"$in": ids}}, {"hash_bruto": 1})}
    servico = settings().servico_usuario_id

    try:
        incidente_id = _transacao_promocao(alerta, alerta_id, ids, hashes, servico)
    except SemSLA:
        m.alertas.update_one({"_id": alerta["_id"]}, {"$set": {"status": "SEM_SLA"}})
        log.error("alerta %s: organização %s sem SLA para %s",
                  alerta_id, alerta["organizacao_id"], alerta["severidade"])
        raise
    except IntegrityError:
        # Outro processo promoveu ao mesmo tempo: o UNIQUE barrou, usamos o incidente dele
        with mysql().connect() as c:
            incidente_id = c.execute(text("SELECT id FROM incidentes WHERE alerta_origem_id = :a"),
                                     {"a": alerta_id}).scalar_one()

    _pos_commit(alerta["_id"], incidente_id, ids)
    return incidente_id


def _transacao_promocao(alerta, alerta_id, ids, hashes, servico) -> int:
    with mysql().begin() as c:  # COMMIT ao sair do bloco; ROLLBACK se houver exceção
        existente = c.execute(text("SELECT id FROM incidentes WHERE alerta_origem_id = :a"),
                              {"a": alerta_id}).scalar()
        if existente:
            return existente

        alvo = None
        if alerta.get("ativo_id"):
            alvo = c.execute(text("SELECT hostname FROM ativos WHERE id = :id"),
                             {"id": alerta["ativo_id"]}).scalar()
        titulo = f'{alerta["regra"]["nome"]} em {alvo or alerta["resumo"]["ip_origem"]}'[:200]

        # Prazos vêm do contrato do cliente: sem política, nenhuma linha é inserida
        r = c.execute(text("""
            INSERT INTO incidentes (organizacao_id, regra_id, alerta_origem_id, titulo, severidade,
                                    aberto_em, prazo_resposta, prazo_resolucao)
            SELECT p.organizacao_id, :regra, :alerta, :titulo, p.severidade,
                   UTC_TIMESTAMP(),
                   UTC_TIMESTAMP() + INTERVAL p.minutos_resposta  MINUTE,
                   UTC_TIMESTAMP() + INTERVAL p.minutos_resolucao MINUTE
              FROM politicas_sla p
             WHERE p.organizacao_id = :org AND p.severidade = :sev"""),
            {"regra": alerta["regra"]["id"], "alerta": alerta_id, "titulo": titulo,
             "org": alerta["organizacao_id"], "sev": alerta["severidade"]})
        if r.rowcount == 0:
            raise SemSLA()
        incidente_id = r.lastrowid

        if alerta.get("ativo_id"):
            c.execute(text("INSERT INTO incidente_ativo VALUES (:i, :a, 'ALVO')"),
                      {"i": incidente_id, "a": alerta["ativo_id"]})
        evidencias = [{"i": incidente_id, "e": str(eid), "h": hashes[eid], "u": servico}
                      for eid in ids if eid in hashes]
        if evidencias:
            c.execute(text("""
                INSERT INTO incidente_evidencia (incidente_id, evento_id, hash_sha256, anexada_por)
                VALUES (:i, :e, :h, :u)"""), evidencias)
        resumo = alerta["resumo"]
        comentario = (f'Promovido pelo motor: {resumo["falhas"]} falhas e {resumo["sucessos"]} '
                      f'sucesso(s) de {resumo["ip_origem"]}'
                      + (" (IP em inteligência de ameaças)" if alerta.get("enriquecimento") else ""))
        c.execute(text("""
            INSERT INTO incidente_historico (incidente_id, usuario_id, status_novo, comentario)
            VALUES (:i, :u, 'ABERTO', :c)"""), {"i": incidente_id, "u": servico, "c": comentario})
        return incidente_id


def _pos_commit(alerta_oid: ObjectId, incidente_id: int, ids: list) -> None:
    m = mongo()
    m.alertas.update_one({"_id": alerta_oid},
                         {"$set": {"status": "PROMOVIDO", "incidente_id": incidente_id}})
    if ids:  # evidência sai do TTL de 180 dias
        m.eventos.update_many({"_id": {"$in": ids}, "preservado": False},
                              {"$set": {"preservado": True}})


# ---------------------------------------------------------------------------
# Reconciliação (idempotente): conserta o que ficou pela metade
# ---------------------------------------------------------------------------
def reconciliar(agora: datetime | None = None) -> dict:
    agora = agora or datetime.now(timezone.utc)
    m = mongo()
    resultado = {"promovidos": 0, "alertas_corrigidos": 0, "eventos_preservados": 0}

    # 1) Alertas NOVO há mais de 2 min: promove (ou só conclui o pós-commit, se o MySQL já tem)
    for alerta in m.alertas.find({"status": "NOVO", "criado_em": {"$lt": agora - timedelta(minutes=2)}}):
        with mysql().connect() as c:
            ja = c.execute(text("SELECT id FROM incidentes WHERE alerta_origem_id = :a"),
                           {"a": str(alerta["_id"])}).scalar()
        try:
            promover(alerta)
            resultado["alertas_corrigidos" if ja else "promovidos"] += 1
        except Exception:
            log.exception("reconciliação: alerta %s continua pendente", alerta["_id"])

    # 2) Toda evidência anexada nas últimas 24 h precisa estar fora do TTL
    with mysql().connect() as c:
        ids = c.execute(text("""
            SELECT evento_id FROM incidente_evidencia
             WHERE anexada_em >= UTC_TIMESTAMP() - INTERVAL 1 DAY""")).scalars().all()
    if ids:
        r = m.eventos.update_many({"_id": {"$in": [ObjectId(i) for i in ids]}, "preservado": False},
                                  {"$set": {"preservado": True}})
        resultado["eventos_preservados"] = r.modified_count
    return resultado
