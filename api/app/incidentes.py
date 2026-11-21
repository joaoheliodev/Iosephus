"""Incidentes: fila, detalhe (com verificação de integridade), assumir e mudar status."""
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text

from .auth import Usuario, exigir
from .db import linha, mongo, mysql, utc
from .dominio import STATUS, integridade, transicao_valida

router = APIRouter(prefix="/api/incidentes", tags=["incidentes"])


def _carregar_visivel(c, incidente_id: int, usuario: Usuario, travar: bool = False):
    sql = "SELECT * FROM incidentes WHERE id = :id" + (" FOR UPDATE" if travar else "")
    inc = c.execute(text(sql), {"id": incidente_id}).first()
    # 404 também quando é de outro cliente: não revela que o incidente existe
    if inc is None or not usuario.ve_organizacao(inc.organizacao_id):
        raise HTTPException(404, "Incidente não encontrado")
    return inc


@router.get("")
def fila(abertos: bool = True, usuario: Usuario = Depends(exigir("incidente.ler"))):
    with mysql().connect() as c:
        rows = c.execute(text("""
            SELECT i.id, o.nome AS cliente, i.titulo, i.severidade, i.status,
                   u.nome AS analista, i.aberto_em, i.prazo_resposta, i.prazo_resolucao,
                   i.primeira_resposta_em, i.encerrado_em,
                   TIMESTAMPDIFF(MINUTE, UTC_TIMESTAMP(), i.prazo_resolucao) AS min_restantes
              FROM incidentes i
              JOIN organizacoes o ON o.id = i.organizacao_id
              LEFT JOIN usuarios u ON u.id = i.analista_id
             WHERE (:todas OR i.organizacao_id = :org)
               AND (:abertos = 0 OR i.status <> 'ENCERRADO')
             ORDER BY i.status = 'ENCERRADO', i.prazo_resolucao
             LIMIT 200"""),
            {"todas": usuario.provedor, "org": usuario.organizacao_id, "abertos": int(abertos)}).all()
    return [linha(r) for r in rows]


@router.get("/resumo")
def resumo(usuario: Usuario = Depends(exigir("incidente.ler"))):
    with mysql().connect() as c:
        r = c.execute(text("""
            SELECT COUNT(*) AS abertos,
                   COALESCE(SUM(severidade = 'CRITICA'), 0) AS criticos,
                   COALESCE(SUM(analista_id IS NULL), 0) AS na_fila,
                   COALESCE(SUM(prazo_resolucao < UTC_TIMESTAMP()), 0) AS sla_estourado
              FROM incidentes
             WHERE status <> 'ENCERRADO' AND (:todas OR organizacao_id = :org)"""),
            {"todas": usuario.provedor, "org": usuario.organizacao_id}).first()
    return {k: int(v) for k, v in r._mapping.items()}


@router.get("/{incidente_id}")
def detalhe(incidente_id: int, usuario: Usuario = Depends(exigir("incidente.ler"))):
    with mysql().connect() as c:
        inc = _carregar_visivel(c, incidente_id, usuario)
        cliente = c.execute(text("SELECT nome FROM organizacoes WHERE id = :o"),
                            {"o": inc.organizacao_id}).scalar()
        analista = (c.execute(text("SELECT nome FROM usuarios WHERE id = :u"),
                              {"u": inc.analista_id}).scalar() if inc.analista_id else None)
        ativos = [linha(r) for r in c.execute(text("""
            SELECT a.id, a.hostname, a.ip, a.tipo, a.sistema_operacional, a.criticidade, ia.papel
              FROM incidente_ativo ia JOIN ativos a ON a.id = ia.ativo_id
             WHERE ia.incidente_id = :i"""), {"i": incidente_id}).all()]
        vulns = []
        if ativos:
            # Ativo atacado que também tem vulnerabilidade crítica aberta = prioridade máxima
            vulns = [linha(r) for r in c.execute(text("""
                SELECT a.hostname, v.cve_id, v.titulo, v.cvss, v.severidade, av.prazo_correcao
                  FROM ativo_vulnerabilidade av
                  JOIN vulnerabilidades v ON v.id = av.vulnerabilidade_id
                  JOIN ativos a           ON a.id = av.ativo_id
                 WHERE av.ativo_id IN :ids AND av.status IN ('ABERTA', 'EM_CORRECAO')
                   AND v.severidade IN ('ALTA', 'CRITICA')
                 ORDER BY v.cvss DESC""").bindparams(bindparam("ids", expanding=True)),
                {"ids": [a["id"] for a in ativos]}).all()]
        evidencias = c.execute(text("""
            SELECT evento_id, hash_sha256, anexada_em FROM incidente_evidencia
             WHERE incidente_id = :i ORDER BY id"""), {"i": incidente_id}).all()
        historico = [linha(r) for r in c.execute(text("""
            SELECT h.status_anterior, h.status_novo, h.comentario, h.registrado_em, u.nome AS usuario
              FROM incidente_historico h JOIN usuarios u ON u.id = h.usuario_id
             WHERE h.incidente_id = :i ORDER BY h.id"""), {"i": incidente_id}).all()]

    # Ponte MySQL -> MongoDB: ObjectId + hash; nunca FK
    m = mongo()
    docs = {str(d["_id"]): d for d in m.eventos.find(
        {"_id": {"$in": [ObjectId(e.evento_id) for e in evidencias]}},
        {"ocorrido_em": 1, "fonte": 1, "rede": 1, "dados": 1, "bruto": 1})}
    linha_do_tempo = []
    for e in evidencias:
        d = docs.get(e.evento_id)
        linha_do_tempo.append({
            "evento_id": e.evento_id,
            "hash_sha256": e.hash_sha256,
            "integridade": integridade(e.hash_sha256, d),
            "ocorrido_em": utc(d["ocorrido_em"]) if d else None,
            "fonte": d["fonte"] if d else None,
            "ip_origem": (d.get("rede") or {}).get("ip_origem") if d else None,
            "evento": (d.get("dados") or {}).get("evento_id") if d else None,
            "usuario_alvo": (d.get("dados") or {}).get("usuario_alvo") if d else None,
            "bruto": d["bruto"][:2000] if d else None,
        })
    linha_do_tempo.sort(key=lambda x: (x["ocorrido_em"] is None, x["ocorrido_em"] or 0))

    alerta = None
    if inc.alerta_origem_id:
        try:
            a = m.alertas.find_one({"_id": ObjectId(inc.alerta_origem_id)},
                                   {"regra": 1, "resumo": 1, "enriquecimento": 1, "severidade": 1})
        except InvalidId:
            a = None
        if a:
            enr = a.get("enriquecimento")
            alerta = {"id": str(a["_id"]), "regra": a.get("regra"), "resumo": a.get("resumo"),
                      "severidade": a.get("severidade"),
                      "enriquecimento": ({"tags": enr.get("tags"), "confianca": enr.get("confianca")}
                                         if enr else None)}

    return {
        "incidente": linha(inc) | {"cliente": cliente, "analista": analista},
        "ativos": ativos,
        "vulnerabilidades": vulns,
        "evidencias": linha_do_tempo,
        "historico": historico,
        "alerta": alerta,
        "proximos_status": [s for s in STATUS if transicao_valida(inc.status, s)],
    }


@router.post("/{incidente_id}/assumir")
def assumir(incidente_id: int, usuario: Usuario = Depends(exigir("incidente.alterar_status"))):
    with mysql().begin() as c:
        _carregar_visivel(c, incidente_id, usuario)
        # Concorrência otimista: se dois analistas clicarem juntos, só um afeta a linha
        r = c.execute(text("""
            UPDATE incidentes
               SET status = 'EM_ANALISE', analista_id = :u,
                   primeira_resposta_em = COALESCE(primeira_resposta_em, UTC_TIMESTAMP())
             WHERE id = :i AND status = 'ABERTO' AND analista_id IS NULL"""),
            {"u": usuario.id, "i": incidente_id})
        if r.rowcount == 0:
            raise HTTPException(409, "Incidente já assumido por outro analista")
        c.execute(text("""
            INSERT INTO incidente_historico (incidente_id, usuario_id, status_anterior, status_novo, comentario)
            VALUES (:i, :u, 'ABERTO', 'EM_ANALISE', 'Incidente assumido')"""),
            {"i": incidente_id, "u": usuario.id})
    return {"ok": True}


class MudancaStatus(BaseModel):
    status_novo: str
    comentario: str = Field(min_length=3, max_length=2000)


@router.post("/{incidente_id}/status")
def mudar_status(incidente_id: int, dados: MudancaStatus,
                 usuario: Usuario = Depends(exigir("incidente.alterar_status"))):
    with mysql().begin() as c:
        inc = _carregar_visivel(c, incidente_id, usuario, travar=True)
        if inc.analista_id != usuario.id and not usuario.pode("usuario.gerenciar"):
            raise HTTPException(403, "Só o analista responsável (ou um admin) muda o status")
        if not transicao_valida(inc.status, dados.status_novo):
            raise HTTPException(422, f"Transição inválida: {inc.status} -> {dados.status_novo}")
        c.execute(text("""
            UPDATE incidentes
               SET status = :novo,
                   encerrado_em = IF(:novo = 'ENCERRADO', UTC_TIMESTAMP(), NULL),
                   primeira_resposta_em = COALESCE(primeira_resposta_em, UTC_TIMESTAMP())
             WHERE id = :i"""), {"novo": dados.status_novo, "i": incidente_id})
        c.execute(text("""
            INSERT INTO incidente_historico (incidente_id, usuario_id, status_anterior, status_novo, comentario)
            VALUES (:i, :u, :ant, :novo, :c)"""),
            {"i": incidente_id, "u": usuario.id, "ant": inc.status,
             "novo": dados.status_novo, "c": dados.comentario})
    return {"ok": True}
