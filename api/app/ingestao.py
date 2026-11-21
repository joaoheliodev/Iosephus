"""Ingestão: o coletor manda o log, a API calcula o hash e grava o fato bruto no MongoDB."""
import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import bindparam, text

from .auth import chave_coletor
from .db import mongo, mysql
from .dominio import sha256

router = APIRouter(prefix="/api", tags=["ingestão"])


class Fonte(BaseModel):
    tipo: Literal["autenticacao", "firewall", "ids", "edr", "dns"]
    produto: str = Field(max_length=80)
    coletor: str | None = Field(default=None, max_length=80)


class Rede(BaseModel):
    ip_origem: str | None = Field(default=None, max_length=45)
    ip_destino: str | None = Field(default=None, max_length=45)
    porta_destino: int | None = Field(default=None, ge=0, le=65535)
    protocolo: str | None = Field(default=None, max_length=10)


class EventoIn(BaseModel):
    organizacao_id: int = Field(gt=0)
    ativo_id: int | None = Field(default=None, gt=0)  # se vier vazio, resolve pelo IP de destino
    fonte: Fonte
    ocorrido_em: datetime
    severidade: int | None = Field(default=None, ge=0, le=10)
    rede: Rede | None = None
    dados: dict[str, Any] = Field(default_factory=dict)
    bruto: str = Field(min_length=1, max_length=65536)  # o log original, como chegou

    @field_validator("ocorrido_em")
    @classmethod
    def em_utc(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)


class Lote(BaseModel):
    eventos: list[EventoIn] = Field(min_length=1, max_length=1000)


def _resolver_ativos(eventos: list[EventoIn]) -> dict[tuple[int, str], int]:
    """(organizacao_id, ip) -> ativo_id, uma consulta por lote (usa o índice organizacao_id, ip)."""
    pares = {(e.organizacao_id, e.rede.ip_destino) for e in eventos
             if e.ativo_id is None and e.rede and e.rede.ip_destino}
    if not pares:
        return {}
    ips = sorted({ip for _, ip in pares})
    with mysql().connect() as c:
        rows = c.execute(text("""
            SELECT id, organizacao_id, ip FROM ativos
             WHERE ip IN :ips AND desativado_em IS NULL""").bindparams(bindparam("ips", expanding=True)),
            {"ips": ips}).all()
    return {(r.organizacao_id, r.ip): r.id for r in rows}


@router.post("/eventos", status_code=201, dependencies=[Depends(chave_coletor)])
def receber(lote: Lote):
    orgs = sorted({e.organizacao_id for e in lote.eventos})
    with mysql().connect() as c:
        existentes = set(c.execute(
            text("SELECT id FROM organizacoes WHERE id IN :ids").bindparams(bindparam("ids", expanding=True)),
            {"ids": orgs}).scalars().all())
    desconhecidas = set(orgs) - existentes
    if desconhecidas:
        raise HTTPException(422, f"Organização inexistente: {sorted(desconhecidas)}")

    ativos = _resolver_ativos(lote.eventos)
    agora = datetime.now(timezone.utc)
    documentos = []
    for e in lote.eventos:
        ativo_id = e.ativo_id
        if ativo_id is None and e.rede and e.rede.ip_destino:
            ativo_id = ativos.get((e.organizacao_id, e.rede.ip_destino))
        doc = {
            "organizacao_id": e.organizacao_id,
            "ativo_id": ativo_id,                     # None = fora do inventário
            "fonte": e.fonte.model_dump(exclude_none=True),
            "ocorrido_em": e.ocorrido_em,
            "recebido_em": agora,
            "severidade": e.severidade,
            "rede": e.rede.model_dump(exclude_none=True) if e.rede else None,
            "dados": json.loads(json.dumps(e.dados)),  # garante JSON puro
            "bruto": e.bruto,
            "hash_bruto": sha256(e.bruto),
            "preservado": False,                      # vira True quando vira evidência
        }
        documentos.append(doc)
    resultado = mongo().eventos.insert_many(documentos, ordered=True)
    return {"recebidos": len(resultado.inserted_ids), "ids": [str(i) for i in resultado.inserted_ids]}
