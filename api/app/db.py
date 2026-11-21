"""Conexões. MySQL guarda decisões; MongoDB guarda fatos brutos."""
from datetime import datetime, timezone
from decimal import Decimal

from pymongo import MongoClient
from pymongo.database import Database
from sqlalchemy import Engine, create_engine

from .config import settings

_engine: Engine | None = None
_mongo: Database | None = None


def mysql() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings().mysql_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            connect_args={"init_command": "SET time_zone = '+00:00'"},  # tudo em UTC
        )
    return _engine


def mongo() -> Database:
    global _mongo
    if _mongo is None:
        cliente = MongoClient(settings().mongo_url, tz_aware=True, serverSelectionTimeoutMS=5000)
        _mongo = cliente[settings().mongo_db]
    return _mongo


def usar_mongo(db: Database) -> None:
    """Troca o banco do MongoDB (usado pelos testes)."""
    global _mongo
    _mongo = db


def utc(dt: datetime | None) -> datetime | None:
    """O MySQL devolve DATETIME sem fuso; aqui tudo é UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def linha(row) -> dict:
    """Converte uma linha do SQLAlchemy em dict pronto para JSON."""
    saida = {}
    for chave, valor in row._mapping.items():
        if isinstance(valor, datetime):
            valor = utc(valor)
        elif isinstance(valor, Decimal):
            valor = float(valor)
        saida[chave] = valor
    return saida
