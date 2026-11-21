"""Login do dashboard (Argon2id + JWT) e chave dos coletores."""
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import text

from .config import settings
from .db import mysql

router = APIRouter(prefix="/api/auth", tags=["auth"])
_hasher = PasswordHasher()  # Argon2id
_bearer = HTTPBearer(auto_error=False)
# Hash qualquer, para o tempo de resposta não revelar se o e-mail existe
_HASH_FALSO = _hasher.hash(secrets.token_hex(16))


@dataclass
class Usuario:
    id: int
    nome: str
    email: str
    organizacao_id: int
    provedor: bool          # usuário do SOC vê todos os clientes; gestor vê só a própria organização
    perfil: str
    permissoes: set[str]

    def pode(self, permissao: str) -> bool:
        return permissao in self.permissoes

    def ve_organizacao(self, organizacao_id: int) -> bool:
        return self.provedor or self.organizacao_id == organizacao_id


def gerar_hash(senha: str) -> str:
    return _hasher.hash(senha)


def _carregar(usuario_id: int) -> Usuario | None:
    with mysql().connect() as c:
        u = c.execute(text("""
            SELECT u.id, u.nome, u.email, u.organizacao_id, u.perfil_id, u.ativo,
                   o.tipo AS org_tipo, p.nome AS perfil
              FROM usuarios u
              JOIN organizacoes o ON o.id = u.organizacao_id
              JOIN perfis p       ON p.id = u.perfil_id
             WHERE u.id = :id"""), {"id": usuario_id}).first()
        if u is None or not u.ativo:
            return None
        perms = c.execute(text("""
            SELECT pe.codigo FROM perfil_permissao pp
              JOIN permissoes pe ON pe.id = pp.permissao_id
             WHERE pp.perfil_id = :p"""), {"p": u.perfil_id}).scalars().all()
    return Usuario(u.id, u.nome, u.email, u.organizacao_id, u.org_tipo == "PROVEDOR", u.perfil, set(perms))


def usuario_atual(cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Usuario:
    negado = HTTPException(status.HTTP_401_UNAUTHORIZED, "Sessão inválida ou expirada",
                           headers={"WWW-Authenticate": "Bearer"})
    if cred is None:
        raise negado
    try:
        dados = jwt.decode(cred.credentials, settings().jwt_secret, algorithms=["HS256"])
        usuario = _carregar(int(dados["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise negado
    if usuario is None:
        raise negado
    return usuario


def exigir(permissao: str):
    def dependencia(usuario: Usuario = Depends(usuario_atual)) -> Usuario:
        if not usuario.pode(permissao):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Sem a permissão {permissao}")
        return usuario
    return dependencia


def chave_coletor(x_api_key: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_api_key.encode(), settings().ingest_api_key.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Chave de coletor inválida")


class Login(BaseModel):
    email: str = Field(max_length=254)
    senha: str = Field(max_length=200)


@router.post("/login")
def login(dados: Login):
    with mysql().connect() as c:
        u = c.execute(text("""
            SELECT u.id, u.senha_hash, u.ativo, p.nome AS perfil
              FROM usuarios u JOIN perfis p ON p.id = u.perfil_id
             WHERE u.email = :e"""), {"e": dados.email.strip().lower()}).first()
    hash_alvo = u.senha_hash if u else _HASH_FALSO
    try:
        _hasher.verify(hash_alvo, dados.senha)
        senha_ok = u is not None
    except (VerificationError, InvalidHashError):
        senha_ok = False
    # Conta de serviço não entra no dashboard
    if not senha_ok or not u.ativo or u.perfil == "SERVICO":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "E-mail ou senha incorretos")
    expira = datetime.now(timezone.utc) + timedelta(hours=settings().jwt_horas)
    token = jwt.encode({"sub": str(u.id), "exp": expira}, settings().jwt_secret, algorithm="HS256")
    return {"token": token, "expira_em": expira}


@router.get("/eu")
def eu(usuario: Usuario = Depends(usuario_atual)):
    return {"id": usuario.id, "nome": usuario.nome, "perfil": usuario.perfil,
            "provedor": usuario.provedor, "permissoes": sorted(usuario.permissoes)}
