"""Login do dashboard (Argon2id + JWT) e chave dos coletores."""
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import text

from .config import settings
from .db import mysql
from .limites import LimitadorDeTentativas

router = APIRouter(prefix="/api/auth", tags=["auth"])
_hasher = PasswordHasher()  # Argon2id
_bearer = HTTPBearer(auto_error=False)
# Hash qualquer, para o tempo de resposta não revelar se o e-mail existe
_HASH_FALSO = _hasher.hash(secrets.token_hex(16))
_falhas_por_conta = LimitadorDeTentativas()   # chave: IP + e-mail
_falhas_por_ip = LimitadorDeTentativas()      # chave: IP
_trava_vagas = threading.Lock()
_vagas: threading.BoundedSemaphore | None = None


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


def chave_coletor(x_api_key: str = Header(default="")) -> int | None:
    """Valida a X-API-Key e devolve a organização a que ela está presa (None = chave do provedor).

    Compara com todas as chaves, sempre, para o tempo de resposta não indicar qual quase bateu.
    """
    cfg = settings()
    recebida = x_api_key.encode()
    valida, organizacao = False, None
    if recebida:
        valida = secrets.compare_digest(recebida, cfg.ingest_api_key.encode())
        for chave, org_id in cfg.chaves_por_organizacao().items():
            if secrets.compare_digest(recebida, chave.encode()):
                valida, organizacao = True, org_id
    if not valida:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Chave de coletor inválida")
    return organizacao


class Login(BaseModel):
    email: str = Field(max_length=254)
    senha: str = Field(max_length=200)


def _vagas_argon2() -> threading.BoundedSemaphore:
    global _vagas
    with _trava_vagas:
        if _vagas is None:
            _vagas = threading.BoundedSemaphore(settings().argon2_simultaneos)
        return _vagas


def _verificar_senha(hash_alvo: str, senha: str) -> bool:
    """Argon2id com teto de verificações simultâneas: 40 logins em paralelo pediriam 2,5 GB de RAM."""
    vagas = _vagas_argon2()
    if not vagas.acquire(timeout=5):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Servidor ocupado, tente de novo",
                            headers={"Retry-After": "5"})
    try:
        return _hasher.verify(hash_alvo, senha)
    except (VerificationError, InvalidHashError):
        return False
    finally:
        vagas.release()


def _muitas_tentativas(janela_s: int) -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                         "Muitas tentativas de login. Aguarde alguns minutos.",
                         headers={"Retry-After": str(janela_s)})


@router.post("/login")
def login(dados: Login, request: Request):
    cfg = settings()
    email = dados.email.strip().lower()
    ip = request.client.host if request.client else "desconhecido"
    conta = f"{ip}|{email}"
    # A tentativa é reservada antes do Argon2 e devolvida se o login der certo
    if not _falhas_por_ip.consumir(ip, cfg.login_falhas_por_ip, cfg.login_janela_s):
        raise _muitas_tentativas(cfg.login_janela_s)
    if not _falhas_por_conta.consumir(conta, cfg.login_falhas_por_conta, cfg.login_janela_s):
        _falhas_por_ip.devolver(ip)
        raise _muitas_tentativas(cfg.login_janela_s)

    with mysql().connect() as c:
        u = c.execute(text("""
            SELECT u.id, u.senha_hash, u.ativo, p.nome AS perfil
              FROM usuarios u JOIN perfis p ON p.id = u.perfil_id
             WHERE u.email = :e"""), {"e": email}).first()
    # Conta sem senha definida ("!" do seed) também gasta um Argon2: senão responde na hora
    # e o tempo de resposta entrega quais e-mails existem
    tem_hash = u is not None and u.senha_hash.startswith("$argon2")
    try:
        senha_ok = _verificar_senha(u.senha_hash if tem_hash else _HASH_FALSO, dados.senha) and tem_hash
    except HTTPException:  # servidor ocupado: não conta como tentativa errada
        _falhas_por_conta.devolver(conta)
        _falhas_por_ip.devolver(ip)
        raise
    # Conta de serviço não entra no dashboard
    if not senha_ok or not u.ativo or u.perfil == "SERVICO":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "E-mail ou senha incorretos")
    _falhas_por_conta.esquecer(conta)
    _falhas_por_ip.devolver(ip)
    expira = datetime.now(timezone.utc) + timedelta(hours=settings().jwt_horas)
    token = jwt.encode({"sub": str(u.id), "exp": expira}, settings().jwt_secret, algorithm="HS256")
    return {"token": token, "expira_em": expira}


@router.get("/eu")
def eu(usuario: Usuario = Depends(usuario_atual)):
    return {"id": usuario.id, "nome": usuario.nome, "perfil": usuario.perfil,
            "provedor": usuario.provedor, "permissoes": sorted(usuario.permissoes)}
