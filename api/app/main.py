import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from . import auth, incidentes, ingestao, motor
from .config import settings
from .db import mongo, mysql
from .limites import LimiteDeCorpo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("iosephus")
ESTATICO = Path(__file__).parent / "static"


def _laco_do_motor(parar: threading.Event) -> None:
    """Correlação a cada 30 s e reconciliação a cada 5 min (uma réplica da API basta no MVP)."""
    cfg = settings()
    ultima_reconciliacao = 0.0
    while not parar.is_set():
        try:
            motor.correlacionar()
            if time.monotonic() - ultima_reconciliacao >= cfg.reconciliacao_intervalo_s:
                r = motor.reconciliar()
                ultima_reconciliacao = time.monotonic()
                if any(r.values()):
                    log.info("reconciliação: %s", r)
        except Exception:
            log.exception("erro no ciclo do motor")
        parar.wait(cfg.correlacao_intervalo_s)


@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    cfg = settings()  # segredo vazio/curto derruba a subida aqui, não na primeira requisição
    parar = threading.Event()
    if cfg.worker_ativo:
        threading.Thread(target=_laco_do_motor, args=(parar,), daemon=True, name="motor").start()
    yield
    parar.set()


app = FastAPI(title="Iosephus SOC", version="0.1.0", lifespan=ciclo_de_vida,
              docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
app.include_router(auth.router)
app.include_router(ingestao.router)
app.include_router(incidentes.router)
app.add_middleware(LimiteDeCorpo)  # antes do middleware abaixo: o 413 também leva os cabeçalhos


@app.middleware("http")
async def cabecalhos_de_seguranca(request: Request, call_next):
    resposta = await call_next(request)
    # Caminho que o roteador usou. request.url é remontado a partir do Host, que o cliente controla
    caminho = request.scope["path"]
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    if caminho.startswith("/api/"):  # token, incidentes e evidências não ficam em cache
        resposta.headers["Cache-Control"] = "no-store"
    if not (caminho == "/api/docs" or caminho.startswith("/api/docs/")):
        resposta.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'")
    return resposta


@app.get("/api/saude", tags=["infra"])
def saude():
    estado = {}
    try:
        with mysql().connect() as c:
            c.execute(text("SELECT 1"))
        estado["mysql"] = "ok"
    except Exception:
        estado["mysql"] = "erro"
    try:
        mongo().command("ping")
        estado["mongodb"] = "ok"
    except Exception:
        estado["mongodb"] = "erro"
    return estado


app.mount("/static", StaticFiles(directory=ESTATICO), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(ESTATICO / "index.html")
