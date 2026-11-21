"""Limites contra abuso: tentativas de login e tamanho do corpo das requisições."""
import threading
import time
from collections import deque

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from .config import settings


class LimitadorDeTentativas:
    """Janela deslizante em memória (uma réplica da API basta no MVP).

    `consumir` reserva a tentativa ANTES do trabalho caro (Argon2): rajadas paralelas não
    passam todas pela checagem antes de a primeira falha ser registrada.
    """

    def __init__(self, max_chaves: int = 50_000):
        self._registros: dict[str, deque[float]] = {}
        self._trava = threading.Lock()
        self._max_chaves = max_chaves

    def consumir(self, chave: str, maximo: int, janela_s: float) -> bool:
        agora = time.monotonic()
        with self._trava:
            fila = self._registros.get(chave)
            if fila is None:
                if len(self._registros) >= self._max_chaves:
                    self._purgar(agora, janela_s)
                fila = self._registros[chave] = deque()
            while fila and fila[0] <= agora - janela_s:
                fila.popleft()
            if len(fila) >= maximo:
                return False
            fila.append(agora)
            return True

    def devolver(self, chave: str) -> None:
        """Desfaz a última reserva (a tentativa deu certo)."""
        with self._trava:
            fila = self._registros.get(chave)
            if fila:
                fila.pop()
            if not fila:
                self._registros.pop(chave, None)

    def esquecer(self, chave: str) -> None:
        with self._trava:
            self._registros.pop(chave, None)

    def zerar(self) -> None:
        with self._trava:
            self._registros.clear()

    def _purgar(self, agora: float, janela_s: float) -> None:
        # Memória limitada: tira as chaves vencidas; se não bastar, as mais antigas
        for chave in [k for k, f in self._registros.items() if not f or f[-1] <= agora - janela_s]:
            del self._registros[chave]
        excesso = len(self._registros) - self._max_chaves + 1
        for chave in list(self._registros)[:max(excesso, 0)]:
            del self._registros[chave]


class LimiteDeCorpo:
    """Recusa com 413 o corpo maior que o limite, antes de o JSON ser montado na memória.

    Sem isso, qualquer um (sem login) manda um corpo de centenas de MB para /api/auth/login.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        cfg = settings()
        limite = cfg.max_corpo_ingestao_bytes if scope["path"] == "/api/eventos" else cfg.max_corpo_bytes

        for nome, valor in scope["headers"]:
            if nome == b"content-length":
                try:
                    excede = int(valor) > limite
                except ValueError:
                    excede = True
                if excede:
                    await JSONResponse({"detail": "Corpo da requisição grande demais"}, 413)(
                        scope, receive, send)
                    return

        recebido = 0

        async def receber_com_limite():  # corpo em chunks, sem Content-Length
            nonlocal recebido
            mensagem = await receive()
            if mensagem["type"] == "http.request":
                recebido += len(mensagem.get("body", b""))
                if recebido > limite:
                    raise HTTPException(413, "Corpo da requisição grande demais")
            return mensagem

        await self.app(scope, receber_com_limite, send)
