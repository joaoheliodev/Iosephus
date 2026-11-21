"""Comandos de administração.

  python -m app.cli definir-senha analista2@iosephus.local
  python -m app.cli correlacionar      # roda um ciclo do motor agora
  python -m app.cli reconciliar
"""
import getpass
import sys

from sqlalchemy import text

from .auth import gerar_hash
from .db import mysql


def definir_senha(email: str) -> None:
    senha = getpass.getpass("Nova senha: ")
    if len(senha) < 12:
        sys.exit("Use pelo menos 12 caracteres.")
    if senha != getpass.getpass("Repita: "):
        sys.exit("As senhas não conferem.")
    with mysql().begin() as c:
        r = c.execute(text("UPDATE usuarios SET senha_hash = :h WHERE email = :e"),
                      {"h": gerar_hash(senha), "e": email.strip().lower()})
    if r.rowcount == 0:
        sys.exit(f"Usuário {email} não encontrado.")
    print(f"Senha de {email} definida.")


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[0] == "definir-senha":
        definir_senha(argv[1])
    elif argv[:1] == ["correlacionar"]:
        from .motor import correlacionar
        print(f"alertas novos: {len(correlacionar())}")
    elif argv[:1] == ["reconciliar"]:
        from .motor import reconciliar
        print(reconciliar())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
