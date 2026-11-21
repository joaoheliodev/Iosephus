#!/usr/bin/env bash
# Gera um .env com segredos aleatórios (hex: seguros dentro de URLs de conexão).
# Uso:  ./scripts/gerar_env.sh > .env && chmod 600 .env
set -euo pipefail
aleatorio() { openssl rand -hex "$1"; }
cat <<FIM
MYSQL_ROOT_PASSWORD=$(aleatorio 24)
MYSQL_APP_PASSWORD=$(aleatorio 24)
MONGO_ROOT_PASSWORD=$(aleatorio 24)
MONGO_APP_PASSWORD=$(aleatorio 24)
INGEST_API_KEY=$(aleatorio 32)
JWT_SECRET=$(aleatorio 32)
FIM
