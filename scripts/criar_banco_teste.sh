#!/usr/bin/env bash
# Recria o banco iosephus num MySQL local (sem Docker), do mesmo jeito que o container faz.
# Uso: MYSQL_APP_PASSWORD=teste ./scripts/criar_banco_teste.sh   (precisa de acesso root ao MySQL)
set -euo pipefail
cd "$(dirname "$0")/.."
docker_process_sql() { mysql "$@"; }
mysql -e "DROP DATABASE IF EXISTS iosephus; DROP USER IF EXISTS 'app_soc'@'%';
          CREATE DATABASE iosephus CHARACTER SET utf8mb4;"
mysql iosephus < db/mysql/01_schema.sql
source db/mysql/02_usuario_app.sh
mysql iosephus < db/mysql/03_seed_demo.sql
echo "banco iosephus recriado"
