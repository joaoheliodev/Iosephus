#!/bin/bash
# Cria o usuário da aplicação com o mínimo de privilégio.
# Roda uma vez, na primeira subida do container (docker-entrypoint-initdb.d).
# Custódia (incidente_evidencia) e auditoria (incidente_historico) só aceitam INSERT:
# nem a API consegue apagar ou alterar evidência e histórico.
set -euo pipefail

if [[ -z "${MYSQL_APP_PASSWORD:-}" ]]; then
  echo "MYSQL_APP_PASSWORD não definido" >&2
  exit 1
fi

docker_process_sql --database=iosephus <<-EOSQL
	CREATE USER 'app_soc'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
	GRANT SELECT                 ON iosephus.*                   TO 'app_soc'@'%';
	GRANT INSERT, UPDATE         ON iosephus.incidentes          TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_ativo     TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_evidencia TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_historico TO 'app_soc'@'%';
	GRANT UPDATE (senha_hash)    ON iosephus.usuarios            TO 'app_soc'@'%';
EOSQL
