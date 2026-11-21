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

# O entrypoint do MySQL EXECUTA (em vez de carregar) o .sh com permissão de execução, e aí
# docker_process_sql não existe: sem isto, app_soc e os GRANTs nunca eram criados no 1º boot
if ! declare -F docker_process_sql >/dev/null; then
  docker_process_sql() { MYSQL_PWD="${MYSQL_ROOT_PASSWORD:-}" mysql --protocol=socket -uroot "$@"; }
fi

# A senha entra num literal SQL executado como root: escapa \ e ' em vez de interpolar crua
# (uma senha com aspa quebraria o script ou injetaria SQL)
senha_sql=${MYSQL_APP_PASSWORD//\\/\\\\}
senha_sql=${senha_sql//\'/\'\'}

docker_process_sql --database=iosephus <<-EOSQL
	CREATE USER 'app_soc'@'%' IDENTIFIED BY '${senha_sql}';
	GRANT SELECT                 ON iosephus.*                   TO 'app_soc'@'%';
	GRANT INSERT, UPDATE         ON iosephus.incidentes          TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_ativo     TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_evidencia TO 'app_soc'@'%';
	GRANT INSERT                 ON iosephus.incidente_historico TO 'app_soc'@'%';
	GRANT UPDATE (senha_hash)    ON iosephus.usuarios            TO 'app_soc'@'%';
EOSQL
