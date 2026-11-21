# IOSEPHVS · *custos datorum*

SOC-as-a-Service para pequenas empresas e prefeituras. O Iosephus recebe logs de segurança, detecta ataques, abre incidentes com prazo de SLA e mantém a cadeia de custódia das evidências.

O princípio do modelo é: **MongoDB guarda o fato bruto; MySQL guarda a decisão.** Os dois bancos se ligam por ObjectId + hash SHA-256, nunca por chave estrangeira.

```
coletores ──POST /api/eventos──▶ API ──▶ MongoDB  eventos (log bruto + hash), alertas, IoCs
                                  │
                         motor (a cada 30 s)
                     correlaciona ▸ alerta ▸ promove
                                  │
                                  ▼
                                MySQL    incidentes, SLA, ativos, evidências, auditoria
                                  │
                              dashboard  fila por SLA, evidências com verificação de integridade
```

## O que o MVP faz

- **Ingestão** (`POST /api/eventos`, chave `X-API-Key`)
  - Calcula o SHA-256 do log bruto.
  - Descobre o ativo pelo IP de destino.
  - Grava no MongoDB com TTL de 180 dias.
- **Correlação**
  - Lê as regras ativas do MySQL. A regra 15 detecta força bruta seguida de logon bem-sucedido (T1110.001).
  - Agrega na janela de tempo e enriquece com inteligência de ameaças.
  - Não repete o alerta para o mesmo ataque.
- **Promoção para incidente**: uma transação no MySQL grava o incidente, os prazos da `politicas_sla`, o ativo, as evidências e o histórico. Só depois do COMMIT o MongoDB é atualizado e os eventos saem do TTL.
- **Reconciliação** (a cada 5 min, idempotente): conserta o que ficou pela metade entre os dois bancos.
- **Dashboard**
  - Fila ordenada pelo prazo do SLA.
  - Detalhe com a vulnerabilidade crítica do ativo atacado.
  - Evidências marcadas como `INTEGRA`, `ADULTERADA` ou `AUSENTE`.
  - "Assumir" com concorrência otimista e ciclo de status NIST, só para frente.
  - Histórico de auditoria.
- **Controle de acesso**
  - Login com Argon2id + JWT.
  - Permissões do RBAC do próprio modelo.
  - O gestor do cliente vê só a própria organização.
  - A conta da aplicação no MySQL não consegue apagar evidência nem histórico (GRANT).

## Rodar na sua máquina

Pré-requisitos: Docker com o plugin Compose e Python 3.

```bash
./scripts/gerar_env.sh > .env && chmod 600 .env
docker compose up -d --build                 # 1ª vez: os bancos se inicializam sozinhos
docker compose exec api python -m app.cli definir-senha analista2@iosephus.local

# simula o ataque de Vale Verde
INGEST_API_KEY=$(grep INGEST_API_KEY .env | cut -d= -f2) python3 scripts/simular_ataque.py
```

Abra http://127.0.0.1:8000 e entre como `analista2@iosephus.local`. O incidente aparece em até 30 segundos. A documentação da API fica em `/api/docs`.

Usuários de demonstração (todos começam **sem senha válida**):

| E-mail | Perfil | Pode |
|---|---|---|
| `admin@iosephus.local` | ADMIN | tudo |
| `analista2@iosephus.local`, `analista3@iosephus.local` | ANALISTA_N2 | assumir e mudar status |
| `ti@valeverde.example` | GESTOR_CLIENTE | só ver os incidentes da prefeitura |

Para entrar nos bancos:

```bash
docker compose exec mysql mysql -uroot -p iosephus      # senha: MYSQL_ROOT_PASSWORD do .env
docker compose exec mongo mongosh -u root -p --authenticationDatabase admin iosephus
```

Para zerar tudo: `docker compose down -v`.

## Subir na AWS

Fica tudo numa EC2 `t4g.small` (ARM, 2 GB) com Docker, criada pelo CDK em Python.

O código vai para o S3 como asset, então funciona com o repositório privado. A instância baixa o código e gera os próprios segredos no primeiro boot; eles nunca passam pelo Git nem pelo CDK.

```bash
cd infra
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

npx aws-cdk@2 bootstrap                                  # só na primeira vez por conta/região
npx aws-cdk@2 deploy -c email_alerta=SEU@EMAIL
```

O deploy imprime comandos prontos:

| Saída | Para quê |
|---|---|
| `TunelDashboard` | abre o dashboard em http://localhost:8000 por túnel SSM, sem porta aberta na internet |
| `Terminal` | shell na instância, sem SSH e sem chave |
| `Atualizar` | depois de um novo `cdk deploy`, instala o código novo sem perder os dados |
| `Ligar` / `Desligar` | economizar quando não estiver usando |

O túnel e o terminal precisam do `session-manager-plugin`.

Na primeira vez, defina a senha de um analista pelo terminal SSM:

```bash
sudo -i
cd /opt/iosephus/app && docker compose exec api python -m app.cli definir-senha analista2@iosephus.local
grep INGEST_API_KEY /opt/iosephus/.env        # chave para os coletores
```

**Abrir o dashboard para a internet (opcional).** O padrão é tudo fechado. Para liberar só o seu IP na porta 80:

```bash
npx aws-cdk@2 deploy -c email_alerta=SEU@EMAIL -c acesso_cidr=$(curl -s https://checkip.amazonaws.com)/32
```

Mesmo assim é HTTP sem TLS: prefira o túnel SSM. Para expor de verdade, coloque um domínio e TLS (por exemplo, Caddy na frente da API).

### Custo e limite de gastos

| Item | ≈ US$/mês (us-east-1, ligada 24 h) |
|---|---|
| EC2 t4g.small | 12,3 |
| EBS gp3 20 GB | 1,6 |
| IPv4 público | 3,6 |
| VPC sem NAT Gateway, SSM, S3 do asset | ~0 |
| **Total** | **~17,5** |

Desligada, a instância custa só o disco (~US$ 1,60 por mês).

Com `-c email_alerta=...`, o stack cria uma **ação de orçamento**: quando o gasto real chega a 90% do orçamento `iosephus-20usd`, a AWS desliga a EC2 sozinha.

Esse orçamento precisa existir antes do deploy (crie pelo console ou pela CLI). Para usar outro nome, passe `-c orcamento=NOME`.

O faturamento da AWS atualiza com algumas horas de atraso, então isso é um freio e não um teto exato.

## Testes

```bash
cd api && pip install -r requirements-dev.txt
pytest                                        # regras de domínio

# fluxo completo contra um MySQL local (schema e GRANTs reais; MongoDB simulado com mongomock)
MYSQL_APP_PASSWORD=teste ../scripts/criar_banco_teste.sh
IOSEPHUS_TESTE_MYSQL=1 pytest
```

O GitHub Actions (`.github/workflows/testes.yml`) roda os dois a cada push, com MySQL 8.4 de verdade.

## Estrutura

```
api/app/
  ingestao.py     POST /api/eventos: hash, resolução do ativo, gravação no MongoDB
  motor.py        correlação, promoção (MySQL → depois MongoDB) e reconciliação
  incidentes.py   fila, detalhe com integridade, assumir, mudar status
  auth.py         login Argon2id + JWT, RBAC, chave dos coletores
  static/         dashboard (HTML + JS puro, CSP restrita)
db/mysql/         schema (14 tabelas), usuário da aplicação com GRANT mínimo, seed de demonstração
db/mongo/         coleções com $jsonSchema, TTL parcial, índices, IoC de demonstração
infra/            AWS CDK: VPC sem NAT, EC2 com SSM, ação de orçamento
scripts/          gerar .env, simular o ataque, criar banco de teste
```

## Próximos passos

- TLS com domínio próprio.
- Coletor real (Winlogbeat ou Fluent Bit enviando para `/api/eventos`).
- Uma chave de ingestão por cliente.
- MFA no login: a coluna `mfa_habilitado` já existe.
- Backup dos volumes para o S3.
- Mais tipos de regra no `motor.DETECTORES`.
