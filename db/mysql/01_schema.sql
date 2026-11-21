-- Iosephus · MySQL 8.0.16+ · InnoDB · utf8mb4 · horários em UTC
SET NAMES utf8mb4;
-- Rodado automaticamente pelo container (docker-entrypoint-initdb.d) no banco iosephus.
-- Para rodar à mão: mysql -u root -p iosephus < 01_schema.sql

-- A. Organizações, SLA e controle de acesso (RBAC) --------------------------
CREATE TABLE organizacoes (
  id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nome               VARCHAR(150) NOT NULL,
  cnpj               CHAR(14)     NOT NULL UNIQUE,      -- texto: o CNPJ alfanumérico tem letras
  tipo               ENUM('PROVEDOR','CLIENTE') NOT NULL DEFAULT 'CLIENTE',
  pequeno_porte_lgpd BOOLEAN      NOT NULL DEFAULT FALSE, -- prazos da ANPD contam em dobro
  criada_em          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE politicas_sla (                      -- contrato: um prazo por cliente e severidade
  organizacao_id    INT UNSIGNED NOT NULL,
  severidade        ENUM('BAIXA','MEDIA','ALTA','CRITICA') NOT NULL,
  minutos_resposta  SMALLINT UNSIGNED NOT NULL,
  minutos_resolucao INT UNSIGNED      NOT NULL,
  PRIMARY KEY (organizacao_id, severidade),
  FOREIGN KEY (organizacao_id) REFERENCES organizacoes(id),
  CHECK (minutos_resolucao >= minutos_resposta)
);

CREATE TABLE perfis (
  id        TINYINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nome      VARCHAR(30) NOT NULL UNIQUE,         -- ADMIN, ANALISTA_N1, ANALISTA_N2, GESTOR_CLIENTE, SERVICO
  descricao VARCHAR(200)
);

CREATE TABLE permissoes (
  id     SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  codigo VARCHAR(60) NOT NULL UNIQUE             -- ex.: incidente.alterar_status, regra.editar
);

CREATE TABLE perfil_permissao (                   -- N:N
  perfil_id    TINYINT UNSIGNED  NOT NULL,
  permissao_id SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (perfil_id, permissao_id),
  FOREIGN KEY (perfil_id)    REFERENCES perfis(id)     ON DELETE CASCADE,
  FOREIGN KEY (permissao_id) REFERENCES permissoes(id) ON DELETE CASCADE
);

CREATE TABLE usuarios (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organizacao_id INT UNSIGNED     NOT NULL,
  perfil_id      TINYINT UNSIGNED NOT NULL,
  nome           VARCHAR(120) NOT NULL,
  email          VARCHAR(254) NOT NULL UNIQUE,
  senha_hash     VARCHAR(255) NOT NULL,           -- Argon2id/bcrypt, nunca a senha
  mfa_habilitado BOOLEAN NOT NULL DEFAULT FALSE,
  ativo          BOOLEAN NOT NULL DEFAULT TRUE,
  FOREIGN KEY (organizacao_id) REFERENCES organizacoes(id),
  FOREIGN KEY (perfil_id)      REFERENCES perfis(id)
);

-- B. Ativos e vulnerabilidades ----------------------------------------------
CREATE TABLE ativos (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organizacao_id      INT UNSIGNED NOT NULL,
  hostname            VARCHAR(100) NOT NULL,
  ip                  VARCHAR(45),                -- comporta IPv6
  tipo                ENUM('SERVIDOR','ESTACAO','FIREWALL','REDE','IOT','OUTRO') NOT NULL,
  sistema_operacional VARCHAR(80),
  criticidade         ENUM('BAIXA','MEDIA','ALTA','CRITICA') NOT NULL,
  responsavel_id      INT UNSIGNED,
  desativado_em       DATETIME,                   -- exclusão lógica: o histórico segue apontando para ele
  UNIQUE (organizacao_id, hostname),
  INDEX (organizacao_id, ip),                     -- a ingestão resolve ativo_id pelo IP
  FOREIGN KEY (organizacao_id) REFERENCES organizacoes(id),
  FOREIGN KEY (responsavel_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

CREATE TABLE vulnerabilidades (                   -- catálogo (CVE)
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  cve_id     VARCHAR(20) UNIQUE,                  -- NULL para falhas sem CVE (ex.: configuração)
  titulo     VARCHAR(200) NOT NULL,
  cvss       DECIMAL(3,1) NOT NULL CHECK (cvss > 0 AND cvss <= 10),
  severidade VARCHAR(8) AS (CASE WHEN cvss >= 9 THEN 'CRITICA'
                                 WHEN cvss >= 7 THEN 'ALTA'
                                 WHEN cvss >= 4 THEN 'MEDIA'
                                 ELSE 'BAIXA' END) STORED   -- derivada do CVSS, nunca digitada
);

CREATE TABLE ativo_vulnerabilidade (              -- N:N com atributos próprios
  ativo_id           INT UNSIGNED NOT NULL,
  vulnerabilidade_id INT UNSIGNED NOT NULL,
  status             ENUM('ABERTA','EM_CORRECAO','CORRIGIDA','RISCO_ACEITO') NOT NULL DEFAULT 'ABERTA',
  detectada_em       DATETIME NOT NULL,
  prazo_correcao     DATE     NOT NULL,
  corrigida_em       DATETIME,
  varredura_id       CHAR(24) NOT NULL,           -- ObjectId do relatório em varreduras (MongoDB)
  PRIMARY KEY (ativo_id, vulnerabilidade_id),
  FOREIGN KEY (ativo_id)           REFERENCES ativos(id),
  FOREIGN KEY (vulnerabilidade_id) REFERENCES vulnerabilidades(id),
  CHECK (varredura_id REGEXP '^[0-9a-f]{24}$')
);

-- C. Detecção e resposta a incidentes ---------------------------------------
CREATE TABLE regras_deteccao (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nome          VARCHAR(120) NOT NULL UNIQUE,
  tecnica_mitre VARCHAR(12)  NOT NULL,            -- ex.: T1110.001
  severidade    ENUM('BAIXA','MEDIA','ALTA','CRITICA') NOT NULL,
  condicao      JSON NOT NULL,                    -- parâmetros lidos pelo motor (tipo, limiar, janela...)
  versao        SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  ativa         BOOLEAN NOT NULL DEFAULT TRUE,
  criada_por    INT UNSIGNED NOT NULL,
  atualizada_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (criada_por) REFERENCES usuarios(id)
);

CREATE TABLE incidentes (
  id                        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organizacao_id            INT UNSIGNED NOT NULL,
  regra_id                  INT UNSIGNED,          -- NULL = aberto manualmente
  analista_id               INT UNSIGNED,          -- NULL = na fila
  alerta_origem_id          CHAR(24) UNIQUE,       -- ObjectId do alerta (MongoDB); UNIQUE impede promoção dupla
  titulo                    VARCHAR(200) NOT NULL,
  severidade                ENUM('BAIXA','MEDIA','ALTA','CRITICA') NOT NULL,
  status                    ENUM('ABERTO','EM_ANALISE','CONTIDO','ERRADICADO','RECUPERADO','ENCERRADO')
                            NOT NULL DEFAULT 'ABERTO',
  aberto_em                 DATETIME NOT NULL,
  prazo_resposta            DATETIME NOT NULL,
  prazo_resolucao           DATETIME NOT NULL,
  primeira_resposta_em      DATETIME,
  encerrado_em              DATETIME,
  ciencia_dados_pessoais_em DATETIME,              -- início do prazo de comunicação à ANPD
  comunicado_anpd_em        DATETIME,
  INDEX (organizacao_id, status),
  INDEX (status, prazo_resolucao),                 -- fila do dashboard ordenada por SLA
  FOREIGN KEY (organizacao_id) REFERENCES organizacoes(id),
  FOREIGN KEY (regra_id)       REFERENCES regras_deteccao(id),
  FOREIGN KEY (analista_id)    REFERENCES usuarios(id),
  CHECK (alerta_origem_id REGEXP '^[0-9a-f]{24}$'),
  CHECK ((status = 'ENCERRADO') = (encerrado_em IS NOT NULL))  -- status e data nunca discordam
);

CREATE TABLE incidente_ativo (                    -- N:N
  incidente_id INT UNSIGNED NOT NULL,
  ativo_id     INT UNSIGNED NOT NULL,
  papel        ENUM('ORIGEM','ALVO','AFETADO') NOT NULL,
  PRIMARY KEY (incidente_id, ativo_id),
  FOREIGN KEY (incidente_id) REFERENCES incidentes(id),
  FOREIGN KEY (ativo_id)     REFERENCES ativos(id)
);

CREATE TABLE incidente_evidencia (                -- ponte para o MongoDB
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incidente_id INT UNSIGNED NOT NULL,
  evento_id    CHAR(24) NOT NULL,                 -- ObjectId do documento em eventos (MongoDB)
  hash_sha256  CHAR(64) NOT NULL,                 -- hash do log bruto, calculado na ingestão
  anexada_por  INT UNSIGNED NOT NULL,
  anexada_em   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (incidente_id, evento_id),
  FOREIGN KEY (incidente_id) REFERENCES incidentes(id),
  FOREIGN KEY (anexada_por)  REFERENCES usuarios(id),
  CHECK (evento_id   REGEXP '^[0-9a-f]{24}$'),
  CHECK (hash_sha256 REGEXP '^[0-9a-f]{64}$')
);

CREATE TABLE incidente_historico (                -- trilha de auditoria: só inserção
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incidente_id    INT UNSIGNED NOT NULL,
  usuario_id      INT UNSIGNED NOT NULL,
  status_anterior ENUM('ABERTO','EM_ANALISE','CONTIDO','ERRADICADO','RECUPERADO','ENCERRADO'),
  status_novo     ENUM('ABERTO','EM_ANALISE','CONTIDO','ERRADICADO','RECUPERADO','ENCERRADO') NOT NULL,
  comentario      TEXT,
  registrado_em   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (incidente_id) REFERENCES incidentes(id),
  FOREIGN KEY (usuario_id)   REFERENCES usuarios(id)
);

