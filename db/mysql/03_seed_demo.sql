-- Dados de demonstração: Prefeitura de Vale Verde (fictícios).
-- Em produção, apague este arquivo antes da primeira subida.
-- Nenhum usuário tem senha válida: defina com  docker compose exec api python -m app.cli definir-senha <email>
SET NAMES utf8mb4;

INSERT INTO organizacoes (id, nome, cnpj, tipo) VALUES
 (1, 'Iosephus SOC', '12ABC34501DE35', 'PROVEDOR'),        -- CNPJ alfanumérico cabe no CHAR(14)
 (7, 'Prefeitura de Vale Verde', '11222333000181', 'CLIENTE');

INSERT INTO politicas_sla VALUES
 (7,'CRITICA',15,240),(7,'ALTA',60,720),(7,'MEDIA',240,2880),(7,'BAIXA',1440,10080);

INSERT INTO perfis (id, nome) VALUES
 (1,'ADMIN'),(2,'ANALISTA_N1'),(3,'ANALISTA_N2'),(4,'GESTOR_CLIENTE'),(5,'SERVICO');
INSERT INTO permissoes (id, codigo) VALUES
 (1,'incidente.ler'),(2,'incidente.alterar_status'),(3,'evidencia.anexar'),(4,'regra.editar'),(5,'usuario.gerenciar');
INSERT INTO perfil_permissao VALUES
 (1,1),(1,2),(1,3),(1,4),(1,5),(2,1),(2,3),(3,1),(3,2),(3,3),(3,4),(4,1),(5,1),(5,3);

-- senha_hash "!" nunca confere com Argon2: a conta existe, mas ninguém entra até definir a senha
INSERT INTO usuarios (id, organizacao_id, perfil_id, nome, email, senha_hash, mfa_habilitado) VALUES
 (1, 1, 1, 'Administrador',        'admin@iosephus.local',     '!', FALSE),
 (2, 1, 5, 'svc-motor-correlacao', 'motor@iosephus.local',     '!', FALSE),
 (5, 1, 3, 'Analista N2',          'analista2@iosephus.local', '!', TRUE),
 (6, 1, 3, 'Analista N2 (b)',      'analista3@iosephus.local', '!', TRUE),
 (9, 7, 4, 'Gestor de TI',         'ti@valeverde.example',     '!', TRUE);

INSERT INTO ativos (id, organizacao_id, hostname, ip, tipo, sistema_operacional, criticidade, responsavel_id) VALUES
 (3,  7, 'FW-BORDA',     '10.20.0.1',  'FIREWALL', 'pfSense',                'CRITICA', 9),
 (42, 7, 'SRV-ARQUIVOS', '10.20.0.15', 'SERVIDOR', 'Windows Server 2008 R2', 'ALTA',    9);

INSERT INTO vulnerabilidades (id, cve_id, titulo, cvss) VALUES
 (311, 'CVE-2019-0708', 'BlueKeep: execução remota de código no RDP', 9.8);
INSERT INTO ativo_vulnerabilidade (ativo_id, vulnerabilidade_id, detectada_em, prazo_correcao, varredura_id)
VALUES (42, 311, '2026-11-10 02:47:10', '2026-11-17', '6af285ae5d2e8a41f0000412');

-- "tipo" diz ao motor qual detector usar; o resto são os parâmetros dele
INSERT INTO regras_deteccao (id, nome, tecnica_mitre, severidade, condicao, versao, criada_por) VALUES
 (15, 'Força bruta RDP seguida de logon bem-sucedido', 'T1110.001', 'CRITICA',
  '{"tipo": "forca_bruta_com_sucesso", "evento_falha": 4625, "evento_sucesso": 4624, "limiar_falhas": 20, "janela_min": 10}',
  3, 5);
