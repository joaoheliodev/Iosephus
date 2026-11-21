// Iosephus · MongoDB — coleções, validação, índices, usuário da aplicação e IoCs de demonstração.
// Roda uma vez, na primeira subida do container (docker-entrypoint-initdb.d), como root.
// Para rodar à mão:  mongosh "mongodb://root:SENHA@localhost:27017/admin" 01_init.js

db = db.getSiblingDB("iosephus");

// Usuário da aplicação: só lê e escreve no banco iosephus
const senhaApp = process.env.MONGO_APP_PASSWORD;
if (!senhaApp) throw new Error("MONGO_APP_PASSWORD não definido");
db.createUser({ user: "app_soc", pwd: senhaApp, roles: [{ role: "readWrite", db: "iosephus" }] });

// eventos: fato bruto, um envelope comum para qualquer fonte
db.createCollection("eventos", {
  validator: { $jsonSchema: {
    bsonType: "object",
    required: ["organizacao_id", "fonte", "ocorrido_em", "recebido_em", "bruto", "hash_bruto", "preservado"],
    properties: {
      organizacao_id: { bsonType: ["int", "long"] },
      ativo_id:       { bsonType: ["int", "long", "null"] },   // null = dispositivo fora do inventário
      fonte: { bsonType: "object", required: ["tipo", "produto"],
               properties: { tipo: { enum: ["autenticacao", "firewall", "ids", "edr", "dns"] } } },
      ocorrido_em: { bsonType: "date" },
      recebido_em: { bsonType: "date" },
      bruto:       { bsonType: "string" },
      hash_bruto:  { bsonType: "string", pattern: "^[0-9a-f]{64}$" },
      preservado:  { bsonType: "bool" },
      dados:       { bsonType: "object" }                      // livre: cada fonte tem o seu formato
    }
  } }
});
db.eventos.createIndex({ organizacao_id: 1, ocorrido_em: -1 });                        // linha do tempo do cliente
db.eventos.createIndex({ organizacao_id: 1, "rede.ip_origem": 1, ocorrido_em: -1 });   // pivô pelo IP atacante
db.eventos.createIndex({ "fonte.tipo": 1, "dados.evento_id": 1, ocorrido_em: -1 });   // janela do motor de correlação
db.eventos.createIndex({ recebido_em: 1 }, {                                           // TTL parcial: 180 dias,
  expireAfterSeconds: 60 * 60 * 24 * 180,                                              // mas nunca apaga evidência
  partialFilterExpression: { preservado: false }
});

// alertas: saída do motor, antes de virar incidente
db.createCollection("alertas");
db.alertas.createIndex({ organizacao_id: 1, status: 1, criado_em: -1 });               // fila de triagem
db.alertas.createIndex({ status: 1, criado_em: 1 });                                   // reconciliação
db.alertas.createIndex({ "regra.id": 1, organizacao_id: 1, "resumo.ip_origem": 1, ativo_id: 1, criado_em: -1 }); // deduplicação

// indicadores_ameaca: inteligência de ameaças (IoC)
db.indicadores_ameaca.createIndex({ tipo: 1, valor: 1 }, { unique: true });             // um documento por IoC
db.indicadores_ameaca.createIndex({ expira_em: 1 }, { expireAfterSeconds: 0 });         // expira na data do campo

// varreduras e telemetria (ainda não usadas pela API do MVP)
db.varreduras.createIndex({ "hosts.ativo_id": 1, concluida_em: -1 });
db.createCollection("telemetria_rede", {
  timeseries: { timeField: "ts", metaField: "meta", granularity: "minutes" },
  expireAfterSeconds: 60 * 60 * 24 * 30
});

// IoC de demonstração: o IP do cenário de Vale Verde (RFC 5737, faixa de documentação)
const umAno = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
db.indicadores_ameaca.insertOne({
  tipo: "ipv4", valor: "203.0.113.45",
  tags: ["rdp-bruteforce", "botnet"],
  fontes: [{ nome: "AbuseIPDB", confianca: 90, visto_em: new Date() }],
  primeiro_visto: new Date(),
  expira_em: umAno
});

print("iosephus: MongoDB inicializado");
