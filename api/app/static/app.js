"use strict";
// Dashboard do Iosephus. Todo dado vindo da API entra na página por textContent (nunca innerHTML).

const $ = (id) => document.getElementById(id);
let token = null;
let eu = null;
let selecionado = null;

try { token = sessionStorage.getItem("iosephus_token"); } catch (_) { /* navegação privada */ }

function el(tag, attrs = {}, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const f of filhos.flat()) {
    if (f === null || f === undefined) continue;
    n.append(f instanceof Node ? f : document.createTextNode(String(f)));
  }
  return n;
}

async function api(caminho, opcoes = {}) {
  const r = await fetch(caminho, {
    ...opcoes,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (r.status === 401 && caminho !== "/api/auth/login") { sair(); throw new Error("Sessão expirada"); }
  const corpo = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = corpo.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : `Erro ${r.status}`);
  }
  return corpo;
}

const fmt = (iso) => iso ? new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "medium" }) : "–";

function sla(min, status) {
  if (status === "ENCERRADO") return el("span", { class: "sla-ok" }, "—");
  if (min < 0) return el("span", { class: "sla-estourado" }, `estourado há ${tempo(-min)}`);
  return el("span", { class: min < 30 ? "sla-perto" : "sla-ok" }, tempo(min));
}
function tempo(min) {
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  return h < 48 ? `${h} h ${min % 60} min` : `${Math.floor(h / 24)} d`;
}

// ---------------------------------------------------------------- sessão
async function entrar(ev) {
  ev.preventDefault();
  $("erro-login").textContent = "";
  try {
    const r = await api("/api/auth/login", {
      method: "POST", body: JSON.stringify({ email: $("email").value, senha: $("senha").value }),
    });
    token = r.token;
    try { sessionStorage.setItem("iosephus_token", token); } catch (_) {}
    $("senha").value = "";
    await iniciar();
  } catch (e) { $("erro-login").textContent = e.message; }
}

function sair() {
  token = null; eu = null; selecionado = null;
  try { sessionStorage.removeItem("iosephus_token"); } catch (_) {}
  $("tela-painel").hidden = true; $("sessao").hidden = true; $("tela-login").hidden = false;
}

async function iniciar() {
  if (!token) { sair(); return; }
  eu = await api("/api/auth/eu");
  $("quem").textContent = `${eu.nome} · ${eu.perfil}`;
  $("tela-login").hidden = true; $("sessao").hidden = false; $("tela-painel").hidden = false;
  await atualizar();
}

// ---------------------------------------------------------------- fila
async function atualizar() {
  if (!token) return;
  const abertos = !$("mostrar-encerrados").checked;
  const [resumo, fila] = await Promise.all([
    api("/api/incidentes/resumo"), api(`/api/incidentes?abertos=${abertos}`),
  ]);
  $("k-abertos").textContent = resumo.abertos;
  $("k-criticos").textContent = resumo.criticos;
  $("k-fila").textContent = resumo.na_fila;
  $("k-sla").textContent = resumo.sla_estourado;

  const corpo = $("linhas");
  corpo.replaceChildren(...fila.map((i) => el("tr",
    { class: i.id === selecionado ? "selecionado" : "", onclick: () => abrir(i.id) },
    el("td", { class: "mono" }, i.id),
    el("td", {}, i.cliente),
    el("td", {}, i.titulo),
    el("td", {}, el("span", { class: `sev ${i.severidade}` }, i.severidade)),
    el("td", { class: "status" }, i.status),
    el("td", {}, sla(i.min_restantes, i.status)),
  )));
  $("vazio").hidden = fila.length > 0;
  if (selecionado) await abrir(selecionado, false);
}

// ---------------------------------------------------------------- detalhe
async function abrir(id, marcar = true) {
  selecionado = id;
  if (marcar) for (const tr of $("linhas").children) tr.classList.toggle("selecionado", tr.firstChild.textContent === String(id));
  const d = await api(`/api/incidentes/${id}`);
  const i = d.incidente;
  const painel = $("detalhe");
  const blocos = [
    el("h2", {}, `Incidente ${i.id}`),
    el("p", {}, el("span", { class: `sev ${i.severidade}` }, i.severidade), " ", i.titulo),
    el("dl", {},
      el("dt", {}, "Cliente"), el("dd", {}, i.cliente),
      el("dt", {}, "Status"), el("dd", { class: "status" }, i.status),
      el("dt", {}, "Analista"), el("dd", {}, i.analista || "na fila"),
      el("dt", {}, "Aberto em"), el("dd", {}, fmt(i.aberto_em)),
      el("dt", {}, "Prazo de resposta"), el("dd", {}, fmt(i.prazo_resposta)),
      el("dt", {}, "Prazo de resolução"), el("dd", {}, fmt(i.prazo_resolucao)),
      el("dt", {}, "Alerta (MongoDB)"), el("dd", { class: "mono" }, i.alerta_origem_id || "manual"),
    ),
  ];

  if (d.alerta && d.alerta.enriquecimento) {
    blocos.push(el("div", { class: "aviso-ioc" },
      `IP ${d.alerta.resumo.ip_origem} consta em inteligência de ameaças (${(d.alerta.enriquecimento.tags || []).join(", ")}; confiança ${d.alerta.enriquecimento.confianca ?? "?"}).`));
  }
  blocos.push(acoes(i, d.proximos_status));

  blocos.push(el("h3", {}, "Ativos"));
  blocos.push(d.ativos.length ? el("ul", {}, d.ativos.map((a) =>
    el("li", {}, `${a.hostname} (${a.ip || "sem IP"}) · ${a.papel} · criticidade ${a.criticidade}`))) : el("p", { class: "vazio" }, "Nenhum ativo do inventário."));

  if (d.vulnerabilidades.length) {
    blocos.push(el("h3", {}, "Vulnerabilidades abertas nesses ativos"));
    blocos.push(el("ul", {}, d.vulnerabilidades.map((v) =>
      el("li", {}, `${v.hostname}: ${v.cve_id || "sem CVE"} · CVSS ${v.cvss} (${v.severidade}) · corrigir até ${v.prazo_correcao}`))));
  }

  const integras = d.evidencias.filter((e) => e.integridade === "INTEGRA").length;
  blocos.push(el("h3", {}, `Evidências · ${integras}/${d.evidencias.length} íntegras`));
  blocos.push(el("div", { class: "evidencias" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "Quando"), el("th", {}, "Evento"), el("th", {}, "Origem"), el("th", {}, "Hash"))),
    el("tbody", {}, d.evidencias.map((e) => el("tr", {},
      el("td", { class: "mono" }, fmt(e.ocorrido_em)),
      el("td", {}, e.evento ?? e.fonte?.tipo ?? "–", e.usuario_alvo ? ` · ${e.usuario_alvo}` : ""),
      el("td", { class: "mono" }, e.ip_origem || "–"),
      el("td", {},
        el("span", { class: `integridade ${e.integridade}` }, e.integridade),
        el("details", {}, el("summary", { class: "mono" }, `${e.hash_sha256.slice(0, 12)}…`),
          el("pre", {}, `sha256 ${e.hash_sha256}\n\n${e.bruto || "(documento ausente no MongoDB)"}`)),
      ),
    ))),
  )));

  blocos.push(el("h3", {}, "Histórico (auditoria)"));
  blocos.push(el("ul", { class: "historico" }, d.historico.map((h) => el("li", {},
    el("span", { class: "quando" }, fmt(h.registrado_em)), " ",
    `${h.status_anterior ? h.status_anterior + " → " : ""}${h.status_novo} · ${h.usuario}`,
    h.comentario ? el("div", {}, h.comentario) : null))));

  painel.replaceChildren(...blocos);
}

function acoes(i, proximos) {
  const caixa = el("div", { class: "acoes" });
  if (!eu.permissoes.includes("incidente.alterar_status")) return caixa;
  if (i.status === "ABERTO" && !i.analista_id) {
    caixa.append(el("button", { class: "botao", onclick: () => executar(`/api/incidentes/${i.id}/assumir`, {}) }, "Assumir"));
  }
  const dono = i.analista_id === eu.id || eu.permissoes.includes("usuario.gerenciar");
  if (dono && proximos.length && i.status !== "ABERTO") {
    const sel = el("select", {}, proximos.map((s) => el("option", { value: s }, s)));
    const txt = el("input", { placeholder: "Comentário (obrigatório)", maxlength: "2000" });
    caixa.append(sel, txt, el("button", { class: "botao", onclick: () =>
      executar(`/api/incidentes/${i.id}/status`, { status_novo: sel.value, comentario: txt.value }) }, "Avançar"));
  }
  return caixa;
}

async function executar(caminho, corpo) {
  try {
    await api(caminho, { method: "POST", body: JSON.stringify(corpo) });
    await atualizar();
  } catch (e) { alert(e.message); }
}

// ---------------------------------------------------------------- início
$("form-login").addEventListener("submit", entrar);
$("sair").addEventListener("click", sair);
$("mostrar-encerrados").addEventListener("change", atualizar);
setInterval(() => atualizar().catch(() => {}), 30000);
iniciar().catch(() => sair());
