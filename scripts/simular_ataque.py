#!/usr/bin/env python3
"""Simula o cenário de Vale Verde contra a API (horário atual, para a regra disparar).

  INGEST_API_KEY=... python3 scripts/simular_ataque.py                # http://127.0.0.1:8000
  INGEST_API_KEY=... python3 scripts/simular_ataque.py http://IP-DA-EC2

O que vai acontecer:
  1. o firewall registra o RDP exposto por NAT e o IDS, uma varredura de SSH;
  2. 37 falhas de logon (4625) do IP 203.0.113.45 contra o SRV-ARQUIVOS;
  3. 5 erros de senha de uma funcionária (ruído, não deve virar incidente);
  4. 1 logon bem-sucedido (4624) do atacante.
Em até 30 s o motor cria o alerta e o incidente aparece no dashboard.
Só usa a biblioteca padrão: roda em qualquer Python 3.9+.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

URL = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
CHAVE = os.environ.get("INGEST_API_KEY") or sys.exit("Defina INGEST_API_KEY (está no .env).")
ORG = 7
ATACANTE = "203.0.113.45"
ALVO = "10.20.0.15"
AUTH = {"tipo": "autenticacao", "produto": "Windows Security", "coletor": "agente-srv-arquivos"}


def xml_windows(evento_id: int, quando: datetime, usuario: str, ip: str, extra: str) -> str:
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<EventID>{evento_id}</EventID><TimeCreated SystemTime='{quando.isoformat()}'/>"
            "<Computer>SRV-ARQUIVOS</Computer></System><EventData>"
            f"<Data Name='TargetUserName'>{usuario}</Data>{extra}"
            f"<Data Name='IpAddress'>{ip}</Data></EventData></Event>")


def logon(evento_id: int, quando: datetime, usuario: str, ip: str, porta: int) -> dict:
    falha = evento_id == 4625
    extra = ("<Data Name='LogonType'>3</Data><Data Name='SubStatus'>0xc000006a</Data>" if falha
             else "<Data Name='LogonType'>10</Data>")
    dados = {"evento_id": evento_id, "usuario_alvo": usuario, "tipo_logon": 3 if falha else 10}
    if falha:
        dados["sub_status"] = "0xc000006a"
    return {
        "organizacao_id": ORG, "fonte": AUTH, "ocorrido_em": quando.isoformat(),
        "severidade": 4 if falha else 8,
        "rede": {"ip_origem": ip, "ip_destino": ALVO, "porta_destino": porta, "protocolo": "tcp"},
        "dados": dados, "bruto": xml_windows(evento_id, quando, usuario, ip, extra),
    }


def montar_cenario() -> list[dict]:
    agora = datetime.now(timezone.utc).replace(microsecond=0)
    inicio = agora - timedelta(minutes=9, seconds=30)
    eventos = [
        {"organizacao_id": ORG, "ativo_id": 3, "ocorrido_em": (inicio - timedelta(minutes=6)).isoformat(),
         "fonte": {"tipo": "ids", "produto": "Suricata", "coletor": "sensor-borda"}, "severidade": 5,
         "rede": {"ip_origem": ATACANTE, "ip_destino": ALVO, "porta_destino": 22, "protocolo": "tcp"},
         "dados": {"assinatura": {"sid": 2001219, "msg": "ET SCAN Potential SSH Scan"}, "acao": "allowed"},
         "bruto": json.dumps({"event_type": "alert", "src_ip": ATACANTE, "dest_ip": ALVO,
                              "dest_port": 22, "alert": {"signature_id": 2001219}})},
        {"organizacao_id": ORG, "ativo_id": 3, "ocorrido_em": (inicio - timedelta(seconds=40)).isoformat(),
         "fonte": {"tipo": "firewall", "produto": "pfSense", "coletor": "fw-borda"}, "severidade": 2,
         "rede": {"ip_origem": ATACANTE, "ip_destino": ALVO, "porta_destino": 3389, "protocolo": "tcp"},
         "dados": {"acao": "pass", "interface": "wan", "regra": "NAT 3389 -> SRV-ARQUIVOS"},
         "bruto": f"filterlog: 12,,,1000000103,em0,match,pass,in,4,0x0,,49,54321,0,DF,6,tcp,60,"
                  f"{ATACANTE},{ALVO},51514,3389,0,S"},
    ]
    for i in range(37):  # força bruta: uma tentativa a cada 15 s
        eventos.append(logon(4625, inicio + timedelta(seconds=15 * i), "administrador", ATACANTE, 3389))
    for i in range(5):   # ruído: funcionária errando a senha
        eventos.append(logon(4625, inicio + timedelta(minutes=1, seconds=5 * i), "joana.silva", "10.20.0.88", 445))
    eventos.append(logon(4624, inicio + timedelta(seconds=15 * 37 + 12), "administrador", ATACANTE, 3389))
    return eventos


def main() -> None:
    corpo = json.dumps({"eventos": montar_cenario()}).encode()
    req = urllib.request.Request(f"{URL}/api/eventos", data=corpo, method="POST",
                                 headers={"Content-Type": "application/json", "X-API-Key": CHAVE})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"{json.load(r)['recebidos']} eventos enviados. O incidente aparece no dashboard em até 30 s.")
    except urllib.error.HTTPError as e:
        sys.exit(f"Erro {e.code}: {e.read().decode()}")


if __name__ == "__main__":
    main()
