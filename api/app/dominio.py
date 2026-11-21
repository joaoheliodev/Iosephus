"""Regras de negócio puras, sem banco: fáceis de testar."""
import hashlib

# Ciclo de vida do incidente (NIST SP 800-61): só anda para frente
STATUS = ["ABERTO", "EM_ANALISE", "CONTIDO", "ERRADICADO", "RECUPERADO", "ENCERRADO"]
SEVERIDADES = ["BAIXA", "MEDIA", "ALTA", "CRITICA"]

MAX_REFERENCIAS_ALERTA = 100  # teto de eventos_ids por alerta (limite de 16 MB do documento)


def sha256(texto: str) -> str:
    """Hash do log bruto, calculado na ingestão: base da cadeia de custódia."""
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def transicao_valida(atual: str, novo: str) -> bool:
    """Avança no ciclo (pode pular etapas, ex.: falso positivo vai direto a ENCERRADO)."""
    if atual not in STATUS or novo not in STATUS:
        return False
    return STATUS.index(novo) > STATUS.index(atual)


def severidade_alerta(severidade_regra: str, ip_em_ioc: bool) -> str:
    """Logon bem-sucedido vindo de IP já conhecido como malicioso é sempre crítico."""
    return "CRITICA" if ip_em_ioc else severidade_regra


def integridade(hash_mysql: str, documento: dict | None) -> str:
    """Compara o hash guardado no MySQL com o log bruto que está no MongoDB agora."""
    if documento is None:
        return "AUSENTE"
    if sha256(documento.get("bruto", "")) != hash_mysql:
        return "ADULTERADA"
    return "INTEGRA"
