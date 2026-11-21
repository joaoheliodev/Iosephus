from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SEGREDO = 32  # gerar_env.sh e a EC2 geram 64 caracteres hex


def interpretar_chaves(texto: str) -> dict[str, int]:
    """INGEST_API_KEYS="7:chave,8:outra" -> {chave: organizacao_id}. Mensagens nunca citam a chave."""
    chaves: dict[str, int] = {}
    for item in filter(None, (p.strip() for p in texto.split(","))):
        org, separador, chave = item.partition(":")
        try:
            org_id = int(org)
        except ValueError:
            org_id = 0
        if not separador or org_id <= 0:
            raise ValueError("INGEST_API_KEYS: use organizacao_id:chave, separados por vírgula")
        chave = chave.strip()
        if len(chave) < MIN_SEGREDO:
            raise ValueError(f"INGEST_API_KEYS: chave da organização {org_id} "
                             f"com menos de {MIN_SEGREDO} caracteres")
        if chave in chaves:
            raise ValueError("INGEST_API_KEYS: a mesma chave aparece duas vezes")
        chaves[chave] = org_id
    return chaves


class Settings(BaseSettings):
    """Configuração lida de variáveis de ambiente (ou de um arquivo .env)."""

    # hide_input_in_errors: um erro de validação não pode imprimir segredo no log
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    mysql_url: str
    mongo_url: str
    mongo_db: str = "iosephus"

    # Segredo vazio ou curto derruba a API na subida: chave vazia aceitaria coletor
    # sem X-API-Key, e JWT_SECRET vazio deixaria qualquer um forjar o token de login.
    ingest_api_key: str = Field(min_length=MIN_SEGREDO)  # chave do provedor: vale para qualquer organização
    ingest_api_keys: str = ""    # chaves presas a um cliente: "7:chave,8:outra" (é a que vai para o cliente)
    jwt_secret: str = Field(min_length=MIN_SEGREDO)      # assina o token de login do dashboard
    jwt_horas: int = Field(default=8, ge=1, le=24)

    servico_usuario_id: int = 2  # usuário SERVICO que assina promoções e evidências
    correlacao_intervalo_s: int = 30
    reconciliacao_intervalo_s: int = 300
    worker_ativo: bool = True    # desligado nos testes

    # Login: força bruta e exaustão de memória (cada Argon2 usa ~64 MB de RAM)
    login_janela_s: int = 900
    login_falhas_por_conta: int = 5    # mesmo IP + mesmo e-mail
    login_falhas_por_ip: int = 20      # mesmo IP, qualquer e-mail
    argon2_simultaneos: int = Field(default=4, ge=1)

    # Tamanho máximo do corpo das requisições
    max_corpo_bytes: int = 64 * 1024
    max_corpo_ingestao_bytes: int = 10 * 1024 * 1024

    @field_validator("ingest_api_keys")
    @classmethod
    def _formato_das_chaves(cls, v: str) -> str:
        interpretar_chaves(v)
        return v

    @model_validator(mode="after")
    def _chaves_distintas(self) -> "Settings":
        if self.ingest_api_key in interpretar_chaves(self.ingest_api_keys):
            raise ValueError("INGEST_API_KEYS não pode repetir a INGEST_API_KEY do provedor")
        return self

    def chaves_por_organizacao(self) -> dict[str, int]:
        return interpretar_chaves(self.ingest_api_keys)


@lru_cache
def settings() -> Settings:
    return Settings()
