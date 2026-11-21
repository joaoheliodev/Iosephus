from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuração lida de variáveis de ambiente (ou de um arquivo .env)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mysql_url: str
    mongo_url: str
    mongo_db: str = "iosephus"

    ingest_api_key: str          # chave dos coletores (header X-API-Key)
    jwt_secret: str              # assina o token de login do dashboard
    jwt_horas: int = 8

    servico_usuario_id: int = 2  # usuário SERVICO que assina promoções e evidências
    correlacao_intervalo_s: int = 30
    reconciliacao_intervalo_s: int = 300
    worker_ativo: bool = True    # desligado nos testes


@lru_cache
def settings() -> Settings:
    return Settings()
