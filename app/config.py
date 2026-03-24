from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/dms"
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24

    upload_dir: str = "./uploads"

    # Blockchain (leave empty to skip on-chain notarization in development)
    eth_rpc_url: str = ""
    private_key: str = ""
    contract_address: str = ""
    chain_id: int = 1


settings = Settings()
