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
    # Optional: global BatchNotary.sol for periodic Merkle roots (same RPC/chain as above).
    batch_contract_address: str = ""  # env: BATCH_CONTRACT_ADDRESS

    # Public share links for verify (defaults to JWT secret if empty — set in production)
    public_verify_secret: str = ""
    public_verify_token_hours: int = 168

    # If set, the first registration with this email (case-insensitive) gets `admin` role.
    bootstrap_admin_email: str = ""

    # Optional: set retention_expires_at on new uploads to now + N days (UTC).
    default_retention_days: int | None = None


settings = Settings()
