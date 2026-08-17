from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str
    APP_VERSION: str
    APP_DESCRIPTION: str

    API_PREFIX: str

    OLLAMA_HOST: str

    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    LOG_LEVEL: str

    # Caspian configuration
    CASPIAN_API_KEY: str
    CASPIAN_BASE_URL: str
    CASPIAN_WEBHOOK_SECRET: str
    CASPIAN_CONNECTION_ID: str

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )


settings = Settings()