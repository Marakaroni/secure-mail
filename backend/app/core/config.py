from pydantic import BaseSettings


class Settings(BaseSettings):
    app_name: str = "secure-mail"
    app_env: str = "development"
    database_url: str = "sqlite:////data/db.sqlite"

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
