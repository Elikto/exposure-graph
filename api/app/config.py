from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ExposureGraph"
    data_dir: str = "/data"

    flowsint_base_url: str = "http://host.docker.internal:5001"
    flowsint_api_token: str = ""
    flowsint_sketch_id: str = ""

    hibp_api_key: str = ""
    vt_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""

    enable_gravatar: bool = True
    enable_rdap: bool = True
    enable_crtsh: bool = True
    enable_urlscan: bool = True

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "exposure.db"


settings = Settings()
