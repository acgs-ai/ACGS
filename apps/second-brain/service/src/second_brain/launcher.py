import uvicorn

from second_brain.app import create_app
from second_brain.config import Settings, get_settings


def server_config(settings: Settings) -> uvicorn.Config:
    return uvicorn.Config(
        create_app(settings),
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=False,
        forwarded_allow_ips="",
        access_log=False,
        server_header=False,
    )


def main() -> None:
    uvicorn.Server(server_config(get_settings())).run()


if __name__ == "__main__":
    main()
