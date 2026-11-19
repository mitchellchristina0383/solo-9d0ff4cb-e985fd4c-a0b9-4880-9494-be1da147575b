"""Process entry point: run the CONNECT proxy and the web UI together."""

from __future__ import annotations

import asyncio
import contextlib
import logging

import uvicorn

from .config import Settings
from .web import create_app

logger = logging.getLogger("controlled_egress")


async def _serve(settings: Settings, stop_event: asyncio.Event) -> None:
    app = create_app(settings)
    config = uvicorn.Config(
        app,
        host=settings.web_host,
        port=settings.web_port,
        log_level="info",
        access_log=False,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # we own signal handling

    async def watch() -> None:
        await stop_event.wait()
        server.should_exit = True

    watcher = asyncio.create_task(watch())
    try:
        await server.serve()
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = Settings.from_env()

    async def runner() -> None:
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                import signal

                loop.add_signal_handler(getattr(signal, sig), stop_event.set)

        logger.info(
            "CONNECT proxy listening on %s:%s, web UI on http://%s:%s",
            settings.proxy_host,
            settings.proxy_port,
            settings.web_host,
            settings.web_port,
        )
        await _serve(settings, stop_event)

    asyncio.run(runner())


if __name__ == "__main__":
    main()
