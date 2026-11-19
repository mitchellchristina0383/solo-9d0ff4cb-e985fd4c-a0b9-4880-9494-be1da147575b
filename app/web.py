"""HTTP API and the operator web page."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings
from .probe import Probe
from .proxy import ConnectProxy
from .rules import MAX_RULES, RuleValidationError, validate_rules
from .storage import Storage

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class RulesPayload(BaseModel):
    rules: list[dict[str, Any]]
    note: str = Field(default="", max_length=200)


class ProbePayload(BaseModel):
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    storage = Storage(settings.db_path)
    proxy = ConnectProxy(settings, storage)
    probe = Probe(settings, storage)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await storage.open()
        await storage.seed_if_empty(settings.bootstrap_rules)
        await proxy.start()
        try:
            yield
        finally:
            await proxy.stop()
            await storage.close()

    app = FastAPI(
        title="Controlled Egress Proxy",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.storage = storage
    app.state.proxy = proxy
    app.state.probe = probe

    MAX_API_BODY = 512 * 1024

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                if int(length) > MAX_API_BODY:
                    return JSONResponse(
                        status_code=413,
                        content={"ok": False, "message": "request body too large"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "message": "invalid Content-Length"},
                )
        return await call_next(request)

    # -- pages -------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/static/{name}", include_in_schema=False)
    async def static_file(name: str):
        if "/" in name or "\\" in name or name.startswith("."):
            raise HTTPException(status_code=404)
        path = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404)
        return FileResponse(path)

    # -- health ------------------------------------------------------------

    @app.get("/api/health")
    async def health(request: Request) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "proxy_port": settings.proxy_port,
            "active_tunnels": proxy.active_tunnel_count(),
        }

    @app.get("/api/config")
    async def config() -> dict[str, Any]:
        return {
            "proxy_port": settings.proxy_port,
            "host_listen": settings.proxy_host,
            "demo_host": settings.demo_host,
            "demo_port": settings.demo_port,
            "idle_timeout": settings.idle_timeout,
            "connect_timeout": settings.connect_timeout,
            "dns_timeout": settings.dns_timeout,
            "max_rules": MAX_RULES,
        }

    # -- rules -------------------------------------------------------------

    @app.get("/api/rules")
    async def get_rules() -> dict[str, Any]:
        snapshot = await storage.latest_snapshot()
        if snapshot is None:
            return {"revision": 0, "created_at": None, "note": "", "rules": []}
        return snapshot.to_api()

    @app.post("/api/rules/validate")
    async def validate_rules_endpoint(payload: RulesPayload) -> dict[str, Any]:
        try:
            normalized = validate_rules(payload.rules)
        except RuleValidationError as exc:
            return JSONResponse(
                status_code=422,
                content={"ok": False, "errors": exc.problems},
            )
        return {"ok": True, "rules": normalized}

    @app.put("/api/rules")
    async def put_rules(payload: RulesPayload) -> JSONResponse:
        try:
            snapshot, previous = await storage.commit_rules(payload.rules, note=payload.note.strip())
        except RuleValidationError as exc:
            return JSONResponse(
                status_code=422,
                content={
                    "ok": False,
                    "errors": exc.problems,
                    "message": "rules were rejected and nothing was changed",
                },
            )
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "previous_revision": previous,
                "revision": snapshot.revision,
                "rules": snapshot.to_api()["rules"],
                "created_at": snapshot.created_at,
                "note": snapshot.note,
            },
        )

    @app.get("/api/rules/revisions")
    async def revisions(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
        return {"items": await storage.list_revisions(limit)}

    @app.get("/api/rules/revisions/{revision}")
    async def revision_detail(revision: int) -> dict[str, Any]:
        for item in await storage.list_revisions(200):
            if item["revision"] == revision:
                return item
        raise HTTPException(status_code=404, detail="revision not found")

    # -- admissions --------------------------------------------------------

    @app.get("/api/admissions")
    async def admissions(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        decision: str | None = Query(default=None, pattern="^(allowed|denied|error)$"),
        kind: str | None = Query(default=None, pattern="^(connect|probe)$"),
        q: str | None = Query(default=None, max_length=200),
    ) -> dict[str, Any]:
        return await storage.list_admissions(
            limit=limit, offset=offset, decision=decision, kind=kind, query=q
        )

    @app.get("/api/admissions/summary")
    async def admissions_summary() -> dict[str, Any]:
        summary = await storage.summary()
        summary["active_tunnels"] = proxy.active_tunnel_count()
        return summary

    @app.get("/api/admissions/{admission_id}")
    async def admission_detail(admission_id: int) -> dict[str, Any]:
        row = await storage.get_admission(admission_id)
        if row is None:
            raise HTTPException(status_code=404, detail="admission not found")
        return row

    # -- test connect ------------------------------------------------------

    @app.post("/api/probe")
    async def run_probe(payload: ProbePayload) -> dict[str, Any]:
        host = payload.host if payload.host is not None else settings.demo_host
        port = payload.port if payload.port is not None else settings.demo_port
        if not isinstance(host, str) or not host.strip():
            raise HTTPException(status_code=422, detail="host is required")
        result = await probe.run(host.strip(), port)
        return result.to_api()

    return app
