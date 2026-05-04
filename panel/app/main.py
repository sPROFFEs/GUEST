"""FastAPI entry point."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from app import auth, config, db as dbmod
from app.routers import account, acl, auth_views, hosts, lan_egress, peers, settings, views


_MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


def create_app() -> FastAPI:
    cfg = config.load()

    # Apply pending migrations idempotently on every boot so a panel rsync +
    # restart is enough to pick up new tables — no full re-run of module 40.
    dbmod.init_db(cfg.db_path, _MIGRATIONS)

    app = FastAPI(title="Gateway Panel", docs_url=None, redoc_url=None)
    app.state.cfg = cfg
    app.state.db = dbmod.connect(cfg.db_path)

    # Sessions
    secret = auth.get_or_create_session_secret(app.state.db)
    app.state.sessions = auth.SessionManager(secret)
    app.state.last_error = None

    # Static + routers
    static_dir = Path(__file__).resolve().parent / "web" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(auth_views.router)
    app.include_router(views.router)
    app.include_router(peers.router)
    app.include_router(acl.router)
    app.include_router(hosts.router)
    app.include_router(settings.router)
    app.include_router(account.router)
    app.include_router(lan_egress.router)

    @app.exception_handler(HTTPException)
    async def _401(request: Request, exc: HTTPException):
        if exc.status_code == 401 and not request.url.path.startswith("/api/"):
            return RedirectResponse(url="/login", status_code=303)
        raise exc

    return app


app = create_app()
