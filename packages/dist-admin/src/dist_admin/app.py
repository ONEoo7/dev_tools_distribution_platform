"""The operator web application.

Server-rendered Jinja with no JavaScript at all. PLAN.md 8.3 asks for a strict
CSP and for every stored string to render as untrusted text; the cheapest way
to mean it is to have no script to allow, so the policy this app sends is
`default-src 'none'` with `style-src 'self'` and nothing else. Jinja
autoescaping is on and no template uses `|safe`.

Every mutating route is a POST carrying a per-session CSRF token, and answers
with a redirect so that a reload does not resubmit.

What this application deliberately cannot do is at the top of `__init__.py`.
The short version: it writes rows, and it queues jobs for a service that has a
credential it does not.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from importlib import resources
from typing import Any

import jinja2
from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, PackageLoader, select_autoescape

from dist_admin import auth
from dist_admin.config import Settings
from dist_admin.forms import (
    DEFAULT_API_BASE,
    FormError,
    source_edit_from_form,
    source_from_form,
)
from dist_core.buildinfo import build_ref, build_time, source_digest
from dist_registry import db, store
from dist_registry.models import Forge, JobKind, SourceStatus
from dist_registry.store import Conn, StoreError

CSP = (
    "default-src 'none'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)

_env = Environment(
    loader=PackageLoader("dist_admin", "templates"),
    autoescape=select_autoescape(["html"]),
    # A typo in a template name is a blank cell in an operations UI, which is
    # indistinguishable from a genuinely empty value. Raise instead.
    undefined=jinja2.StrictUndefined,
)


class Operator:
    """Who is making the request, and the CSRF token their session carries."""

    def __init__(self, username: str, csrf: str) -> None:
        self.username = username
        self.csrf = csrf


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = db.pool(resolved.database_url)
        with pool.connection() as conn:
            db.migrate(conn)
            _bootstrap_operator(conn, resolved)
            store.purge_expired_sessions(conn)
        app.state.pool = pool
        try:
            yield
        finally:
            pool.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = resolved
    _register_routes(app)
    return app


def _bootstrap_operator(conn: Conn, settings: Settings) -> None:
    """Create the first operator, once, if a password was supplied.

    Guarded on there being no operators rather than on the username being
    absent, so that a bootstrap variable left set in a compose file cannot
    quietly reset a password that someone has since changed.
    """
    if settings.bootstrap_password is None or store.operator_count(conn) > 0:
        return
    digest, salt = auth.hash_password(settings.bootstrap_password)
    store.put_operator(conn, "admin", digest, salt)
    store.audit(conn, actor="system", action="operator.bootstrap", detail={"username": "admin"})


# ------------------------------------------------------------- dependencies


def _pool(request: Request) -> db.Pool:
    pool: db.Pool = request.app.state.pool
    return pool


def get_conn(request: Request) -> Iterator[Conn]:
    with _pool(request).connection() as conn:
        yield conn


def current_operator(request: Request, conn: Conn = Depends(get_conn)) -> Operator | None:
    session = auth.session_for(conn, request.cookies.get(auth.SESSION_COOKIE))
    if session is None:
        return None
    return Operator(str(session["username"]), str(session["csrf_token"]))


# ----------------------------------------------------------------- helpers


def _render(template: str, **context: Any) -> HTMLResponse:
    body = _env.get_template(template).render(**context)
    response = HTMLResponse(body)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    # This page lists which repositories the system trusts. It is not something
    # an intermediary or a shared browser cache should keep.
    response.headers["Cache-Control"] = "no-store"
    return response


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _login_required() -> RedirectResponse:
    return _redirect("/login")


def _check_csrf(operator: Operator, supplied: str | None) -> None:
    if not auth.csrf_ok(operator.csrf, supplied):
        raise FormError("this form expired; reload the page and try again")


def _register_routes(app: FastAPI) -> None:
    settings: Settings = app.state.settings

    @app.get("/healthz")
    def healthz() -> Response:
        # Carries the build identity so "which code is this container running"
        # is answerable without shelling into it or reading back through the
        # log. Unauthenticated on purpose, like the rest of this endpoint: it
        # names a revision, which tells an attacker nothing they could not get
        # from the repository, and the alternative is an operator who cannot
        # check it during the incident where it matters.
        return Response(
            f"ok\nsource {source_digest()}\nbuilt {build_ref()} {build_time()}\n",
            media_type="text/plain",
        )

    @app.get("/static/app.css")
    def stylesheet() -> Response:
        css = resources.files("dist_admin").joinpath("static/app.css").read_text(encoding="utf-8")
        return Response(css, media_type="text/css", headers={"Cache-Control": "max-age=300"})

    # ------------------------------------------------------------- session

    @app.get("/login")
    def login_form(operator: Operator | None = Depends(current_operator)) -> Response:
        if operator is not None:
            return _redirect("/sources")
        return _render("login.html", error=None)

    @app.post("/login")
    def login(
        response: Response,
        conn: Conn = Depends(get_conn),
        username: str = Form(...),
        password: str = Form(...),
    ) -> Response:
        if not auth.authenticate(conn, username, password):
            store.audit(conn, actor=username, action="login.failed", detail={"outcome": "rejected"})
            # One message for both "no such operator" and "wrong password".
            return _render("login.html", error="Incorrect username or password.")

        token, _ = auth.begin_session(conn, username)
        store.audit(conn, actor=username, action="login.succeeded")
        out = _redirect("/sources")
        out.set_cookie(
            auth.SESSION_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=settings.secure_cookie,
            max_age=int(auth.SESSION_LIFETIME.total_seconds()),
            path="/",
        )
        return out

    @app.post("/logout")
    def logout(request: Request, conn: Conn = Depends(get_conn)) -> Response:
        auth.end_session(conn, request.cookies.get(auth.SESSION_COOKIE))
        out = _redirect("/login")
        out.delete_cookie(auth.SESSION_COOKIE, path="/")
        return out

    # ------------------------------------------------------------- sources

    @app.get("/")
    def index() -> Response:
        return _redirect("/sources")

    @app.get("/sources")
    def sources(
        conn: Conn = Depends(get_conn), operator: Operator | None = Depends(current_operator)
    ) -> Response:
        if operator is None:
            return _login_required()
        return _render(
            "sources.html",
            operator=operator,
            sources=store.list_sources(conn),
            status=SourceStatus,
        )

    @app.get("/sources/new")
    def new_source(
        forge: str = "github", operator: Operator | None = Depends(current_operator)
    ) -> Response:
        if operator is None:
            return _login_required()
        selected = Forge(forge) if forge in {f.value for f in Forge} else Forge.GITHUB
        return _render(
            "source_new.html",
            operator=operator,
            forge=selected,
            forges=list(Forge),
            api_base=DEFAULT_API_BASE[selected],
            error=None,
            values={},
        )

    @app.post("/sources")
    async def create_source(
        request: Request,
        conn: Conn = Depends(get_conn),
        operator: Operator | None = Depends(current_operator),
    ) -> Response:
        if operator is None:
            return _login_required()
        data = dict((await request.form()).items())
        forge_value = str(data.get("forge", "github"))
        selected = Forge(forge_value) if forge_value in {f.value for f in Forge} else Forge.GITHUB

        try:
            _check_csrf(operator, str(data.get("csrf", "")))
            source = source_from_form(data, actor=operator.username)
            created = store.add_source(conn, source)
        except (FormError, StoreError) as exc:
            return _render(
                "source_new.html",
                operator=operator,
                forge=selected,
                forges=list(Forge),
                api_base=str(data.get("api_base") or DEFAULT_API_BASE[selected]),
                error=str(exc),
                values=data,
            )

        store.audit(
            conn,
            actor=operator.username,
            action="source.added",
            source_id=created.id,
            detail={
                "app_id": created.app_id,
                "forge": str(created.forge),
                "project": created.project,
                "critical": created.critical,
            },
        )
        # Validation is the worker's to do: it holds the forge credential and
        # this process does not.
        store.enqueue(conn, created.id, JobKind.VALIDATE, requested_by=operator.username)
        store.set_status(conn, created.id, SourceStatus.VALIDATING)
        return _redirect(f"/sources/{created.id}")

    @app.get("/sources/{source_id}")
    def source_detail(
        source_id: uuid.UUID,
        conn: Conn = Depends(get_conn),
        operator: Operator | None = Depends(current_operator),
    ) -> Response:
        if operator is None:
            return _login_required()
        source = store.get_source(conn, source_id)
        if source is None:
            return _render("not_found.html", operator=operator)
        return _render(
            "source_detail.html",
            operator=operator,
            source=source,
            jobs=store.recent_jobs(conn, source_id),
            status=SourceStatus,
        )

    @app.get("/sources/{source_id}/edit")
    def edit_source_form(
        source_id: uuid.UUID,
        conn: Conn = Depends(get_conn),
        operator: Operator | None = Depends(current_operator),
    ) -> Response:
        if operator is None:
            return _login_required()
        source = store.get_source(conn, source_id)
        if source is None:
            return _render("not_found.html", operator=operator)
        return _render("source_edit.html", operator=operator, source=source, error=None)

    @app.post("/sources/{source_id}/edit")
    async def edit_source(
        source_id: uuid.UUID,
        request: Request,
        conn: Conn = Depends(get_conn),
        operator: Operator | None = Depends(current_operator),
    ) -> Response:
        if operator is None:
            return _login_required()
        source = store.get_source(conn, source_id)
        if source is None:
            return _render("not_found.html", operator=operator)

        data = dict(await request.form())
        try:
            _check_csrf(operator, str(data.get("csrf", "")))
            changed = source_edit_from_form(data, source)
        except FormError as exc:
            return _render(
                "source_edit.html", operator=operator, source=source, error=str(exc)
            )

        if not changed:
            return _redirect(f"/sources/{source_id}")

        try:
            store.update_source(conn, source_id, changed)
        except StoreError as exc:
            return _render(
                "source_edit.html", operator=operator, source=source, error=str(exc)
            )

        # The values, not just the field names: this is the record of what a
        # release will be built from next time, and "somebody edited the source"
        # is not something anyone can audit.
        store.audit(
            conn,
            actor=operator.username,
            action="source.edited",
            source_id=source_id,
            detail={k: str(v) for k, v in changed.items()},
        )
        return _redirect(f"/sources/{source_id}")

    @app.post("/sources/{source_id}/{action}")
    def source_action(
        source_id: uuid.UUID,
        action: str,
        conn: Conn = Depends(get_conn),
        operator: Operator | None = Depends(current_operator),
        csrf: str = Form(""),
    ) -> Response:
        if operator is None:
            return _login_required()
        source = store.get_source(conn, source_id)
        if source is None:
            return _render("not_found.html", operator=operator)
        try:
            _check_csrf(operator, csrf)
        except FormError:
            return _redirect(f"/sources/{source_id}")

        recorded = f"source.{action}"

        if action == "validate":
            store.enqueue(conn, source_id, JobKind.VALIDATE, requested_by=operator.username)
            store.set_status(conn, source_id, SourceStatus.VALIDATING)
        elif action == "poll":
            # Refused rather than queued for a source with no delegation: the
            # artifacts could not be promoted, and quarantine would fill with
            # things nobody can sign. The template disables the control; this
            # is what enforces it, since a disabled attribute is a suggestion.
            #
            # The refusal is audited *as a refusal*. Recording `source.poll`
            # for a request that queued nothing would make the log say an
            # operator polled a source that was never polled.
            if source.pollable:
                store.enqueue(conn, source_id, JobKind.POLL, requested_by=operator.username)
            else:
                recorded = "source.poll.refused"
        elif action == "pause":
            store.set_status(conn, source_id, SourceStatus.PAUSED)
        elif action == "delete":
            store.delete_source(conn, source_id)
            store.audit(
                conn,
                actor=operator.username,
                action="source.deleted",
                detail={"app_id": source.app_id},
            )
            return _redirect("/sources")
        else:
            return _redirect(f"/sources/{source_id}")

        store.audit(conn, actor=operator.username, action=recorded, source_id=source_id)
        return _redirect(f"/sources/{source_id}")

    @app.get("/audit")
    def audit_log(
        conn: Conn = Depends(get_conn), operator: Operator | None = Depends(current_operator)
    ) -> Response:
        if operator is None:
            return _login_required()
        return _render("audit.html", operator=operator, events=store.recent_audit(conn))
