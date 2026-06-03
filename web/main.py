"""FastAPI application — API routes only. Frontend is served by Netlify."""
import asyncio
import base64
import hashlib
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import aiofiles
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import cleanup, database, mailer
from .models import SessionCreate, TokenCreate

load_dotenv()

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", BASE_URL)
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "2"))
TOKEN_EXPIRY_DAYS = int(os.getenv("TOKEN_EXPIRY_DAYS", "7"))
FILE_EXPIRY_DAYS = int(os.getenv("FILE_EXPIRY_DAYS", "21"))
MAX_ACTIVE_TOKENS = 50

ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "")
if not ALLOWED_ORIGINS_RAW:
    raise RuntimeError("ALLOWED_ORIGINS environment variable is required")
ALLOWED_ORIGINS = ALLOWED_ORIGINS_RAW.split(",")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(
    os.getenv("UPLOAD_DIR", os.path.join(_PROJECT_ROOT, "uploads"))
)

limiter = Limiter(key_func=get_remote_address)


def _public_key_fingerprint(pem: str) -> str:
    """SHA-256 of the DER bytes of a PEM public key, hex-encoded, first 16 chars."""
    b64 = re.sub(r"-----[^-]+-----|[\s]", "", pem)
    if not b64:
        raise ValueError("Empty PEM payload")
    der = base64.b64decode(b64, validate=True)
    return hashlib.sha256(der).hexdigest()[:16]


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    await database.init_db()
    await cleanup.cleanup_expired()
    task = asyncio.create_task(cleanup.cleanup_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, redirect_slashes=False)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if BASE_URL.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["X-Session-Token", "Content-Type", "Accept"],
    expose_headers=["Content-Disposition"],
)

if BASE_URL.startswith("https://"):
    app.add_middleware(HTTPSRedirectMiddleware)


# ── Session dependency ────────────────────────────────────────────────────────

async def _get_session(request: Request) -> dict:
    token = request.headers.get("X-Session-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Session token required")
    session = await database.get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    await database.update_session_last_seen(token)
    return session


# ── Config API ────────────────────────────────────────────────────────────────

@app.get("/api/config")
async def get_config():
    """Public configuration consumed by the static frontend."""
    return {
        "max_file_size_mb": MAX_FILE_SIZE_MB,
        "token_expiry_days": TOKEN_EXPIRY_DAYS,
        "file_expiry_days": FILE_EXPIRY_DAYS,
        "app_version": "2.0.0",
    }


# ── Token API ─────────────────────────────────────────────────────────────────

@app.post("/api/tokens")
@limiter.limit("20/hour")
async def create_token(request: Request, body: TokenCreate):
    try:
        fingerprint = _public_key_fingerprint(body.public_key)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid public key format")
    active = await database.count_active_tokens(fingerprint)
    if active >= MAX_ACTIVE_TOKENS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many active tokens for this key ({MAX_ACTIVE_TOKENS} max)",
        )
    token = await database.create_token(
        public_key=body.public_key,
        public_key_fingerprint=fingerprint,
        researcher_email=body.researcher_email,
        collector_email=body.collector_email,
    )
    # Dev local uses query string (?token=) because no redirect server is running.
    # Production Netlify uses path format (/upload/<id>) handled by netlify.toml redirect.
    _is_local = "localhost" in FRONTEND_URL or "127.0.0.1" in FRONTEND_URL
    upload_url = (
        f"{FRONTEND_URL}/upload.html?token={token['id']}"
        if _is_local
        else f"{FRONTEND_URL}/upload/{token['id']}"
    )
    asyncio.create_task(
        mailer.send_collector_invitation(body.collector_email, upload_url, token["expires_at"])
    )
    return {"token_id": token["id"], "upload_url": upload_url, "expires_at": token["expires_at"]}


@app.get("/api/tokens/{token_id}")
async def get_token_status(token_id: str):
    token = await database.get_token(token_id)
    if not token:
        return {"valid": False, "used": False, "expired": False}
    now = datetime.now(timezone.utc).isoformat()
    expired = token["expires_at"] < now
    used = token["used_at"] is not None
    return {"valid": not expired, "used": used, "expired": expired}


@app.get("/api/tokens/{token_id}/public-key")
async def get_token_public_key(token_id: str):
    token = await database.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token introuvable")
    now = datetime.now(timezone.utc).isoformat()
    if token["expires_at"] < now:
        raise HTTPException(status_code=404, detail="Token expiré")
    return {"public_key": token["public_key"]}


# ── Sessions API ──────────────────────────────────────────────────────────────

@app.post("/api/sessions")
@limiter.limit("20/hour")
async def create_session(request: Request, body: SessionCreate):
    session = await database.create_session(body.public_key_fingerprint)
    return {"session_token": session["token"]}


@app.get("/api/sessions/me")
async def get_session_status(session: dict = Depends(_get_session)):
    return {"valid": True, "fingerprint": session["public_key_fingerprint"]}


# ── Upload API ────────────────────────────────────────────────────────────────

@app.post("/api/upload/{token_id}")
@limiter.limit("10/hour")
async def upload_file(
    request: Request,
    token_id: str,
    file: UploadFile = File(...),
    original_filename: str = Form(""),
):
    token = await database.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token introuvable")

    now = datetime.now(timezone.utc).isoformat()
    if token["expires_at"] < now:
        raise HTTPException(status_code=410, detail="Token expiré")
    if token["used_at"] is not None:
        raise HTTPException(status_code=409, detail="Token déjà utilisé")

    max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413, detail=f"Fichier trop volumineux (max {MAX_FILE_SIZE_MB} Mo)"
        )

    stored_filename = f"{uuid.uuid4()}.enc"
    stored_path = os.path.join(UPLOAD_DIR, stored_filename)
    async with aiofiles.open(stored_path, "wb") as fh:
        await fh.write(data)

    fname = original_filename or file.filename or "fichier"
    file_id = await database.create_uploaded_file(
        token_id=token_id,
        original_filename=fname,
        stored_filename=stored_filename,
        file_size=len(data),
        public_key_fingerprint=token["public_key_fingerprint"],
    )
    await database.mark_token_used(token_id, file_id)

    if token.get("researcher_email"):
        file_record = await database.get_file(file_id)
        assert file_record is not None  # just inserted above
        asyncio.create_task(
            mailer.send_researcher_notification(
                to=token["researcher_email"],
                original_filename=fname,
                uploaded_at=file_record["uploaded_at"],
                expires_at=file_record["expires_at"],
                base_url=FRONTEND_URL,
            )
        )

    return {"success": True}


# ── Files API ─────────────────────────────────────────────────────────────────

@app.get("/api/files")
@limiter.limit("60/hour")
async def list_files(request: Request, session: dict = Depends(_get_session)):
    return await database.get_files_by_fingerprint(session["public_key_fingerprint"])


@app.get("/api/files/{file_id}")
@limiter.limit("30/hour")
async def download_file(request: Request, file_id: str, session: dict = Depends(_get_session)):
    record = await database.get_file(file_id)
    if not record or record["public_key_fingerprint"] != session["public_key_fingerprint"]:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    path = os.path.join(UPLOAD_DIR, record["stored_filename"])
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Fichier introuvable sur le disque")
    fname = (record["original_filename"] or "fichier") + ".enc"
    return FileResponse(path, filename=fname, media_type="application/octet-stream")


@app.delete("/api/files/{file_id}")
@limiter.limit("10/hour")
async def delete_file(request: Request, file_id: str, session: dict = Depends(_get_session)):
    record = await database.get_file(file_id)
    if not record or record["public_key_fingerprint"] != session["public_key_fingerprint"]:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    path = os.path.join(UPLOAD_DIR, record["stored_filename"])
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    await database.delete_file(file_id)
    return {"success": True}
