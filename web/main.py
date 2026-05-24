"""FastAPI application — routes, middleware, lifespan."""
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
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import cleanup, database, mailer
from .models import TokenCreate

load_dotenv()

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "500"))

# Resolve UPLOAD_DIR to an absolute path.
# Default: <project_root>/uploads/ — derived from this file's location so the
# directory lands in the right place regardless of the working directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(
    os.getenv("UPLOAD_DIR", os.path.join(_PROJECT_ROOT, "uploads"))
)

limiter = Limiter(key_func=get_remote_address)


def _public_key_fingerprint(pem: str) -> str:
    """SHA-256 of the DER bytes of a PEM public key, hex-encoded, first 16 chars.

    Mirrors getFingerprint() in crypto.js:
      pemToBuffer strips headers + whitespace → base64-decode → DER bytes
      crypto.subtle.digest("SHA-256", ...) → hex.slice(0, 16)
    """
    der = base64.b64decode(re.sub(r"-----[^-]+-----|[\s]", "", pem))
    return hashlib.sha256(der).hexdigest()[:16]

_HERE = os.path.dirname(__file__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    await database.init_db()
    await cleanup.cleanup_expired()
    task = asyncio.create_task(cleanup.cleanup_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory=os.path.join(_HERE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' https://unpkg.com; "
        "img-src 'self' data:"
    )
    return response


# ── HTML pages ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def researcher_page(request: Request):
    return templates.TemplateResponse(request=request, name="researcher.html")


@app.get("/upload/{token_id}", response_class=HTMLResponse)
async def upload_page(request: Request, token_id: str):
    return templates.TemplateResponse(
        request=request, name="upload.html", context={"token_id": token_id}
    )


@app.get("/decrypt", response_class=HTMLResponse)
async def decrypt_page(request: Request):
    return templates.TemplateResponse(request=request, name="decrypt.html")


# ── Token API ─────────────────────────────────────────────────────────────────

@app.post("/api/tokens")
@limiter.limit("20/hour")
async def create_token(request: Request, body: TokenCreate):
    fingerprint = _public_key_fingerprint(body.public_key)
    token = await database.create_token(
        public_key=body.public_key,
        public_key_fingerprint=fingerprint,
        researcher_email=body.researcher_email,
        collector_email=body.collector_email,
    )
    upload_url = f"{BASE_URL}/upload/{token['id']}"
    asyncio.create_task(
        mailer.send_collector_invitation(body.collector_email, upload_url, token["expires_at"])
    )
    return {"token_id": token["id"], "upload_url": upload_url, "expires_at": token["expires_at"]}


@app.get("/api/tokens/{token_id}")
async def get_token_status(token_id: str):
    token = await database.get_token(token_id)
    if not token:
        # Always 200 to avoid enumeration
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


# ── Upload API ────────────────────────────────────────────────────────────────

@app.post("/api/upload/{token_id}")
async def upload_file(
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

    data = await file.read()
    max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
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
        asyncio.create_task(
            mailer.send_researcher_notification(
                to=token["researcher_email"],
                original_filename=fname,
                uploaded_at=file_record["uploaded_at"],
                expires_at=file_record["expires_at"],
                base_url=BASE_URL,
            )
        )

    return {"success": True}


# ── Files API ─────────────────────────────────────────────────────────────────

@app.get("/api/files")
async def list_files(fingerprint: str):
    return await database.get_files_by_fingerprint(fingerprint)


@app.get("/api/files/{file_id}")
async def download_file(file_id: str):
    record = await database.get_file(file_id)
    if not record:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    path = os.path.join(UPLOAD_DIR, record["stored_filename"])
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Fichier introuvable sur le disque")
    fname = (record["original_filename"] or "fichier") + ".enc"
    return FileResponse(path, filename=fname, media_type="application/octet-stream")


@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str):
    record = await database.get_file(file_id)
    if not record:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    path = os.path.join(UPLOAD_DIR, record["stored_filename"])
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    await database.delete_file(file_id)
    return {"success": True}
