"""Pydantic request/response models."""
from typing import Optional

from pydantic import BaseModel


class TokenCreate(BaseModel):
    public_key: str
    researcher_email: Optional[str] = None
    collector_email: str


class TokenResponse(BaseModel):
    token_id: str
    upload_url: str
    expires_at: str


class TokenStatus(BaseModel):
    valid: bool
    used: bool
    expired: bool


class FileInfo(BaseModel):
    file_id: str
    original_filename: Optional[str] = None
    uploaded_at: str
    file_size: Optional[int] = None
    expires_at: str
