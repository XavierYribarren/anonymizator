"""Pydantic request/response models."""
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


class TokenCreate(BaseModel):
    public_key: str
    researcher_email: Optional[EmailStr] = None
    collector_email: Optional[EmailStr] = None

    @field_validator("public_key")
    @classmethod
    def check_key_length(cls, v: str) -> str:
        if len(v) > 8192:
            raise ValueError("public_key trop long (max 8192 caractères)")
        return v


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


