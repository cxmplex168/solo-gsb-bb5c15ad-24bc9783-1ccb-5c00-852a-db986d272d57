"""Pydantic 请求 / 响应模型。"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

# digest 允许十六进制及常见摘要形式(如 sha256:...),限制为 URL 安全字符。
_DIGEST_RE = re.compile(r"^[A-Za-z0-9._:/\-]{1,256}$")
_ISSUER_RE = re.compile(r"^[A-Za-z0-9._:/\-]{1,128}$")
_REASON_MAX = 512


def _validate_digest(value: str) -> str:
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError(
            "digest must be 1-256 chars of [A-Za-z0-9._:/-], e.g. a hex sha256"
        )
    return value


class IssuerIn(BaseModel):
    id: str = Field(..., examples=["root-ca", "builder@v1"])
    public_key: str = Field(..., description="Ed25519 公钥,base64(32 字节)")
    trusted_root: bool = False


class IssuerOut(BaseModel):
    id: str
    public_key: str
    trusted_root: bool
    created_at: str


class AttestationIn(BaseModel):
    artifact_digest: str
    issuer: str
    parent_digest: str | None = Field(
        default=None, description="父制品 digest;根证明传 null/空串"
    )
    signature: str = Field(..., description="对规范化载荷的 Ed25519 签名,base64(64 字节)")

    @field_validator("artifact_digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        return _validate_digest(v)

    @field_validator("issuer")
    @classmethod
    def _issuer(cls, v: str) -> str:
        if not _ISSUER_RE.fullmatch(v):
            raise ValueError("issuer must be 1-128 chars of [A-Za-z0-9._:/-]")
        return v

    @field_validator("parent_digest")
    @classmethod
    def _parent(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        return _validate_digest(v)

    @field_validator("signature")
    @classmethod
    def _signature(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("signature is required")
        return v


class AttestationOut(BaseModel):
    artifact_digest: str
    issuer: str
    parent_digest: str | None
    signature: str
    created_at: str


class RevocationIn(BaseModel):
    artifact_digest: str
    reason: str | None = Field(default=None, max_length=_REASON_MAX)

    @field_validator("artifact_digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        return _validate_digest(v)


class RevocationOut(BaseModel):
    artifact_digest: str
    reason: str | None
    revoked_at: str


class ChainEntry(BaseModel):
    artifact_digest: str
    issuer: str
    parent_digest: str | None
    signature: str
    created_at: str


class ForkBranch(BaseModel):
    issuer: str
    parent_digest: str | None
    valid: bool
    fail_reason: str | None
    fail_at: str | None
    path: list[str] | None
    chain: list[ChainEntry] | None = None


class VerifyResult(BaseModel):
    artifact_digest: str
    valid: bool
    fail_reason: str | None = None
    fail_at: str | None = None
    path: list[str] | None = None
    chain: list[ChainEntry] | None = None
    fork_count: int | None = None
    branches: list[ForkBranch] | None = None
    revoked_reason: str | None = None
    revoked_at: str | None = None


class SimpleOk(BaseModel):
    ok: bool = True
    detail: dict[str, Any]
