"""Ed25519 签名与证明记录的规范化编码。

签名载荷规范(带长度前缀的字段拼接,字段顺序固定):

    b"attest-v1|"
      + u32le(len(artifact_digest)) + artifact_digest
      + u32le(len(issuer))          + issuer
      + u32le(len(parent_digest))  + parent_digest

其中 digest/issuer 按 UTF-8 编码;根证明的 parent_digest 为空串 b""。
公钥/签名采用 base64(标准或 URL-safe 均可),公钥固定 32 字节,签名固定 64 字节。
"""

from __future__ import annotations

import base64
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ATTEST_PREFIX = b"attest-v1|"


def b64decode(value: str) -> bytes:
    """兼容标准 base64 与 base64url,自动补齐 padding。"""
    raw = value.strip().encode("ascii")
    try:
        return base64.b64decode(raw + b"=" * (-len(raw) % 4), validate=True)
    except Exception:
        return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def canonical_message(
    artifact_digest: str,
    issuer: str,
    parent_digest: str | None,
) -> bytes:
    """复现签发端必须签名的字节串。"""
    parts = [ATTEST_PREFIX]
    for field in (artifact_digest, issuer, parent_digest or ""):
        data = field.encode("utf-8")
        parts.append(struct.pack("<I", len(data)))
        parts.append(data)
    return b"".join(parts)


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    raw = b64decode(public_key_b64)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_attestation(
    public_key_b64: str,
    artifact_digest: str,
    issuer: str,
    parent_digest: str | None,
    signature_b64: str,
) -> bool:
    """校验签名;任何解码/校验失败都返回 False(校验逻辑不抛异常)。"""
    try:
        key = load_public_key(public_key_b64)
        sig = b64decode(signature_b64)
        if len(sig) != 64:
            return False
        key.verify(sig, canonical_message(artifact_digest, issuer, parent_digest))
        return True
    except (InvalidSignature, ValueError):
        return False
