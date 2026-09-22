#!/usr/bin/env python3
"""生成 Ed25519 密钥对。

用法:
    python scripts/keygen.py issuer-id
输出 JSON:{"id", "public_key"(base64), "private_key"(base64, 妥善保管)}
"""

import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def generate(issuer_id: str) -> dict[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "id": issuer_id,
        "public_key": base64.b64encode(pub_raw).decode(),
        "private_key": base64.b64encode(priv_raw).decode(),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python scripts/keygen.py <issuer-id>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(generate(sys.argv[1]), indent=2, ensure_ascii=False))
