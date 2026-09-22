#!/usr/bin/env python3
"""端到端演示:注册签发者、写入证明链、校验,并制造撤销/分叉/断链场景。

仅依赖标准库 + cryptography(与服务端同一套规范化签名规则)。

用法(服务已启动):
    python scripts/demo.py
环境变量:
    API_BASE  默认 http://127.0.0.1:8000
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from app.crypto import canonical_message

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000").rstrip("/")

ROOT_DIGEST = "aa" * 32          # 受信根签发的根制品
APP_DIGEST = "bb" * 32           # 挂在根下的应用制品(分叉点)
ALT_ROOT_DIGEST = "cc" * 32      # 非受信根签发的"根制品"
ORPHAN_DIGEST = "dd" * 32        # 父 digest 不存在的制品
MISSING_DIGEST = "ee" * 32       # 不存在的父
UNKNOWN_DIGEST = "ff" * 32       # 完全没有证明的制品


def api(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API_BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def new_key() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv, pub


def sign(priv: Ed25519PrivateKey, artifact: str, issuer: str,
         parent: str | None) -> str:
    msg = canonical_message(artifact, issuer, parent)
    return base64.b64encode(priv.sign(msg)).decode()


def show(title: str, expected: str, status: int, payload: dict) -> bool:
    reason = None if payload.get("valid") else payload.get("fail_reason")
    label = "(success)" if reason is None else reason
    ok = label == expected
    mark = "PASS" if ok else "FAIL"
    print(f"\n[{mark}] {title}")
    print(f"    HTTP {status} | expect={expected} | got={label}")
    print("    " + json.dumps(payload, ensure_ascii=False, indent=2).replace("\n", "\n    "))
    return ok


def main() -> int:
    root_key, root_pub = new_key()
    builder_key, builder_pub = new_key()
    auditor_key, auditor_pub = new_key()

    # 1) 注册签发者:root 为受信根,builder/auditor 为普通签发者
    api("POST", "/api/v1/issuers",
        {"id": "root", "public_key": root_pub, "trusted_root": True})
    api("POST", "/api/v1/issuers",
        {"id": "builder", "public_key": builder_pub, "trusted_root": False})
    api("POST", "/api/v1/issuers",
        {"id": "auditor", "public_key": auditor_pub, "trusted_root": False})

    results = []

    # 2) 正常链 root -> app
    api("POST", "/api/v1/attestations", {
        "artifact_digest": ROOT_DIGEST, "issuer": "root",
        "parent_digest": None,
        "signature": sign(root_key, ROOT_DIGEST, "root", None),
    })
    api("POST", "/api/v1/attestations", {
        "artifact_digest": APP_DIGEST, "issuer": "builder",
        "parent_digest": ROOT_DIGEST,
        "signature": sign(builder_key, APP_DIGEST, "builder", ROOT_DIGEST),
    })
    st, res = api("GET", f"/api/v1/artifacts/{APP_DIGEST}/verify")
    results.append(show("正常链校验(应得到有序信任链)", "(success)", st, res))
    if res.get("valid"):
        order = [e["artifact_digest"] for e in res["chain"]]
        print(f"    chain order: {order}")

    # 3) 分叉:auditor 也给 app 出证明,但挂到一个非受信根上
    api("POST", "/api/v1/attestations", {
        "artifact_digest": ALT_ROOT_DIGEST, "issuer": "auditor",
        "parent_digest": None,
        "signature": sign(auditor_key, ALT_ROOT_DIGEST, "auditor", None),
    })
    api("POST", "/api/v1/attestations", {
        "artifact_digest": APP_DIGEST, "issuer": "auditor",
        "parent_digest": ALT_ROOT_DIGEST,
        "signature": sign(auditor_key, APP_DIGEST, "auditor", ALT_ROOT_DIGEST),
    })
    st, res = api("GET", f"/api/v1/artifacts/{APP_DIGEST}/verify")
    results.append(show("同一制品分叉(逐分支定位失败点)", "FORK", st, res))

    # 4) 非受信根单独校验
    st, res = api("GET", f"/api/v1/artifacts/{ALT_ROOT_DIGEST}/verify")
    results.append(show("根证明来自非受信签发者", "UNTRUSTED_ROOT", st, res))

    # 5) 断链:父 digest 无任何证明
    api("POST", "/api/v1/attestations", {
        "artifact_digest": ORPHAN_DIGEST, "issuer": "builder",
        "parent_digest": MISSING_DIGEST,
        "signature": sign(builder_key, ORPHAN_DIGEST, "builder", MISSING_DIGEST),
    })
    st, res = api("GET", f"/api/v1/artifacts/{ORPHAN_DIGEST}/verify")
    results.append(show("父制品缺失(返回完整失败路径)", "MISSING_PARENT", st, res))

    # 6) 查无证明
    st, res = api("GET", f"/api/v1/artifacts/{UNKNOWN_DIGEST}/verify")
    results.append(show("制品没有任何证明", "NO_ATTESTATION", st, res))

    # 7) 撤销根祖先:分叉仍然报告 FORK,但 builder 分支透传 REVOKED 定位
    st, res = api("POST", "/api/v1/revocations", {
        "artifact_digest": ROOT_DIGEST,
        "reason": "CVE-2026-0001 root image compromised",
    })
    print(f"\n[----] 撤销 {ROOT_DIGEST[:12]}... -> HTTP {st}")
    st, res = api("GET", f"/api/v1/artifacts/{APP_DIGEST}/verify")
    results.append(show("撤销祖先(分叉内 builder 分支定位到撤销点)", "FORK", st, res))
    for b in res.get("branches", []):
        if b["issuer"] == "builder":
            results.append(b["fail_reason"] == "REVOKED")
            print(f"    builder 分支: fail={b['fail_reason']} "
                  f"at={str(b['fail_at'])[:12]}... path_len={len(b['path'] or [])}")

    print("\n" + "=" * 60)
    print("全部断言通过 ✅" if all(results) else "存在失败断言 ❌")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
