"""信任链递归校验器。

校验规则:
1. 制品被撤销 -> 失败 REVOKED,携带撤销原因。
2. 制品查无证明 -> 失败 NO_ATTESTATION。
3. 同一制品存在多条证明 -> 分叉 FORK:逐条追溯每条分支,
   分支结果(fail_reason/path/chain/valid)随响应返回,便于定位。
4. 签发者未注册 -> UNKNOWN_ISSUER;根证明签发者非受信根 -> UNTRUSTED_ROOT。
5. Ed25519 签名与规范化载荷不符 -> INVALID_SIGNATURE。
6. 父 digest 没有任何证明 -> MISSING_PARENT;父链上出现撤销/环等 -> 透传失败点。
7. 环(A->B->A)-> CYCLE;链长超过 MAX_CHAIN_DEPTH -> CHAIN_TOO_DEEP。

成功时返回从被校验制品到根的有序信任链(索引 0 为被校验制品,最后为根)。
"""

from __future__ import annotations

from typing import Any

from . import db
from .crypto import verify_attestation

MAX_CHAIN_DEPTH = 64


def _att(row: Any) -> dict[str, Any]:
    return {
        "artifact_digest": row["artifact_digest"],
        "issuer": row["issuer"],
        "parent_digest": row["parent_digest"],
        "signature": row["signature"],
        "created_at": row["created_at"],
    }


def _revocation(digest: str) -> Any:
    return db.query_one(
        "SELECT reason, revoked_at FROM revocations WHERE artifact_digest = ?",
        (digest,),
    )


def _attestations(digest: str) -> list[Any]:
    return db.query_all(
        "SELECT * FROM attestations WHERE artifact_digest = ? ORDER BY id",
        (digest,),
    )


def _issuer(issuer_id: str) -> Any:
    return db.query_one(
        "SELECT * FROM issuers WHERE id = ?",
        (issuer_id,),
    )


def _failure(reason: str, digest: str, path: list[str], **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "valid": False,
        "fail_reason": reason,
        "fail_at": digest,
        "path": path,
    }
    result.update(extra)
    return result


def _success(chain: list[dict[str, Any]]) -> dict[str, Any]:
    return {"valid": True, "chain": chain}


def verify_artifact(digest: str) -> dict[str, Any]:
    """制品校验入口;无论成功失败都返回结构化结果(HTTP 固定 200)。"""
    result = _verify_node(digest, on_path=frozenset(), depth=0)
    result["artifact_digest"] = digest
    return result


def _verify_node(
    digest: str,
    on_path: frozenset[str],
    depth: int,
) -> dict[str, Any]:
    path = [digest]
    if digest in on_path:
        return _failure("CYCLE", digest, path)
    if depth > MAX_CHAIN_DEPTH:
        return _failure("CHAIN_TOO_DEEP", digest, path)

    rev = _revocation(digest)
    if rev is not None:
        return _failure(
            "REVOKED",
            digest,
            path,
            revoked_reason=rev["reason"],
            revoked_at=rev["revoked_at"],
        )

    rows = _attestations(digest)
    if not rows:
        return _failure("NO_ATTESTATION", digest, path)

    if len(rows) > 1:
        return _fork_result(rows, on_path | {digest}, depth, path)

    return _check_attestation(rows[0], on_path | {digest}, depth, path)


def _fork_result(
    rows: list[Any],
    on_path: frozenset[str],
    depth: int,
    path: list[str],
) -> dict[str, Any]:
    branches: list[dict[str, Any]] = []
    for row in rows:
        branch = _check_attestation(row, on_path, depth, path)
        branch_summary: dict[str, Any] = {
            "issuer": row["issuer"],
            "parent_digest": row["parent_digest"],
            "valid": bool(branch["valid"]),
            "fail_reason": None if branch["valid"] else branch["fail_reason"],
            "fail_at": None if branch["valid"] else branch["fail_at"],
            "path": None if branch["valid"] else branch["path"],
        }
        if branch["valid"]:
            branch_summary["chain"] = branch["chain"]
        branches.append(branch_summary)

    return _failure(
        "FORK",
        path[0],
        path,
        fork_count=len(rows),
        branches=branches,
    )


def _check_attestation(
    row: Any,
    on_path: frozenset[str],
    depth: int,
    path: list[str],
) -> dict[str, Any]:
    att = _att(row)
    issuer = _issuer(att["issuer"])

    if issuer is None:
        return _failure("UNKNOWN_ISSUER", att["artifact_digest"], path)

    if not verify_attestation(
        issuer["public_key"],
        att["artifact_digest"],
        att["issuer"],
        att["parent_digest"],
        att["signature"],
    ):
        return _failure("INVALID_SIGNATURE", att["artifact_digest"], path)

    if att["parent_digest"] is None:
        if not issuer["trusted_root"]:
            return _failure("UNTRUSTED_ROOT", att["artifact_digest"], path)
        return _success([att])

    parent_digest = att["parent_digest"]
    parent_result = _verify_node(parent_digest, on_path, depth + 1)

    if not parent_result["valid"]:
        # 被引用的父 digest 没有任何证明 -> 断链,区别于顶层查无制品。
        reason = parent_result["fail_reason"]
        if reason == "NO_ATTESTATION":
            reason = "MISSING_PARENT"
        return _failure(
            reason,
            parent_result["fail_at"],
            path + parent_result["path"],
            **{
                k: v
                for k, v in parent_result.items()
                if k
                not in ("valid", "fail_reason", "fail_at", "path", "artifact_digest")
            },
        )

    return _success([att] + parent_result["chain"])
