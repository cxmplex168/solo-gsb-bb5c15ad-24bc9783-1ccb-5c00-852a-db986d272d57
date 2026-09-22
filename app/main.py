"""供应链证明链校验 API。

接口一览(详见 /docs):
  GET    /healthz
  POST   /api/v1/issuers                     注册签发者公钥(可标记受信根)
  GET    /api/v1/issuers                     列出签发者
  POST   /api/v1/attestations                写入证明记录(写入即验签)
  GET    /api/v1/artifacts/{digest}          查询制品的全部证明
  GET    /api/v1/artifacts/{digest}/verify   递归校验信任链
  POST   /api/v1/revocations                 撤销制品
  GET    /api/v1/revocations                 列出撤销记录
  GET    /api/v1/revocations/{digest}        查询单个撤销
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from . import db
from .crypto import b64decode, load_public_key, verify_attestation
from .schemas import (
    AttestationIn,
    AttestationOut,
    IssuerIn,
    IssuerOut,
    RevocationIn,
    RevocationOut,
    SimpleOk,
    VerifyResult,
)
from .verifier import verify_artifact


def _bootstrap_trusted_root() -> None:
    """通过环境变量 BOOTSTRAP_TRUSTED_ROOT_ID / _PUBLIC_KEY 预置受信根。

    仅在首次启动且该 issuer 不存在时写入,之后可用 API 正常管理。
    """
    root_id = os.environ.get("BOOTSTRAP_TRUSTED_ROOT_ID")
    root_pub = os.environ.get("BOOTSTRAP_TRUSTED_ROOT_PUBLIC_KEY")
    if not root_id or not root_pub:
        return
    with db.write_tx() as conn:
        exists = conn.execute(
            "SELECT 1 FROM issuers WHERE id = ?", (root_id,)
        ).fetchone()
        if exists is None:
            try:
                load_public_key(root_pub)
            except ValueError:
                raise RuntimeError("BOOTSTRAP_TRUSTED_ROOT_PUBLIC_KEY is invalid")
            conn.execute(
                "INSERT INTO issuers (id, public_key, trusted_root) VALUES (?, ?, 1)",
                (root_id, root_pub.strip()),
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    os.makedirs(os.path.dirname(db.db_path()), exist_ok=True)
    db.init_db()
    _bootstrap_trusted_root()
    yield


app = FastAPI(
    title="供应链证明链校验 API",
    description="FastAPI + SQLite + Ed25519 的有向证明记录与信任链递归校验服务",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["meta"])
def healthz() -> dict[str, bool]:
    return {"ok": True}


# ---------------------------------------------------------------- issuers


@app.post(
    "/api/v1/issuers",
    response_model=IssuerOut,
    status_code=status.HTTP_201_CREATED,
    tags=["issuers"],
)
def register_issuer(body: IssuerIn) -> dict:
    try:
        load_public_key(body.public_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid public key: {exc}")

    with db.write_tx() as conn:
        row = conn.execute(
            "SELECT * FROM issuers WHERE id = ?", (body.id,)
        ).fetchone()
        if row is not None:
            if row["public_key"] != body.public_key.strip():
                raise HTTPException(
                    status_code=409,
                    detail=f"issuer {body.id!r} already registered with a "
                    "different public key; identity is bound to the key",
                )
            conn.execute(
                "UPDATE issuers SET trusted_root = ? WHERE id = ?",
                (1 if body.trusted_root else 0, body.id),
            )
            row = conn.execute(
                "SELECT * FROM issuers WHERE id = ?", (body.id,)
            ).fetchone()
            return JSONResponse(status_code=status.HTTP_200_OK, content=dict(row))

        conn.execute(
            "INSERT INTO issuers (id, public_key, trusted_root) VALUES (?, ?, ?)",
            (body.id, body.public_key.strip(), 1 if body.trusted_root else 0),
        )
        return dict(
            conn.execute(
                "SELECT * FROM issuers WHERE id = ?", (body.id,)
            ).fetchone()
        )


@app.get("/api/v1/issuers", response_model=list[IssuerOut], tags=["issuers"])
def list_issuers() -> list[dict]:
    return [dict(r) for r in db.query_all("SELECT * FROM issuers ORDER BY id")]


# ------------------------------------------------------------ attestations


@app.post(
    "/api/v1/attestations",
    response_model=AttestationOut,
    status_code=status.HTTP_201_CREATED,
    tags=["attestations"],
)
def put_attestation(body: AttestationIn) -> dict:
    # 写入前防御性校验:签名必须是 64 字节,且能通过已注册公钥验签。
    issuer = db.query_one(
        "SELECT * FROM issuers WHERE id = ?", (body.issuer,)
    )
    if issuer is None:
        raise HTTPException(
            status_code=422,
            detail=f"unknown issuer {body.issuer!r}; register its public key first",
        )

    if body.parent_digest is not None and body.parent_digest == body.artifact_digest:
        raise HTTPException(status_code=400, detail="artifact cannot attest itself")

    if len(b64decode(body.signature)) != 64:
        raise HTTPException(status_code=400, detail="signature must decode to 64 bytes")

    if not verify_attestation(
        issuer["public_key"],
        body.artifact_digest,
        body.issuer,
        body.parent_digest,
        body.signature,
    ):
        raise HTTPException(
            status_code=400,
            detail="signature verification failed against the issuer's public key",
        )

    with db.write_tx() as conn:
        existing = conn.execute(
            "SELECT * FROM attestations WHERE artifact_digest = ? AND issuer = ?",
            (body.artifact_digest, body.issuer),
        ).fetchone()
        if existing is not None:
            if (
                existing["parent_digest"] == body.parent_digest
                and existing["signature"] == body.signature
            ):
                # 幂等:完全相同的重复写入回显 200。
                return JSONResponse(status_code=status.HTTP_200_OK,
                                    content=dict(existing))
            raise HTTPException(
                status_code=409,
                detail=(
                    f"artifact {body.artifact_digest!r} already has an attestation "
                    f"from issuer {body.issuer!r}; a second issuer creates a fork"
                ),
            )

        conn.execute(
            """INSERT INTO attestations
                   (artifact_digest, issuer, parent_digest, signature)
               VALUES (?, ?, ?, ?)""",
            (
                body.artifact_digest,
                body.issuer,
                body.parent_digest,
                body.signature,
            ),
        )
        row = conn.execute(
            "SELECT * FROM attestations WHERE artifact_digest = ? AND issuer = ?",
            (body.artifact_digest, body.issuer),
        ).fetchone()
        return dict(row)


@app.get(
    "/api/v1/artifacts/{digest}",
    response_model=list[AttestationOut],
    tags=["attestations"],
)
def get_artifact(digest: str) -> list[dict]:
    return [
        dict(r)
        for r in db.query_all(
            "SELECT * FROM attestations WHERE artifact_digest = ? ORDER BY id",
            (digest,),
        )
    ]


@app.get(
    "/api/v1/artifacts/{digest}/verify",
    response_model=VerifyResult,
    tags=["verification"],
)
def verify(digest: str) -> dict:
    return verify_artifact(digest)


# -------------------------------------------------------------- revocations


@app.post(
    "/api/v1/revocations",
    response_model=RevocationOut,
    status_code=status.HTTP_201_CREATED,
    tags=["revocations"],
)
def revoke(body: RevocationIn) -> dict:
    with db.write_tx() as conn:
        existing = conn.execute(
            "SELECT * FROM revocations WHERE artifact_digest = ?",
            (body.artifact_digest,),
        ).fetchone()
        already = existing is not None
        if existing is not None:
            conn.execute(
                "UPDATE revocations SET reason = ? WHERE artifact_digest = ?",
                (body.reason, body.artifact_digest),
            )
        else:
            conn.execute(
                "INSERT INTO revocations (artifact_digest, reason) VALUES (?, ?)",
                (body.artifact_digest, body.reason),
            )
        payload = dict(
            conn.execute(
                "SELECT * FROM revocations WHERE artifact_digest = ?",
                (body.artifact_digest,),
            ).fetchone()
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK if already else status.HTTP_201_CREATED,
            content=payload,
        )


@app.get(
    "/api/v1/revocations",
    response_model=list[RevocationOut],
    tags=["revocations"],
)
def list_revocations() -> list[dict]:
    return [dict(r) for r in db.query_all(
        "SELECT * FROM revocations ORDER BY revoked_at"
    )]


@app.get(
    "/api/v1/revocations/{digest}",
    response_model=RevocationOut,
    tags=["revocations"],
)
def get_revocation(digest: str) -> dict:
    row = db.query_one(
        "SELECT * FROM revocations WHERE artifact_digest = ?", (digest,)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="artifact is not revoked")
    return dict(row)
