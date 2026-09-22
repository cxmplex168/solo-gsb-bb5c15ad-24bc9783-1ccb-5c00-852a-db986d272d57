# 供应链证明链校验 API(FastAPI + SQLite + Ed25519)

接收有向证明记录(`artifact_digest` / `issuer` / `parent_digest` / `signature`),
用 **Ed25519** 验证每条记录的签名,并从制品出发沿 `parent_digest` **递归校验到受信根**。
当同一制品出现**分叉**或链上存在**被撤销的祖先**时,返回可定位的失败路径与逐条分支结果;
成功时返回从制品到根的**有序信任链**。

## 信任模型

- **签发者身份 = Ed25519 公钥**。先通过 `POST /api/v1/issuers` 注册公钥,`trusted_root=true` 的签发者才允许签发根证明。
- 每条证明由签发者对**规范化载荷**签名(见下),写入时即验签,校验时再次验签。
- `parent_digest` 为 `null`/空串的记录是根证明,必须由受信根签发。
- 同一 `artifact_digest` 出现第二条(不同签发者的)证明即为**分叉**,校验失败并逐条追溯各分支。
- 对任一制品 `POST /api/v1/revocations` 即撤销;该制品及其全部后代校验失败,失败路径精确指向被撤销节点。

## 签名载荷规范

签发端对如下定长前缀拼接的字节串做 Ed25519 签名(长度均为小端 uint32):

```
b"attest-v1|" + u32le(len(artifact_digest)) + artifact_digest
              + u32le(len(issuer))          + issuer
              + u32le(len(parent_digest))   + parent_digest
```

- 字段按 UTF-8 编码;根证明的 `parent_digest` 为空串。
- 公钥 base64 解码后必须为 32 字节;签名 base64 解码后必须为 64 字节(标准/URL-safe base64 均接受)。
- 参考实现见 `app/crypto.py` 的 `canonical_message()`。

## 一键启动

### Docker Compose(推荐)

```bash
docker compose up -d --build
```

数据持久化在命名卷 `sc-data`(容器内 `/data/supplychain.db`)。
查看状态:`docker compose ps` / `docker compose logs -f`;停止:`docker compose down`(保留数据)。

可选:在 `docker-compose.yml` 中填入 `BOOTSTRAP_TRUSTED_ROOT_ID` 与
`BOOTSTRAP_TRUSTED_ROOT_PUBLIC_KEY`,首次启动会预置一个受信根。

### 本地直接运行

```bash
pip install -r requirements.txt
export DATABASE_PATH=./data/supplychain.db
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 服务地址与端口

| 用途 | 地址 |
| --- | --- |
| API Base | `http://127.0.0.1:8000` |
| Swagger UI(交互文档) | http://127.0.0.1:8000/docs |
| OpenAPI JSON | http://127.0.0.1:8000/openapi.json |
| 健康检查 | http://127.0.0.1:8000/healthz |

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康检查 |
| POST | `/api/v1/issuers` | 注册签发者公钥(可标记受信根);同 id 同 key 幂等 |
| GET | `/api/v1/issuers` | 列出签发者 |
| POST | `/api/v1/attestations` | 写入证明记录(写入即验签,重复记录幂等) |
| GET | `/api/v1/artifacts/{digest}` | 查询制品的全部证明 |
| GET | `/api/v1/artifacts/{digest}/verify` | **递归校验**,返回有序信任链或可定位失败 |
| POST | `/api/v1/revocations` | 撤销制品(幂等,可更新原因) |
| GET | `/api/v1/revocations` | 列出全部撤销 |
| GET | `/api/v1/revocations/{digest}` | 查询单个撤销 |

## 校验结果说明

`GET .../verify` 恒返回 HTTP 200,以 JSON 表达结果:

- 成功:`{"valid": true, "chain": [制品, …, 根]}`,`chain[0]` 是被校验制品,末位是受信根证明。
- 失败:`{"valid": false, "fail_reason": ..., "fail_at": <digest>, "path": [被校验制品, …, 失败点]}`。
- 分叉:`fail_reason="FORK"`,`branches[]` 中逐条给出每个签发者分支的 `valid / fail_reason / fail_at / path / chain`。

失败码:`FORK`、`REVOKED`、`INVALID_SIGNATURE`、`UNKNOWN_ISSUER`、`UNTRUSTED_ROOT`、
`MISSING_PARENT`(父 digest 无证明)、`NO_ATTESTATION`、`CYCLE`、`CHAIN_TOO_DEEP`。

## 快速体验

```bash
# 1) 生成两把密钥
python scripts/keygen.py root
python scripts/keygen.py builder

# 2) 注册签发者(root 标记为受信根)
curl -s -X POST localhost:8000/api/v1/issuers -H 'Content-Type: application/json' \
  -d '{"id":"root","public_key":"<ROOT_PUB>","trusted_root":true}'
curl -s -X POST localhost:8000/api/v1/issuers -H 'Content-Type: application/json' \
  -d '{"id":"builder","public_key":"<BUILDER_PUB>","trusted_root":false}'

# 3) 写入根证明与子证明(签名需用私钥对规范化载荷签名,见 app/crypto.py)
curl -s -X POST localhost:8000/api/v1/attestations -H 'Content-Type: application/json' \
  -d '{"artifact_digest":"<ROOT_DIGEST>","issuer":"root","parent_digest":null,"signature":"<SIG1>"}'
curl -s -X POST localhost:8000/api/v1/attestations -H 'Content-Type: application/json' \
  -d '{"artifact_digest":"<APP_DIGEST>","issuer":"builder","parent_digest":"<ROOT_DIGEST>","signature":"<SIG2>"}'

# 4) 校验 -> 有序信任链
curl -s localhost:8000/api/v1/artifacts/<APP_DIGEST>/verify | python -m json.tool

# 5) 撤销根 -> 后代校验返回 REVOKED 与完整路径
curl -s -X POST localhost:8000/api/v1/revocations -H 'Content-Type: application/json' \
  -d '{"artifact_digest":"<ROOT_DIGEST>","reason":"incident"}'
```

完整的自动演示(覆盖正常链、分叉、撤销祖先、断链、非受信根、无证明):

```bash
pip install cryptography   # 演示脚本只依赖 cryptography
python scripts/demo.py
```

## 项目结构

```
app/
  main.py       FastAPI 路由:签发者/证明写入、校验、撤销
  verifier.py   递归信任链校验、分叉逐分支追溯、失败路径
  crypto.py     Ed25519 验签与规范化载荷
  db.py         SQLite 建表、连接与写事务
  schemas.py    Pydantic 模型
scripts/
  keygen.py     生成 Ed25519 密钥对
  demo.py       端到端演示
Dockerfile / docker-compose.yml / requirements.txt
```
