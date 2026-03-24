# Document Management System (DMS)

A small **FastAPI** backend that stores document metadata in **PostgreSQL**, keeps files on local disk (configurable directory), and optionally anchors **SHA-256 content hashes** on an **Ethereum-compatible** chain for proof-of-existence. Integrity is always based on **file bytes**, not filenames.

## Architecture

| Layer | Role |
| --- | --- |
| PostgreSQL | Users, document metadata, content hash, optional transaction hash |
| Local storage (`UPLOAD_DIR`) | Raw file bytes |
| Blockchain (optional) | Immutable mapping of content hash to notary owner address |

## Requirements

- Python 3.11+ (tested with 3.14)
- PostgreSQL
- Optional: RPC URL and a deployed `DocumentNotary` contract for on-chain notarization

## Setup

1. **Clone or copy the project** and create a virtual environment:

   ```bash
   cd dms
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Create a database** in PostgreSQL (example name: `dms`).

3. **Configure environment**: copy `.env.example` to `.env` and set at least `DATABASE_URL` and `JWT_SECRET_KEY`.

   ```bash
   cp .env.example .env
   ```

4. **Run the API** (tables are created on startup via SQLAlchemy):

   ```bash
   uvicorn app.main:app --reload
   ```

5. Open **interactive docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Environment variables

See `.env.example` for the full list. Important fields:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy URL, e.g. `postgresql+psycopg2://user:pass@localhost:5432/dms` |
| `JWT_SECRET_KEY` | Secret for signing access tokens |
| `UPLOAD_DIR` | Directory for stored files (default `./uploads`) |
| `ETH_RPC_URL` | JSON-RPC endpoint (optional) |
| `PRIVATE_KEY` | Hex key for signing notarization transactions (optional; never commit) |
| `CONTRACT_ADDRESS` | Deployed `DocumentNotary` contract (optional) |
| `CHAIN_ID` | Network chain ID (e.g. `1`, `137` for Polygon) |
| `BOOTSTRAP_ADMIN_EMAIL` | Optional. **On registration**, this email gets `admin`. **On every startup**, if a user with this email exists and is not admin yet, they are promoted to `admin` (so you can fix access without SQL) |

If `ETH_RPC_URL`, `CONTRACT_ADDRESS`, or `PRIVATE_KEY` is missing, uploads still work but **on-chain notarization is skipped** (`blockchain_tx_hash` may be null).

## Roles and permissions

Each user has a `role` stored in PostgreSQL (`admin`, `manager`, `user`, or `viewer`). Permissions are fixed per role:

| Role | Capabilities |
| --- | --- |
| **admin** | All document actions; list **all** users’ documents; manage users (`users:manage`) |
| **manager** | Same as user, plus list/read/verify **any** user’s documents |
| **user** | Upload and version **own** documents; list/read/verify own |
| **viewer** | Read and verify **own** documents only (no uploads) |

New registrations default to `user`. Set `BOOTSTRAP_ADMIN_EMAIL` before the first admin registers, or promote users with `PATCH /admin/users/{id}/role` (admins only). After a role change, the user should request a new JWT (`POST /auth/token`) so clients reflect the new role (the API always loads the role from the database on each request).

On startup, PostgreSQL databases that predate the `users.role` column get `ALTER TABLE ... ADD COLUMN IF NOT EXISTS role ...` applied automatically.

## API overview

Protected routes require `Authorization: Bearer <token>`. Access depends on role; insufficient permission returns **403**.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/auth/register` | Register with JSON body `email`, `password` |
| `POST` | `/auth/token` | OAuth2 form: `username` = email, `password` |
| `GET` | `/auth/me` | Current user profile (any authenticated user) |
| `POST` | `/documents/upload` | Multipart upload + optional form field `folder_id` (`documents:write`) |
| `PATCH` | `/documents/{id}` | Metadata: `folder_id`, `tag_ids`, `collection_ids` (partial JSON; `documents:write`, owner only) |
| `GET` | `/documents` | Search & list: `{ items, total, skip, limit }`. Extra filters: `folder_id`, `tag_ids` (repeat param; AND), `collection_id`, plus filename/hash/date/version filters (see Document search below) |
| `GET` | `/folders/tree` | Document tree: nested folders + document summaries + orphans; optional `owner_id` (read_all) |
| `GET`–`POST` | `/folders`, `/folders/{id}` | Folder CRUD (see Folders, tags, and collections) |
| `GET`–`POST`–`DELETE` | `/tags`, `/tags/{id}` | Tag CRUD |
| `GET`–`POST`–`PATCH`–`DELETE` | `/collections`, `/collections/{id}`, … | Collections + document membership |
| `GET` | `/documents/{id}` | Get metadata (own, or any if `manager`/`admin`) |
| `POST` | `/documents/{id}/versions` | New version for **your** document only |
| `GET` | `/documents/{id}/verify` | Content verification |
| `GET` | `/admin/users` | List users with pagination: `skip`, `limit` (default 100, max 500; `users:manage`) |
| `GET` | `/admin/users/{id}` | Get one user (`users:manage`) |
| `POST` | `/admin/users` | Create user: `email`, `password`, optional `role` (`users:manage`) |
| `PATCH` | `/admin/users/{id}` | Partial update: any of `email`, `role`, `password` (`users:manage`) |
| `PATCH` | `/admin/users/{id}/role` | Set role only (shortcut; `users:manage`) |
| `DELETE` | `/admin/users/{id}` | Delete user if they own no documents; cannot delete self or the last admin (`users:manage`) |
| `GET` | `/health` | Liveness check |

The `content_sha256_hex` field in responses is the digest of **file bytes**, not the filename.

### Folders, tags, and collections

- **Folders** — Hierarchical: optional `parent_id` on `POST /folders` (same owner; names unique among **siblings**). `GET /folders/tree` returns nested `roots` (each node has `children`, `documents`) plus `orphan_documents` (no folder). `GET/POST /folders`, `GET/DELETE /folders/{id}`; delete requires no subfolders and no documents.
- **Tags** — `GET/POST /tags`, `DELETE /tags/{id}`. Labels per user; attach via `PATCH /documents/{id}` with `tag_ids` (replaces the set). `POST /tags` returns existing tag if the name already exists.
- **Collections** — named groups: `GET/POST /collections`, `GET/PATCH/DELETE /collections/{id}`, and `POST/DELETE /collections/{id}/documents/{document_id}` to add/remove a document. `PATCH /documents/{id}` with `collection_ids` replaces membership in all listed collections (omit field to leave unchanged).

`DocumentOut` includes `folder_id`, `tag_ids`, and `collection_ids`. New document versions inherit folder, tags, and collections from the parent row.

### Document search (`GET /documents`)

- **`q` + `search_mode=substring`** (default): case-insensitive substring match on `filename`; `%` / `_` in `q` are escaped.
- **`q` + `search_mode=trigram`**: fuzzy match using PostgreSQL `pg_trgm` (`similarity()`). Requires the `pg_trgm` extension (the app attempts `CREATE EXTENSION` on startup; hosted DBs without superuser may log a warning and fall back to substring-only).
- **Filters**: `owner_id` (managers/admins only), `folder_id`, `collection_id`, `tag_ids` (repeat the query param; document must match **all** listed tags), ISO datetimes, `content_sha256_hex`, `version` / `version_min` / `version_max`.
- **Pagination**: `skip` and optional `limit` (1–5000; omit `limit` for no cap—use carefully).

## Smart contract

`contracts/DocumentNotary.sol` exposes `notarize(bytes32 hash, address owner)` and a `documentOwner` mapping. Deploy it on your target network, set `CONTRACT_ADDRESS` and `CHAIN_ID`, fund the wallet for `PRIVATE_KEY`, then restart the app so new uploads can submit transactions.

## Project layout

```text
app/
  main.py              # FastAPI routes
  database.py          # Engine and sessions
  models.py            # SQLAlchemy models
  schemas.py           # Pydantic models
  auth.py              # JWT and password hashing
  config.py            # Settings from environment
  roles.py             # Role enum and permission sets
  permissions.py       # Dependency injection for route permissions
  blockchain_service.py # Web3 notarization helpers
  document_search.py   # Document list filters (ILIKE / pg_trgm)
  routers/
    organization.py    # Folders, tags, collections API
  services/
    storage.py         # Local file IO and hashing
contracts/
  DocumentNotary.sol
.env.example
requirements.txt
```

## Troubleshooting

### `403` on `PATCH /admin/users/.../role`

Only users with role **`admin`** may change roles. Either:

1. Set `BOOTSTRAP_ADMIN_EMAIL` in `.env` to the **same email** as your existing account, restart the API, and the app will promote that user to admin on startup; or  
2. Run SQL: `UPDATE users SET role = 'admin' WHERE id = 1;` (adjust `id` / email as needed).

### `(trapped) error reading bcrypt version` / `bcrypt has no attribute '__about__'`

The app pins `bcrypt` to `<4.1` for compatibility with `passlib`. Reinstall: `pip install -r requirements.txt`.

## Security

- Do **not** commit `.env` or real private keys.
- Use a strong `JWT_SECRET_KEY` in production.
- Treat `PRIVATE_KEY` as highly sensitive; restrict RPC keys and database credentials the same way.
