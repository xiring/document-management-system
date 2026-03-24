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

If `ETH_RPC_URL`, `CONTRACT_ADDRESS`, or `PRIVATE_KEY` is missing, uploads still work but **on-chain notarization is skipped** (`blockchain_tx_hash` may be null).

## API overview

All `/documents/*` routes require `Authorization: Bearer <token>`.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/auth/register` | Register with JSON body `email`, `password` |
| `POST` | `/auth/token` | OAuth2 form: `username` = email, `password` |
| `POST` | `/documents/upload` | Multipart file upload; hashes **content** with SHA-256 |
| `GET` | `/documents` | List current user’s documents |
| `GET` | `/documents/{id}` | Get one document |
| `POST` | `/documents/{id}/versions` | Upload a new version (new row, linked to parent) |
| `GET` | `/documents/{id}/verify` | Re-hash file on disk; compares to DB and optionally chain |
| `GET` | `/health` | Liveness check |

The `content_sha256_hex` field in responses is the digest of **file bytes**, not the filename.

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
  blockchain_service.py # Web3 notarization helpers
  services/
    storage.py         # Local file IO and hashing
contracts/
  DocumentNotary.sol
.env.example
requirements.txt
```

## Security

- Do **not** commit `.env` or real private keys.
- Use a strong `JWT_SECRET_KEY` in production.
- Treat `PRIVATE_KEY` as highly sensitive; restrict RPC keys and database credentials the same way.
