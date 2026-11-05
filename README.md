# Ticketer — Gate Server

Async gate/terminal server for the **Ticketer** contactless fare-payment demo. It
accepts connections from fare cards (the [client](https://github.com/bgnacinski/conductor-ticketer-client)), verifies the card's
CA-signed SSH certificate, challenges the card to prove possession of its private
key, and records the tap into a local outbox that is later pushed to a remote API.

The gate does **not** own or generate the CA key pair. On every start it downloads
the CA **public** key from the API and caches it locally; the matching private key
stays wherever certificates are issued. Every card presents an SSH certificate
signed by that CA, signs a random nonce, and receives an `OK` / `FAIL` (or `BANNED`)
response. Valid taps are queued in SQLite and synced to the API in the background
with retries, so the gate keeps working while the API is offline.

> This is the **server** half of the project. The [card client](https://github.com/bgnacinski/conductor-ticketer-client) connects to `localhost:2137`.

---

## Features

- Plain-TCP authentication server on `localhost:2137`.
- Downloads the CA public key and ban list from the API on startup, caching both
  locally for offline operation.
- Verifies SSH certificates: CA signature, signing key, and validity window.
- Rejects weak or unsupported public keys (`KEY_NOT_SECURE`).
- Proof-of-possession challenge: the card signs a random nonce.
- Rejects banned cards using a locally cached ban list.
- Durable SQLite **outbox** — taps survive restarts and API outages.
- Background sync loop with bulk/single push, batching, and randomized retry
  delays.
- Periodic refresh of the CA public key and ban list from the API.

---

## Requirements

| Tool       | Version used | Notes                                          |
| ---------- | ------------ | ---------------------------------------------- |
| Python     | 3.14+        | Uses `asyncio` and `aiosqlite`                  |
| `pip`      | —            | Installed inside the project virtualenv         |

Python packages (installed with `pip`):

| Package        | Version used |
| -------------- | ------------ |
| `aiosqlite`    | 0.22.1       |
| `httpx`        | 0.28.1       |
| `cryptography` | 50.0.2       |

---

## Project layout

```
server/
├── main.py            # gate handler + certificate/nonce verification
├── Exchanger.py       # Outbox: SQLite persistence and API sync
├── env                # sample configuration (copy to .env)
├── crypto/            # git-ignored — cached CA public key
│   └── ca_key.pub     # downloaded from the API at startup
├── db/                # git-ignored — SQLite database
│   └── outbox.db
└── .venv/             # local virtualenv, git-ignored
```

Both `crypto/` and `db/` are **git-ignored**; a fresh clone starts without them.

---

## How to run

### 1. CA public key

The gate does not generate a CA key pair. On every start, `setup()` calls
`GET {API_URL}pubkey`, validates the returned key, and caches it at
`crypto/ca_key.pub` (or the path in `PUB_KEY`). If the API cannot be reached, the
gate falls back to the cached file. The listener then loads
`crypto/ca_key.pub` when it starts.

For local development without a reachable API, simply create the directories and
place a valid SSH public key there:

```bash
# from the server/ directory
mkdir -p crypto db
# copy the CA public key to crypto/ca_key.pub
```

> `crypto/` is git-ignored. It only holds the cached **public** key here; the CA
> private key never needs to be on the gate.

### 2. Install the packages

```bash
# from the server/ directory
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Configure the environment

Copy the sample `env` file to `.env` and adjust the values:


| Variable         | Default                 | Description                                                        |
| ---------------- | ----------------------- | ------------------------------------------------------------------ |
| `GATE_TYPE`      | `exit`                  | `entry` or `exit` — the action type logged for each tap.            |
| `NONCE_SIZE`     | `16` (sample: `32`)     | Challenge size in bytes. Must match the client's `CHALL_SIZE`.      |
| `DB_FILE`        | `db/outbox.db`          | SQLite database path.                                               |
| `PUB_KEY`        | `crypto/ca_key.pub`     | Path where the API-fetched CA public key is cached and used as an offline fallback. The listener loads `crypto/ca_key.pub` on startup. |
| `API_URL`        | `http://localhost/api/` | Base URL of the remote Ticketer API (trailing slash required).      |
| `API_KEY`        | *(empty)*               | Bearer token sent to the API.                                       |
| `BULK_PUSH`      | `false`                 | `true`/`yes` to push taps in batches instead of one request each.   |
| `PUSH_INTERVAL`  | `1800`                  | Seconds between outbox sync attempts.                               |
| `SETUP_INTERVAL` | `86400`                 | Seconds between CA key / ban list refreshes.                        |
| `BATCH_SIZE`     | `500`                   | Maximum entries per bulk request.                                   |

### 5. Start the gate

Run from the **project root of `server/`** — paths such as `crypto/ca_key.pub` and
`db/outbox.db` are resolved relative to the current working directory.

```bash
source .venv/bin/activate
python main.py
```

Startup sequence:

1. `setup()` prepares the database tables and downloads the CA public key and ban
   list from the API, caching the key at `PUB_KEY` and falling back to the cached
   copies when the API is unreachable.
2. `gate_handler()` opens `localhost:2137`, resets interrupted outbox entries, and
   starts two background loops:
   - `sync_with_api()` — pushes queued taps every `PUSH_INTERVAL` seconds.
   - `setup_loop()` — refreshes the CA key and bans every `SETUP_INTERVAL` seconds.

A card tap produces log lines like:

```
[*] Client Handler | Client connected! Waiting for public key... received public key (length: 1234)
[*] Client Handler | Valid certificate
[*] Client Handler | OK. Gate open
[*] Exchanger | Successful API push of 1/1 elements
```

---

## Protocol

The handshake is a plain TCP exchange over `localhost:2137`:

```
Card                                          Gate
 |                                             |
 |--- CA-signed certificate ------------------>|  parse certificate
 |                                             |  verify CA signature + validity window
 |                                             |  check public key algorithm
 |                                             |
 |<-- random nonce (challenge) ----------------|  or INVALID_CERT / KEY_NOT_SECURE
 |                                             |
 |--- signature over the nonce --------------->|  verify proof of possession
 |                                             |  check local ban list
 |                                             |  enqueue tap in outbox
 |                                             |
 |<-- "OK" / "FAIL" / "BANNED" ----------------|  result
```

Gate responses:

| Response         | Meaning                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `OK`             | Certificate valid, key strong enough, signature verified — tap logged.  |
| `FAIL`           | The nonce signature did not verify.                                     |
| `INVALID_CERT`   | Not a certificate, wrong CA signature, or outside the validity window.  |
| `KEY_NOT_SECURE` | Unsupported algorithm, or RSA < 2048 / ECDSA < 256 bits.                |
| `BANNED`         | Certificate and signature are valid, but the card is banned.            |

### Accepted card key algorithms

| Algorithm | Requirement           | Verification                                  |
| --------- | --------------------- | --------------------------------------------- |
| Ed25519   | any key               | native Ed25519 signature                      |
| ECDSA     | curve size ≥ 256 bits | SHA-256 / SHA-384 / SHA-512 by curve size     |
| RSA       | size ≥ 2048 bits      | PKCS#1 v1.5 + SHA-512, falling back to SHA-256 |

Other key types (DSA, Ed448, …) are rejected with `KEY_NOT_SECURE`.

---

## Outbox and API sync

Each accepted tap is written to the `outbox` table:

| Column               | Description                                              |
| -------------------- | -------------------------------------------------------- |
| `id`                 | UUID of the tap.                                         |
| `client_fingerprint` | SHA-256 hex digest of the card's serialized public key.  |
| `action_type`        | `entry` or `exit`, from `GATE_TYPE`.                     |
| `created_at`         | Insert timestamp (UTC, `CURRENT_TIMESTAMP`).             |
| `status`             | `PENDING`, `PROCESSING`, `FAILED`, `SENT`, `VALERR`.     |
| `next_retry_at`      | Earliest time a `FAILED` entry may be retried.           |
| `error_message`      | Last error (HTTP status or `CONN_ERR`).                  |

Bans are cached in the `bans` table (one row per fingerprint) so a ban survives an
API outage.

On startup, `Outbox.cleanup()` resets `PROCESSING` entries back to `PENDING` and
deletes `SENT` ones. During a push, the sync loop atomically claims pending/retryable
rows as `PROCESSING`, then handles each API response:

| API result                  | Outbox action                                  |
| --------------------------- | ---------------------------------------------- |
| `200` / `201`               | Mark batch `SENT`.                             |
| `207 Multi-Status`          | `created` + `duplicates` → `SENT`, `failed` → `VALERR`. |
| `409 Conflict`              | `duplicates` → `SENT`.                         |
| `422 Unprocessable Entity`  | `failed` → `VALERR` (permanently dropped).     |
| `401` / `403` / `429` / `5xx` | `FAILED` with a `next_retry_at` backoff.      |
| Transport error             | `FAILED` with `CONN_ERR`, sync aborts.         |

Anything still unacknowledged when a push finishes is reset to `PENDING`, so no tap
is lost.

### API endpoints used

| Method | Path                     | Purpose                                    |
| ------ | ------------------------ | ------------------------------------------ |
| `GET`  | `{API_URL}pubkey`        | Fetch the CA public key (base64).          |
| `GET`  | `{API_URL}bans`          | Fetch banned fingerprints (`?output_type=list`). |
| `POST` | `{API_URL}log`           | Push queued taps.                          |

All requests carry `Authorization: Bearer $API_KEY` and a `User-Agent` header.

---

## Troubleshooting

| Symptom                                             | Cause / fix                                                                                     |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `[!] Cannot open database from: ...`                 | Missing `db/` directory or bad `DB_FILE` — run `mkdir -p db`.                                   |
| `[!] Unable to load any public key ...`              | `crypto/ca_key.pub` is missing and the API is unreachable — place the CA public key there (step 1). |
| `[!] Unable to retrieve banned clients ...`          | API unreachable; the gate falls back to the saved ban list.                                     |
| `INVALID_CERT` for every card                        | Card cert was not signed by this CA, or it is outside its `-V` validity window.                |
| `KEY_NOT_SECURE` for every card                      | Card key is too weak (RSA < 2048, ECDSA < 256) or an unsupported type (DSA, Ed448).             |
| `FAIL` for every card                                | The client signed the nonce with a different key/algorithm than the certificate advertises.    |
| Card connects but gets no response                   | The card did not send a complete newline-terminated certificate (`readline()` blocks).          |
| `Connection refused` on `localhost:2137`             | The gate is not running, or another process holds the port.                                    |
| Taps never reach the API                             | Check `API_URL` (trailing `/`), `API_KEY`, and the `[!] Exchanger ...` log lines.               |

Logs are printed to stdout with `[*]` for normal progress, `[!]` for errors, and the
component name (`Client Handler`, `Exchanger`, `Gate Handler`) in the middle.

---

## Related projects

- [Card client](https://github.com/bgnacinski/conductor-ticketer-client) — mock fare card that performs the tap handshake.
- [API](https://github.com/bgnacinski/conductor-api) - API

---

## License

[MIT](LICENSE) © 2026 Borys Gnaciński
