# RANKIGI Proxy Interceptor

The open source proxy component of the RANKIGI execution proof layer.

The proxy intercepts outbound HTTP and HTTPS traffic from AI agents and
submits tamper-evident chain events to the RANKIGI ingest endpoint. No
agent code changes required.

## Quick start

```sh
curl -sSf https://rankigi.com/install | sh
```

## Managed service

The proxy ships with `proof_provider=rankigi.com` by default. Get your
API key at: [app.rankigi.com/dashboard/keys](https://app.rankigi.com/dashboard/keys)

## Self-hosting

The proxy can submit to any RANKIGI-compatible ingest endpoint by
setting `RANKIGI_INGEST_URL`.

## License

MIT. See [LICENSE](./LICENSE).

## Standard

The wire schema follows the open KYA standard:
[github.com/kya-standard/spec](https://github.com/kya-standard/spec)

---

## How it works

The proxy listens on a local port and accepts connections from agents that
have configured `HTTPS_PROXY=http://localhost:8080`. For each outbound HTTP
or HTTPS request the proxy:

1. Forwards the request to the upstream service unmodified.
2. Captures the request and response that crossed the wire.
3. Returns the response to the agent.
4. **Then** asynchronously hashes the captured pair and submits a chain
   event to the RANKIGI ingest endpoint.

The chain write happens entirely off the agent's hot path. If the RANKIGI
ingest endpoint is unreachable, the agent continues executing - gaps are
recorded in the chain when connectivity is restored.

The agent never reports anything. The agent cannot lie about what happened
because it is never asked.

## v1 scope

- ✅ Plain HTTP forwarding with full capture.
- ✅ HTTPS via `CONNECT` + dynamic leaf cert TLS interception (rustls).
- ✅ KYA-canonical JSON output, byte-for-byte identical to the Node SDK.
- ✅ Optional Ed25519 passport signing (when `RANKIGI_PASSPORT_KEY` is set).
- ✅ Bounded async ingest queue with retry, fail-open under saturation.
- ✅ Gap events on queue full or ingest failure.
- ⚠ Seal evaluation is implemented client-side but **disabled by default**
  (`RANKIGI_SEAL_EVAL_ENABLED=false`) because the
  `/api/seal/evaluate` endpoint does not exist on the server yet.
- ⚠ No HTTP/2 to the agent - the proxy speaks HTTP/1.1 only on the inbound
  side. Most agent SDKs negotiate HTTP/1.1 to a proxy by default.

## Setup

```sh
cd proxy
cargo build --release
./target/release/rankigi-proxy
```

Or via Docker:

```sh
cd proxy/docker
RANKIGI_INGEST_URL=https://rankigi.com \
RANKIGI_API_KEY=rnk_xxx \
RANKIGI_AGENT_ID=00000000-0000-0000-0000-000000000000 \
RANKIGI_ORG_ID=00000000-0000-0000-0000-0000000000aa \
docker compose up -d
```

On first startup the proxy generates a local root CA at
`./rankigi-ca.crt` (or `CA_CERT_PATH`) and a private key at
`./rankigi-ca.key` (or `CA_KEY_PATH`). The agent must be configured to
trust this cert (see "Agent configuration" below).

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `RANKIGI_PROXY_PORT` | no | `8080` | TCP port the proxy listens on. |
| `RANKIGI_INGEST_URL` | yes | - | Base URL of the RANKIGI deployment, e.g. `https://rankigi.com`. |
| `RANKIGI_API_KEY` | yes | - | Ingest API key (`rnk_<hex>` or bare hex). Sent as `Authorization: Bearer`. |
| `RANKIGI_AGENT_ID` | yes | - | UUID of the agent being proxied. Must be registered for the org. |
| `RANKIGI_ORG_ID` | yes | - | UUID of the org. (Server derives org from the API key, but the proxy logs both.) |
| `RANKIGI_BUFFER_SIZE` | no | `1000` | Max queued events before fail-open dropping kicks in. |
| `RANKIGI_INGEST_TIMEOUT_MS` | no | `5000` | Per-request timeout for ingest submission. |
| `RANKIGI_PASSPORT_KEY` | no | unset | Base64 PKCS8 Ed25519 private key. If set the proxy signs every event. |
| `RANKIGI_PASSPORT_ID` | no | unset | UUID of the passport corresponding to `RANKIGI_PASSPORT_KEY`. |
| `RANKIGI_SEAL_EVAL_ENABLED` | no | `false` | Toggle seal evaluation. Off by default - endpoint not yet deployed. |
| `RANKIGI_SEAL_EVAL_TIMEOUT_MS` | no | `20` | Maximum wait for a seal verdict before falling open. |
| `CA_CERT_PATH` | no | `rankigi-ca.crt` | Where the root CA cert is persisted. |
| `CA_KEY_PATH` | no | `rankigi-ca.key` | Where the root CA private key is persisted. |
| `RUST_LOG` | no | `info` | Tracing filter. |

## Agent configuration

For each language/runtime, set the proxy URL and trust the CA cert.

### Python (`requests`, `httpx`, `openai`, `anthropic`)

```sh
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export REQUESTS_CA_BUNDLE=/abs/path/to/rankigi-ca.crt
export SSL_CERT_FILE=/abs/path/to/rankigi-ca.crt
```

### Node.js

```sh
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export NODE_EXTRA_CA_CERTS=/abs/path/to/rankigi-ca.crt
```

If your client uses `undici` directly you may also need to construct a
proxy agent - most LLM SDKs (`openai`, `@anthropic-ai/sdk`) honor
`HTTPS_PROXY` automatically.

### Shell (curl, wget)

```sh
export HTTPS_PROXY=http://localhost:8080
export CURL_CA_BUNDLE=/abs/path/to/rankigi-ca.crt
```

### Verifying

```sh
curl -x http://localhost:8080 https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

The request should succeed and a corresponding `llm.openai.*` event should
appear in your RANKIGI dashboard.

## Failure behavior - fail open, always

| Failure | Behavior |
|---|---|
| Queue full (capacity exhausted) | Event dropped. Warning logged. Gap event queued for emission when capacity returns. |
| RANKIGI ingest endpoint unreachable | 3 retries with exponential backoff (100, 200, 400 ms). On exhaustion: gap event. Agent never sees the failure. |
| Seal eval timeout (when enabled) | Verdict tagged `timeout` in `decision_metadata`. Request proceeds to upstream regardless. |
| Seal eval endpoint missing or 5xx | Verdict tagged `unavailable`. Request proceeds. |
| Upstream service slow | Proxy waits up to 60 s. On error the captured pair still goes to the chain (without a status code). |
| CA generation fails on first run | Proxy refuses to start. This is the only fatal startup error. |

## Threat model

**The proxy holds the agent's private passport key when signing is
enabled.** This is a deliberate v1 tradeoff. Holding the key in-process
means the proxy can produce signed events that look identical to events
the SDK would have produced - letting the proxy stand in for the SDK
transparently. It also means: anyone with read access to
`RANKIGI_PASSPORT_KEY` (env var, container filesystem, process memory)
can forge events for the proxied agent.

Mitigations in this release:

- The Docker image is `distroless/static`, runs as a non-root user, and
  has the filesystem mounted read-only. Only the CA volume (`/data`) is
  writable.
- The CA private key is persisted with mode `0600` on Unix.
- The signing key is loaded from `RANKIGI_PASSPORT_KEY` once at startup
  and never written to disk.

If you cannot accept these tradeoffs, leave `RANKIGI_PASSPORT_KEY`
unset. Events will be submitted unsigned and the server will tag
them `data_quality_flag="unverified"`. Honest about the trust boundary.

A future release will introduce a dedicated server-side proxy-passport
type so the proxy never needs to hold the agent's signing key directly.

## Wire schema

The proxy submits to `POST {RANKIGI_INGEST_URL}/api/ingest` with the
exact wire schema that `src/app/api/ingest/route.ts` accepts:

```json
{
  "agent_id": "<uuid>",
  "action": "llm.openai.chat",
  "tool": "api.openai.com/v1/chat/completions",
  "severity": "info",
  "occurred_at": "2026-05-04T12:34:56.789Z",
  "payload": {
    "input_hash": "<sha256 hex>",
    "output_hash": "<sha256 hex>",
    "decision_metadata": {
      "method": "POST",
      "url": "https://api.openai.com/v1/chat/completions",
      "status_code": 200,
      "request_size_bytes": 412,
      "response_size_bytes": 1893,
      "proxy_latency_ms": 247,
      "capture_source": "proxy",
      "seal_verdict": "disabled"
    },
    "proxy_execution_result": "success",
    "proxy_data_quality_flag": "ok",
    "_proxy": "rankigi-proxy/0.1.0",
    "_ts": "2026-05-04T12:34:56.789Z",
    "_proof_provider": "rankigi.com"
  },
  "passport_id": "<uuid, if signed>",
  "signature": "<base64 ed25519, if signed>"
}
```

The server canonicalizes `payload`, hashes `prev_hash | server_received_at | org_id | agent_id | canonical_payload` into the chain, and returns
the new chain head.

## Tests

```sh
cargo test                    # all unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo audit
```

The most important test is `canonical_json_matches_typescript` - it
verifies that the Rust canonical JSON output is byte-for-byte identical
to the Node SDK's. If that test fails the proxy and the SDK no longer
agree on chain hashes and the verifier will reject proxy-captured events.
