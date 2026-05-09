# Stamp Mode -- V1 Limitations

- No persistent queue. Events lost on process crash.
- HTTP/1.1 only. HTTP/2 agents not supported.
- Chunked body hashing is heuristic. Binary chunked bodies may produce non-reproducible stamps.
- sync_anchor=true adds ~1s latency per stamped request. Use with caution.
- Body cap is 4 MiB. Stamps over truncated bodies are marked body_truncated=true in the receipt.
