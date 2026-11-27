# Contract: `Finding` (stable)

The single result type every heuristic and reviewer produces. Source: `core/heuristics/base.py`.
Breaking this shape is a human gate.

```python
@dataclass
class Finding:
    rule: str  # stable id, e.g. "aws_access_key", "pipe_to_shell", "injection_reviewer_manipulation"
    category: str  # secret | pii | command | injection | file | vuln
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    message: str  # human-readable reason (safe to show)
    start: int = -1  # char span in the scanned text; -1 when not applicable
    end: int = -1
    preview: str = ""  # MASKED snippet only — never the raw secret

    def to_dict(self) -> dict: ...
```

Rules:
- `severity` ∈ `SEVERITY_ORDER` (`LOW=1 … CRITICAL=4`). `max_severity(findings)` returns the highest or `None`.
- `preview` is produced by `mask()` — first ≤4 chars then `*`. **Never** put a raw secret/PII value in `preview`, `message`, or logs (INV-6).
- Spans drive `redact_spans()`, which keeps line numbers stable (replaces a span, preserving `\n` count).
- Decision mapping from a finding set: `max_severity ∈ {HIGH,CRITICAL} → deny`, `== MEDIUM → ask`, else `allow`.

Helpers (stable): `mask(value, keep=4)`, `redact_spans(text, findings, label)`, `max_severity(findings)`, `decoded_payloads(text, depth=2)` (base64/hex/`\xNN`, bounded by `MAX_DECODED`/`MAX_BLOB`).
