# v2 / V1 — webhook receiver + gate (build report)

Built test-first, stdlib-only, LLM-backend-agnostic (subscription or free Ollama via `core.config`),
so building V1 did **not** commit the SG-018 ToS decision. No live GitHub and no deployment here.

## Delivered
- **`app/webhook.py`** — the tested core: `verify_signature` (HMAC SHA-256, constant-time),
  `parse_event` (pull_request opened/synchronize/reopened → `Job`; else ignored), `handle()`
  (verify → parse → locate repo → run the **unchanged** gate → log). **Fails closed** on bad
  signature, unreadable body, or gate crash.
- **`app/runner.py`** — `run_job()` reuses `gate.run_gate` verbatim: files from the PR head via
  `git show` (INV-5), `gate.run()`, `log_result()` to the shared store. Engine untouched.
- **`app/server.py`** — thin stdlib `http.server` glue around `handle()` (the deployable edge).
- **`tests/test_webhook.py`** — 14 tests: signature valid/invalid/missing; event parsing matrix;
  handle guards (401/204/404/400); **end-to-end** (signed PR event runs the gate and blocks a
  vulnerable PR, logged to the store); **fail-closed on gate error**.

## Verification
- 14/14 webhook tests green; full suite green; `ruff` + `ruff format` clean.
- **mypy --strict (whole project, 31 files) clean** — and it caught a *latent* type error from the
  P01 confusable fix (`injection.py` used an `int` value in a `dict[int, str]`); fixed to `chr(...)`
  (behaviour identical, now type-correct). The CI `typecheck` job would have failed without this.

## Scope boundaries (deliberately not in V1)
- **Posting back to GitHub** (Check Run + PR comment) → V2.
- **Fetching a remote clone** via the App install token → V3; V1 runs on a local checkout the
  `resolve_repo` seam provides (what the tests and a self-hosted owner use).
- **Live run** against the real subscription still waits on **SG-018** (ToS) and **SG-017** (host).

## What's proven
A signed `pull_request` webhook deterministically runs the real Merge Gate on the PR's committed
head and blocks a vulnerable PR — with no LLM, no network, and fail-closed behaviour throughout.
