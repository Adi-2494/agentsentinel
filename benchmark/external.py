"""Evaluate AgentSentinel on REAL public datasets (downloaded at runtime, never committed).

  deepset/prompt-injections  real injection / benign prompts (Apache-2.0)  -> AI-trap rules
  s2e-lab/SecurityEval       121 real insecure Python samples, by CWE     -> Merge Gate static scan

Rules only by default (no Claude calls). --llm N adds an LLM sample of N items per dataset.

    python benchmark/external.py              # free, rules only
    python benchmark/external.py --llm 40     # + 40 Claude Haiku calls per dataset
"""
import argparse
import json
import random
import sys
import tempfile
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from core import config  # noqa: E402
from core.detectors import injection  # noqa: E402
from core.llm import LLMError, LLMLimitReached, ask_json  # noqa: E402

DATA = ROOT / "benchmark" / "external_data"  # git-ignored
OUT = ROOT / "benchmark" / "results" / "external.json"
HF = "https://huggingface.co/datasets"
SOURCES = {
    "prompt_injections": {
        "dataset": "deepset/prompt-injections", "license": "Apache-2.0",
        "files": ["data/train-00000-of-00001-9564e8b05b4757ab.parquet",
                  "data/test-00000-of-00001-701d16158af87368.parquet"]},
    "securityeval": {
        "dataset": "s2e-lab/SecurityEval", "license": "none stated (used for evaluation only, not redistributed)",
        "files": ["dataset.jsonl"]},
}


def download(name: str) -> list[Path]:
    src, paths = SOURCES[name], []
    for f in src["files"]:
        dest = DATA / src["dataset"].replace("/", "__") / Path(f).name
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(f"{HF}/{src['dataset']}/resolve/main/{f}", dest)
        paths.append(dest)
    return paths


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    pct = lambda n, d: round(100 * n / d, 1) if d else None  # noqa: E731
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision_pct": pct(tp, tp + fp),
            "recall_pct": pct(tp, tp + fn), "false_positive_rate_pct": pct(fp, fp + tn),
            "accuracy_pct": pct(tp + tn, tp + fp + fn + tn)}


def confusion(pairs) -> dict:
    c = Counter((bool(truth), bool(pred)) for truth, pred in pairs)
    return metrics(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])


# ------------------------------------------------------------------ prompt injections
def eval_prompt_injections(llm_n: int, model: str) -> dict:
    parts = []
    for path in download("prompt_injections"):
        part = pd.read_parquet(path)
        part["split"] = "train" if path.name.startswith("train") else "test"
        parts.append(part)
    df = pd.concat(parts, ignore_index=True)
    df["pred_rules"] = df["text"].map(lambda t: bool(injection.scan(t)))
    # Rules were tuned on the TRAIN split only; the TEST split is the honest, held-out score.
    out = {"source": SOURCES["prompt_injections"], "n": len(df), "positives": int(df["label"].sum()),
           "rules_test_heldout": confusion(zip(df[df.split == "test"]["label"], df[df.split == "test"]["pred_rules"])),
           "rules_train_used_for_tuning": confusion(zip(df[df.split == "train"]["label"],
                                                        df[df.split == "train"]["pred_rules"])),
           "rules": confusion(zip(df["label"], df["pred_rules"]))}
    # scores only: dataset texts (some offensive jailbreak strings) are not copied into results
    if llm_n:
        rnd = random.Random(7)
        idx = rnd.sample(list(df[df.label == 1].index), llm_n // 2) + rnd.sample(list(df[df.label == 0].index), llm_n // 2)
        pairs = []
        from core.reviewer import injection_check  # the gate's own prompt, not a side prompt
        for i in idx:
            r = ask_json(injection_check.PROMPT.format(text=f"=== PR DESCRIPTION ===\n{df.at[i, 'text'][:4000]}"), model)
            pairs.append((df.at[i, "label"], isinstance(r, dict) and str(r.get("verdict", "")).upper() == "SUSPICIOUS"))
        out["llm_sample"] = {"model": model, "n": len(pairs), **confusion(pairs),
                             "rules_on_same_sample": confusion((df.at[i, "label"], df.at[i, "pred_rules"]) for i in idx)}
    return out


# ------------------------------------------------------------------ SecurityEval
def eval_securityeval(llm_n: int, model: str) -> dict:
    from core.reviewer import static_scan
    rows = [json.loads(line) for line in download("securityeval")[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {}
    with tempfile.TemporaryDirectory(prefix="as-secev-") as tmp:
        files = []
        for r in rows:
            p = Path(tmp) / r["ID"]
            p.write_text(r["Insecure_code"], encoding="utf-8")
            files.append(p)
        findings, errors = static_scan.scan_files(files, Path(tmp))  # one Semgrep run for all 121
        for f in findings:
            by_id.setdefault(f.file, []).append(f)
    cwe = lambda i: i.split("_")[0]  # noqa: E731
    per_cwe = defaultdict(lambda: [0, 0])
    detected_blocking = 0
    for r in rows:
        fs = by_id.get(r["ID"], [])
        hit = any(f.severity in config.FAIL_ON_SEVERITIES for f in fs)
        detected_blocking += hit
        per_cwe[cwe(r["ID"])][0] += hit
        per_cwe[cwe(r["ID"])][1] += 1
    out = {"source": SOURCES["securityeval"], "n": len(rows),
           "static_blocking_recall_pct": round(100 * detected_blocking / len(rows), 1),
           "static_any_finding_pct": round(100 * sum(bool(by_id.get(r["ID"])) for r in rows) / len(rows), 1),
           "per_cwe": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(per_cwe.items())},
           "tool_warnings": errors[:3]}
    if llm_n:
        from core.reviewer import two_view
        sample = random.Random(7).sample(rows, min(llm_n, len(rows)))
        hits = []
        for r in sample:
            view = two_view._review(f"=== FILE: {r['ID']} ===\n{r['Insecure_code']}", model)
            if view.verdict == "error":
                if "limit" in view.error.lower():
                    raise LLMLimitReached(view.error)
                continue
            static_hit = any(f.severity in config.FAIL_ON_SEVERITIES for f in by_id.get(r["ID"], []))
            hits.append((static_hit, two_view._serious(view)))
        out["llm_sample"] = {
            "model": model, "n": len(hits),
            "static_recall_pct": round(100 * sum(s for s, _ in hits) / len(hits), 1) if hits else None,
            "llm_recall_pct": round(100 * sum(llm for _, llm in hits) / len(hits), 1) if hits else None,
            "combined_recall_pct": round(100 * sum(s or llm for s, llm in hits) / len(hits), 1) if hits else None}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--llm", type=int, default=0, help="LLM sample size per dataset (0 = rules only)")
    ap.add_argument("--model", default="haiku")
    ap.add_argument("--only", choices=list(SOURCES), help="run one dataset")
    args = ap.parse_args()
    previous = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    results = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **{
        k: v for k, v in previous.items() if k in SOURCES}}
    try:
        for name, fn in (("prompt_injections", eval_prompt_injections), ("securityeval", eval_securityeval)):
            if not args.only or args.only == name:
                kept = previous.get(name, {}).get("llm_sample") if not args.llm else None
                results[name] = fn(args.llm, args.model)
                if kept:  # a rules-only re-run keeps the earlier (paid) LLM sample
                    results[name]["llm_sample"] = kept
                print(name, json.dumps({k: v for k, v in results[name].items()
                                        if k not in ("per_cwe", "source")}, indent=1))
    except (LLMLimitReached, LLMError) as e:
        print(f"LLM stopped: {e}")
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"saved {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
