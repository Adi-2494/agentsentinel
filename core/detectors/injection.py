"""AI-trap scanner (A5/B4): instructions aimed at an AI agent or reviewer, and
invisible Unicode. Rules only; the Merge Gate adds an LLM layer on top
(core/reviewer/injection_check.py).
"""
import io
import re
import tokenize
import unicodedata
from pathlib import PurePosixPath

from core.detectors.base import Finding

_AI = r"(?:ai|llm|gpt|claude|copilot|cursor|automated|bot|code)\s*(?:reviewer|review|assistant|agent|model)s?"

PHRASE_RULES = [
    ("injection_ignore_instructions", "HIGH", "Tells the AI to ignore its instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*"
        r"(?:previous|prior|above|earlier|preceding|system|original)\s+"
        r"(?:instructions?|rules|prompts?|guidelines|directions)", re.I)),
    ("injection_role_override", "HIGH", "Tries to give the AI a new role or system prompt", re.compile(
        r"\byou\s+are\s+now\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,3}?"
        r"(?:assistant|ai|model|agent|bot|reviewer|hacker|admin(?:istrator)?)\b|"
        r"\byou\s+are\s+no\s+longer\s+(?:bound|restricted|limited|an?\s+ai|claude)\b|"
        r"\bnew\s+system\s+prompt\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|dan)\b|"
        r"\benter\s+(?:developer|god|jailbreak)\s+mode\b", re.I)),
    ("injection_reviewer_manipulation", "HIGH", "Addresses an AI reviewer and tells it to approve / not flag",
     re.compile(
        rf"\b{_AI}\b[^.\n]{{0,60}}?\b(?:approve|pass|accept|ignore|skip|do\s+not\s+flag|don'?t\s+flag|"
        rf"do\s+not\s+report|mark\s+(?:it\s+|this\s+)?(?:as\s+)?safe|lgtm)\b|"
        rf"\b(?:note|attention|instructions?)\s+(?:to|for)\s+(?:the\s+)?{_AI}\b", re.I)),
    ("injection_suppress_reporting", "MEDIUM", "Asks reviewers not to report issues / claims pre-approval",
     re.compile(
        r"\bdo\s+not\s+(?:report|flag)\s+(?:this|any|these)\s+(?:issues?|findings?|vulnerabilit(?:y|ies)|"
        r"warnings?|problems?)\b|"
        r"\b(?:this|the)\s+(?:code|query|pr|change|function|input)\s+(?:is|has\s+been)\s+"
        r"(?:verified|certified|pre-?approved|guaranteed)\s+(?:safe|secure|sanitized)\b", re.I)),
    ("injection_exfil_instruction", "HIGH", "Asks the AI to send secrets or code to an external location",
     re.compile(
        r"\b(?:send|post|upload|exfiltrate|forward|transmit|leak|copy)\b[^.\n]{0,60}?"
        r"(?:\b(?:env(?:ironment)?(?:\s+variables)?|secrets?|api[\s_-]?keys?|tokens?|credentials|passwords?|"
        r"ssh\s+keys?|private\s+keys?|source\s+code|codebase|repository|repo)\b|\.env\b)[^\n]{0,60}?"
        r"\b(?:to|at|into)\s+(?:https?://|ftp://|[\w.-]+\.(?:com|net|io|xyz|site|ru|cn|top)\b)", re.I)),
    ("injection_hide_from_user", "HIGH", "Tells the AI to hide something from the user", re.compile(
        r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|show|alert|notify)\s+the\s+(?:user|developer|human)\b|"
        r"\bwithout\s+(?:telling|informing|notifying)\s+the\s+(?:user|developer|human)\b|"
        r"\bkeep\s+this\s+(?:secret|hidden)\s+from\s+the\s+(?:user|developer)\b", re.I)),
]

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "᠎", "﻿"}
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}

# Files that configure AI tools: any change deserves a human look.
AI_CONFIG_FILES = {
    ".cursorrules", "claude.md", "agents.md", ".windsurfrules", "copilot-instructions.md",
    "mcp.json", ".mcp.json",
}
AI_CONFIG_PATHS = {".cursor/mcp.json", ".vscode/settings.json", ".claude/settings.json",
                   ".claude/settings.local.json", ".github/copilot-instructions.md"}


def is_ai_config(path: str) -> bool:
    p = str(PurePosixPath(path.replace("\\", "/")))
    name = PurePosixPath(p).name.lower()
    return name in AI_CONFIG_FILES or any(p == c or p.endswith("/" + c) for c in AI_CONFIG_PATHS) \
        or "/.cursor/rules/" in "/" + p or p.startswith(".cursor/rules/")


def _hidden_unicode(text: str) -> list[Finding]:
    findings: list[Finding] = []
    tags = [(i, ch) for i, ch in enumerate(text) if 0xE0000 <= ord(ch) <= 0xE007F]
    if tags:
        hidden = "".join(chr(ord(ch) - 0xE0000) for _, ch in tags if 0x20 <= ord(ch) - 0xE0000 < 0x7F)
        findings.append(Finding(
            rule="hidden_unicode_tags", category="injection", severity="CRITICAL",
            message=f"Invisible Unicode tag characters hide text: {hidden[:120]!r}",
            start=tags[0][0], end=tags[-1][0] + 1, preview=hidden[:60]))
    for chars, rule, sev, label in ((BIDI, "hidden_unicode_bidi", "HIGH", "text-direction override (Trojan Source)"),
                                    (ZERO_WIDTH, "hidden_unicode_zero_width", "HIGH", "zero-width character")):
        hits = [i for i, ch in enumerate(text) if ch in chars and not (ch == "﻿" and i == 0)]
        if hits:
            names = sorted({unicodedata.name(text[i], hex(ord(text[i]))) for i in hits})
            findings.append(Finding(
                rule=rule, category="injection", severity=sev,
                message=f"{len(hits)} invisible {label} character(s): {', '.join(names)[:120]}",
                start=hits[0], end=hits[0] + 1, preview=f"U+{ord(text[hits[0]]):04X} at offset {hits[0]}"))
    return findings


def _visible(text: str) -> str:
    """Drop invisible characters so 'ign​ore previous' still matches."""
    return "".join(ch for ch in text if ch not in ZERO_WIDTH and ch not in BIDI
                   and not 0xE0000 <= ord(ch) <= 0xE007F)


def scan(text: str, path: str = "") -> list[Finding]:
    findings = _hidden_unicode(text)
    visible = _visible(text)
    for rule, sev, message, pattern in PHRASE_RULES:
        m = pattern.search(visible)
        if m:
            findings.append(Finding(rule=rule, category="injection", severity=sev, message=message,
                                    start=m.start(), end=m.end(), preview=m.group(0)[:80]))
    if path and is_ai_config(path):
        hooks = bool(re.search(r'"hooks"\s*:', text)) and path.endswith(".json")
        findings.append(Finding(
            rule="ai_config_hooks" if hooks else "ai_config_changed", category="injection",
            severity="HIGH" if hooks else "MEDIUM",
            message=("Adds hooks to an AI tool config: they run commands on the machine of anyone who "
                     "opens this repo with that tool" if hooks else
                     "Changes a file that instructs AI coding tools; review it by hand"),
            preview=path))
    return findings


def extract_comments(code: str, filename: str) -> str:
    """Comments + docstrings only: where persuasion aimed at reviewers usually hides."""
    if filename.endswith(".py"):
        try:
            out, prev = [], None
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type == tokenize.COMMENT:
                    out.append(f"L{tok.start[0]}: {tok.string}")
                elif tok.type == tokenize.STRING and (prev is None or prev.type in (
                        tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT)):
                    out.append(f"L{tok.start[0]}: {tok.string[:500]}")
                if tok.type not in (tokenize.NL, tokenize.COMMENT):
                    prev = tok
            return "\n".join(out)
        except (tokenize.TokenError, SyntaxError, IndentationError):
            pass
    hits = re.finditer(r"//[^\n]*|/\*[\s\S]*?\*/|<!--[\s\S]*?-->|^\s*#[^\n]*", code, re.M)
    return "\n".join(f"L{code.count(chr(10), 0, m.start()) + 1}: {m.group(0).strip()[:500]}" for m in hits)
