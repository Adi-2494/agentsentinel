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
] + [
    # --- chat-style jailbreaks, learned from the TRAIN split of deepset/prompt-injections only ---
    ("injection_forget_instructions", "HIGH", "Tells the AI to forget / drop its instructions or tasks", re.compile(
        # verb + (all/any/your ... | previous/above ...) + object: "forget all previous tasks", "ignore your instructions"
        r"\b(?:forget|ignore|disregard|drop|abandon|discard)\s+(?:about\s+)?"
        r"(?:(?:all|any|your)\s+(?:of\s+)?(?:the\s+|your\s+)?|(?:the\s+)?(?=previous|prior|above|preceding|earlier|original|provided))"
        r"(?:previous\s+|prior\s+|above\s+|preceding\s+|earlier\s+|original\s+|provided\s+)?"
        r"(?:instructions?|tasks?|assignments?|orders|rules|prompts?|directions|information|context|documents|thoughts)\b|"
        r"\b(?:forget|ignore)\s+(?:about\s+)?everything\s+(?:before|above|we\s+discussed|you\s+know|i\s+said|said)|"
        r"\bignore\s+(?:the\s+)?above\s+(?:and|instructions|prompt)\b|"
        # German / Spanish / French / Croatian / Russian equivalents seen in the train split
        r"\bvergiss\s+(?:nun\s+)?(?:alle?s?\b|deine)|\bignorier(?:e|en\s+sie)\s+(?:alle|die|deine)\b|"
        r"\b(?:die\s+)?obigen\s+(?:ausführungen|anweisungen)\s+ignorieren|\babweichend\s+zu\s+vorherigen\b|"
        r"\bolvid(?:a|e|ar)\s+tod[oa]s?\b|\boubliez\s+toutes\b|\bzaboravi\s+sve\b|забудьте\s+все", re.I)),
    ("injection_dismiss_prior", "HIGH", "Tells the AI to set aside what it was told before (paraphrased)",
     re.compile(
        r"\b(?:set|put|leave|cast|push)\s+aside\s+(?:all\s+|everything\s+|the\s+|any\s+|your\s+)*"
        r"(?:(?:stated|said|written|mentioned|given|told)\s+)?(?:(?:previous|prior|earlier|above|original)\s+)?"
        r"(?:earlier|before|above|previously|so\s+far|"
        r"guidance|instructions?|directions|rules|context)|"
        r"\bpay\s+no\s+(?:attention|heed|mind)\s+to\s+(?:all\s+|any\s+|the\s+|your\s+)*"
        r"(?:previous|prior|earlier|above|preceding|original|existing)?\s*"
        r"(?:guidance|instructions?|directions|rules|context|prompts?|messages?|text)|"
        r"\b(?:everything|anything|all)\s+(?:that\s+was\s+|you\s+were\s+|i\s+)?"
        r"(?:stated|said|written|mentioned|told|given)\s+(?:to\s+you\s+)?(?:earlier|before|above|previously)"
        r"[^.\n]{0,40}\b(?:no\s+longer\s+appl|does\s+not\s+(?:apply|matter)|is\s+(?:void|irrelevant|cancel+ed))|"
        r"\b(?:the\s+)?(?:guidance|instructions?|directions|rules)\s+(?:you\s+were\s+given|above|before)\s+"
        r"(?:no\s+longer\s+appl|(?:are|is)\s+(?:void|cancel+ed|outdated|obsolete))|"
        r"\byour\s+(?:real|actual|true)\s+(?:job|task|instructions?|purpose|goal)\s+(?:is|are|follows)\b", re.I)),
    ("injection_new_task", "HIGH", "Announces new instructions that replace the AI's task", re.compile(
        r"\b(?:focus|concentrate)\s+on\s+your\s+new\s+task\b|\bnew\s+(?:tasks?|instructions)\s+(?:follow|are)\b|"
        r"\bstart\s+(?:over|afresh)\s+with\s+a\s+new\s+task\b|\byour\s+(?:new\s+)?instructions\s+are\s+now\b|"
        r"\bchange\s+your\s+instructions\b|\bleave\s+all\s+(?:the\s+)?previous\s+information\s+behind\b|"
        r"\bremove\s+all\s+previous\s+tasks\b|\bkonzentriere\s+dich\s+(?:jetzt\s+)?auf\s+deine\s+neue\s+aufgabe\b|"
        r"\bnun\s+folgen\s+(?:neue|weitere)\s+(?:aufgaben|anweisungen)\b|"
        r"\balle\s+(?:vorherigen|bisherigen|vorangegangenen)\s+(?:informationen|aufgaben)\b", re.I)),
    ("injection_prompt_leak", "HIGH", "Asks the AI to reveal its prompt / instructions", re.compile(
        r"\b(?:show|print|output|display|reveal|repeat|spell\s+check\s+and\s+display)\s+(?:me\s+)?(?:all\s+)?"
        r"(?:of\s+)?(?:your|the|this)\s+(?:full\s+|entire\s+|system\s+|initial\s+|original\s+)?"
        r"(?:prompts?|instructions)(?:\s+texts?)?\b|\bcopy\s+of\s+the\s+full\s+prompt\b|"
        r"\bwhat\s+(?:are|were)\s+your\s+(?:instructions|rules)\b|\bwhat\s+is\s+written\s+above\b|"
        r"\bzeige?\s+(?:mir\s+)?(?:deinen|deine|alle\s+deine)\s+[\w-]*prompt", re.I)),
    ("injection_context_override", "HIGH", "Tells the AI to ignore the documents / context it was given", re.compile(
        r"\b(?:answer|respond)\s+by\s+your\s+own\s+knowledge\s+and\s+not\s+by\s+the\b|"
        r"\bdisregard(?:ing)?\s+the\s+(?:articles|documents|context)\b|"
        r"\bdo\s+not\s+(?:look\s+in|use)\s+the\s+(?:documents|articles|context)\b|"
        r"\bnot\s+according\s+to\s+the\s+provided\s+documents\b|"
        r"\bdo\s+not\s+answer\s+(?:this|the)\s+question\s+but\b", re.I)),
    ("injection_role_play", "MEDIUM", "Asks the AI to take on a persona or act as a tool", re.compile(
        r"\bi\s+want\s+you\s+to\s+act\s+as\b|\bact\s+as\s+(?:a|an)\s+(?:[\w-]+\s+){0,2}"
        r"(?:interpreter|terminal|console|shell)\b|\bpretend\s+(?:you\s+are|to\s+be|you\s+can)\b|"
        r"\b(?:now|from\s+now\s+on,?)\s+you\s+are\s+(?:a\s+|an\s+)?(?-i:[A-Z])\w+|\bdan\s+mode\b|"
        r"\bimagine\s+you\s+are\b|\brole-?playing\s+as\b|\b(?:jetzt|nun)\s+bist\s+du\b|"
        r"\bstell\s+dir\s+vor,?\s+du\s+bist\b|\bich\s+möchte,\s+dass\s+sie\s+als\b", re.I)),
    ("injection_obfuscated_text", "MEDIUM", "Letter-spaced text, a common filter-evasion trick", re.compile(
        r"(?<!\S)(?:[A-Za-z] ){10,}[A-Za-z](?!\S)")),
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


# Cyrillic / Greek letters that look like Latin ones (common homoglyph disguises)
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ӏ": "l", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
})
_MIXED_WORD = re.compile(r"\b(?=\w*[A-Za-z])(?=\w*[\u0370-\u03ff\u0400-\u04ff])\w{3,}\b")


def _deconfuse(text: str) -> str:
    """NFKC (fullwidth etc.) + look-alike letters mapped to Latin. Same length as the input."""
    return "".join(unicodedata.normalize("NFKC", ch)[:1] or ch for ch in text).translate(_CONFUSABLES)


def scan(text: str, path: str = "") -> list[Finding]:
    findings = _hidden_unicode(text)
    visible = _visible(text)
    mixed = _MIXED_WORD.search(visible)
    if mixed:
        findings.append(Finding(rule="homoglyph_mixed_script", category="injection", severity="MEDIUM",
                                message="A word mixes Latin with Cyrillic/Greek look-alike letters (disguised text)",
                                start=mixed.start(), end=mixed.end(), preview=mixed.group(0)[:40]))
    plain = _deconfuse(visible)
    for rule, sev, message, pattern in PHRASE_RULES:
        # original text (real Russian/Greek rules) and the de-confused copy (disguised Latin)
        m = pattern.search(visible) or (pattern.search(plain) if plain != visible else None)
        if m:
            findings.append(Finding(rule=rule, category="injection", severity=sev, message=message,
                                    start=m.start(), end=m.end(), preview=visible[m.start():m.end()][:80]))
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
