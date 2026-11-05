"""Detect secret-like values that appear in tool results, then later elsewhere."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Patterns that look like secrets / credentials when they appear in tool output.
# Kept deliberately pattern-based (offline, no entropy model) so findings are
# explainable and reproducible for CI gates.
SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)(?:aws[_-]?secret(?:_access)?[_-]?key|secretAccessKey)"
            r"""['"\s:=]+([A-Za-z0-9/+=]{40})\b"""
        ),
    ),
    (
        "github_pat",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
    ),
    (
        "github_fine_grained",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "openai_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "stripe_key",
        re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "bearer_token",
        re.compile(
            r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b"
        ),
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|password|passwd|secret)"
            r"""['"\s:=]+([A-Za-z0-9\-._~+/=!@#$%^&*]{12,})"""
        ),
    ),
    (
        "connection_string",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^\s\"']{8,}"
        ),
    ),
]

# Values that match a pattern but are almost certainly placeholders / fixtures.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(xxx+|your[_-]?|example|sample|dummy|fake|test[_-]?|"
    r"placeholder|changeme|redacted|null|none|n/?a|<[^>]+>|\$\{[^}]+\})"
)

MIN_SECRET_LEN = 12


@dataclass
class SecretHit:
    kind: str
    value: str
    source_step: int
    source_role: str
    source_tool: Optional[str] = None


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    kind: str  # result-to-arg | result-to-reply | result-to-memory
    secret_kind: str
    secret_preview: str
    source_step: int
    sink_step: int
    sink_role: str
    sink_tool: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _preview(value: str, keep: int = 6) -> str:
    if len(value) <= keep * 2 + 3:
        return value
    return f"{value[:keep]}…{value[-keep:]}"


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if len(v) < MIN_SECRET_LEN and not v.startswith("-----BEGIN"):
        return True
    if PLACEHOLDER_RE.search(v):
        return True
    # all same char / obvious fake
    if len(set(v.lower().replace("-", "").replace("_", ""))) <= 2:
        return True
    return False


def extract_secrets(text: str) -> List[Tuple[str, str]]:
    """Return list of (kind, value) found in text."""
    if not text:
        return []
    found: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            value = value.strip().strip("\"'")
            if _is_placeholder(value):
                continue
            key = f"{kind}:{value}"
            if key in seen:
                continue
            seen.add(key)
            found.append((kind, value))
    return found


def _message_text(msg: Dict[str, Any]) -> str:
    parts: List[str] = []
    content = msg.get("content")
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
    # tool results sometimes live under "result" / "output"
    for key in ("result", "output", "stdout", "stderr", "body"):
        val = msg.get(key)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, (dict, list)):
            parts.append(json.dumps(val, sort_keys=True))
    args = msg.get("args")
    if args is not None:
        if isinstance(args, str):
            parts.append(args)
        else:
            try:
                parts.append(json.dumps(args, sort_keys=True))
            except TypeError:
                parts.append(str(args))
    return "\n".join(parts)


def _tool_name(msg: Dict[str, Any]) -> Optional[str]:
    for key in ("tool", "name", "tool_name", "function"):
        val = msg.get(key)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, dict) and isinstance(val.get("name"), str):
            return val["name"]
    return None


def _normalize_role(msg: Dict[str, Any]) -> str:
    role = (msg.get("role") or msg.get("type") or "").lower()
    if role in ("tool", "function", "tool_result", "function_result"):
        return "tool"
    if role in ("tool_call", "function_call", "assistant_tool_call"):
        return "tool_call"
    if role in ("assistant", "model", "ai"):
        return "assistant"
    if role in ("system",):
        return "system"
    if role in ("user", "human"):
        return "user"
    if role in ("memory", "journal", "note"):
        return "memory"
    # Heuristic: presence of tool + args without content => tool_call
    if msg.get("args") is not None and _tool_name(msg) and not msg.get("content"):
        return "tool_call"
    if msg.get("tool") and msg.get("content") is not None and msg.get("args") is None:
        return "tool"
    return role or "unknown"


def load_trace(path: str) -> List[Dict[str, Any]]:
    """Load a JSONL file or a JSON array of messages."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("JSON root must be an array of messages")
        return [m for m in data if isinstance(m, dict)]
    messages: List[Dict[str, Any]] = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON on line {i}: {e}") from e
        if isinstance(obj, dict):
            messages.append(obj)
    return messages


def audit(
    messages: Sequence[Dict[str, Any]],
    *,
    ignore_kinds: Optional[Set[str]] = None,
    min_len: int = MIN_SECRET_LEN,
) -> List[Finding]:
    """Scan a transcript for secret echo findings.

    A secret is "born" when it first appears in a tool *result*. Later appearances
    in tool_call arguments, assistant replies, or memory writes are findings.
    Secrets that first appear in user/system prompts are ignored (the agent did
    not learn them from a tool).
    """
    ignore_kinds = ignore_kinds or set()
    known: Dict[str, SecretHit] = {}  # value -> first tool-result hit
    findings: List[Finding] = []

    for step, msg in enumerate(messages):
        role = _normalize_role(msg)
        text = _message_text(msg)
        tool = _tool_name(msg)
        secrets = extract_secrets(text)

        if role == "tool":
            for kind, value in secrets:
                if kind in ignore_kinds:
                    continue
                if len(value) < min_len and not value.startswith("-----BEGIN"):
                    continue
                if value not in known:
                    known[value] = SecretHit(
                        kind=kind,
                        value=value,
                        source_step=step,
                        source_role=role,
                        source_tool=tool,
                    )
            continue

        # Sink roles: where echoing a previously-seen tool-result secret is bad.
        # Match known values as substrings (not only by re-running patterns), so
        # a password that left the vault unlabeled in chat still counts.
        if role in ("tool_call", "assistant", "memory", "user") and known:
            HIGH_KINDS = {
                "aws_access_key",
                "aws_secret_key",
                "github_pat",
                "github_fine_grained",
                "openai_key",
                "private_key_block",
                "stripe_key",
                "connection_string",
            }
            for value, hit in known.items():
                if hit.source_step >= step:
                    continue
                if value not in text:
                    continue
                if role == "tool_call":
                    finding_kind = "result-to-arg"
                    severity = "high"
                    detail = (
                        f"secret from tool result at step {hit.source_step}"
                        f" ({hit.source_tool or 'tool'}) reappears in tool call"
                        f" `{tool or '?'}` args"
                    )
                elif role == "assistant":
                    finding_kind = "result-to-reply"
                    severity = "high" if hit.kind in HIGH_KINDS else "medium"
                    detail = (
                        f"secret from tool result at step {hit.source_step}"
                        f" ({hit.source_tool or 'tool'}) echoed in assistant reply"
                    )
                elif role == "memory":
                    finding_kind = "result-to-memory"
                    severity = "medium"
                    detail = (
                        f"secret from tool result at step {hit.source_step}"
                        f" persisted into a memory/journal write"
                    )
                else:  # user
                    finding_kind = "result-to-reply"
                    severity = "low"
                    detail = (
                        f"secret from tool result at step {hit.source_step}"
                        f" appears again in a user turn"
                    )
                findings.append(
                    Finding(
                        severity=severity,
                        kind=finding_kind,
                        secret_kind=hit.kind,
                        secret_preview=_preview(value),
                        source_step=hit.source_step,
                        sink_step=step,
                        sink_role=role,
                        sink_tool=tool if role == "tool_call" else None,
                        detail=detail,
                    )
                )

    return findings


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def filter_by_fail_on(
    findings: Sequence[Finding], fail_on: str
) -> List[Finding]:
    threshold = SEVERITY_RANK.get(fail_on, 3)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]


def format_text(
    messages: Sequence[Dict[str, Any]], findings: Sequence[Finding]
) -> str:
    lines = [
        f"secrecho: {len(messages)} messages, {len(findings)} finding(s)",
    ]
    if not findings:
        lines.append("clean: no tool-result secrets echoed into later args or replies")
        return "\n".join(lines)
    for f in findings:
        tool_bit = f" tool=`{f.sink_tool}`" if f.sink_tool else ""
        lines.append(
            f"[{f.severity.upper()}] {f.kind} {f.secret_kind} "
            f"{f.secret_preview} step {f.source_step} -> {f.sink_step}"
            f" ({f.sink_role}{tool_bit})"
        )
        if f.detail:
            lines.append(f"    {f.detail}")
    return "\n".join(lines)


def format_md(
    messages: Sequence[Dict[str, Any]], findings: Sequence[Finding]
) -> str:
    lines = [
        f"# secrecho report",
        "",
        f"- messages: {len(messages)}",
        f"- findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No tool-result secrets echoed into later args or replies.")
        return "\n".join(lines)
    lines += [
        "| severity | kind | secret | from | to | sink |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        sink = f.sink_tool or f.sink_role
        lines.append(
            f"| {f.severity} | {f.kind} | `{f.secret_kind}` `{f.secret_preview}` "
            f"| {f.source_step} | {f.sink_step} | {sink} |"
        )
        if f.detail:
            lines.append(f"|  |  | _{f.detail}_ |  |  |  |")
    return "\n".join(lines)


def format_json(
    messages: Sequence[Dict[str, Any]], findings: Sequence[Finding]
) -> str:
    payload = {
        "tool": "secrecho",
        "messages": len(messages),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
