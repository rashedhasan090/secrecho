import json
import os
import tempfile
import unittest
from pathlib import Path

from secrecho.detect import (
    audit,
    extract_secrets,
    filter_by_fail_on,
    format_json,
    format_text,
    load_trace,
)
from secrecho.cli import main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class ExtractTests(unittest.TestCase):
    def test_github_pat(self):
        hits = extract_secrets("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD")
        kinds = {k for k, _ in hits}
        self.assertIn("github_pat", kinds)

    def test_openai_key(self):
        hits = extract_secrets("sk-proj-abcdefghijklmnopqrstuvwxyz012345")
        self.assertTrue(any(k == "openai_key" for k, _ in hits))

    def test_password_labeled(self):
        hits = extract_secrets("password=StgDb_Rotate9xQ2mL7p")
        self.assertTrue(any(k == "generic_api_key" and "StgDb" in v for k, v in hits))

    def test_placeholder_skipped(self):
        hits = extract_secrets("password=changeme_please_now api_key=YOUR_API_KEY_HERE")
        self.assertEqual(hits, [])

    def test_aws_access_key(self):
        hits = extract_secrets("AKIAIOSFODNN7EXAMPLZ")
        self.assertTrue(any(k == "aws_access_key" for k, _ in hits))


class AuditTests(unittest.TestCase):
    def test_leak_trace_findings(self):
        msgs = load_trace(str(EXAMPLES / "leak_trace.jsonl"))
        findings = audit(msgs)
        kinds = {f.kind for f in findings}
        self.assertIn("result-to-reply", kinds)
        self.assertIn("result-to-arg", kinds)
        self.assertIn("result-to-memory", kinds)
        # password echoed to assistant + http_request args
        pwd = [f for f in findings if "StgDb" in f.secret_preview or f.secret_kind == "generic_api_key"]
        self.assertGreaterEqual(len(pwd), 2)
        # github pat echoed to shell + memory
        pats = [f for f in findings if f.secret_kind == "github_pat"]
        self.assertGreaterEqual(len(pats), 2)
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_clean_trace(self):
        msgs = load_trace(str(EXAMPLES / "clean_trace.jsonl"))
        findings = audit(msgs)
        self.assertEqual(findings, [])

    def test_secret_only_in_user_not_tracked(self):
        msgs = [
            {"role": "user", "content": "use ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
            {"role": "tool_call", "tool": "shell", "args": {"cmd": "echo ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"}},
        ]
        findings = audit(msgs)
        self.assertEqual(findings, [])

    def test_ignore_kind(self):
        msgs = load_trace(str(EXAMPLES / "leak_trace.jsonl"))
        findings = audit(msgs, ignore_kinds={"github_pat"})
        self.assertFalse(any(f.secret_kind == "github_pat" for f in findings))

    def test_json_array_load(self):
        data = [
            {"role": "tool", "tool": "x", "content": "api_key=abcdef1234567890zz"},
            {"role": "assistant", "content": "key is abcdef1234567890zz"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            msgs = load_trace(path)
            findings = audit(msgs)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].kind, "result-to-reply")
        finally:
            os.unlink(path)


class FormatAndCliTests(unittest.TestCase):
    def test_format_text_clean(self):
        text = format_text([], [])
        self.assertIn("0 finding", text)

    def test_format_json(self):
        msgs = load_trace(str(EXAMPLES / "leak_trace.jsonl"))
        findings = audit(msgs)
        payload = json.loads(format_json(msgs, findings))
        self.assertEqual(payload["tool"], "secrecho")
        self.assertGreater(len(payload["findings"]), 0)

    def test_fail_on(self):
        msgs = load_trace(str(EXAMPLES / "leak_trace.jsonl"))
        findings = audit(msgs)
        gated = filter_by_fail_on(findings, "high")
        self.assertTrue(gated)
        self.assertTrue(all(f.severity == "high" for f in gated))

    def test_cli_leak_exit(self):
        code = main([str(EXAMPLES / "leak_trace.jsonl"), "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_cli_clean_exit(self):
        code = main([str(EXAMPLES / "clean_trace.jsonl"), "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_cli_json(self):
        # smoke: does not raise
        code = main([str(EXAMPLES / "clean_trace.jsonl"), "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
