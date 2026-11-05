# secrecho

Agents pull secrets out of vaults, config APIs, and shell output all the time. The dangerous part is what happens next: the same value shows up again in a later tool-call argument, an assistant reply the user can see, or a memory write that sticks around.

`secrecho` is an offline stdlib Python CLI that reads an agent transcript, records secret-like values the first time they appear in a **tool result**, and flags every later echo into tool args, user-facing replies, or memory/journal turns.

## What's new here

Most secret scanners look at a single blob (a repo, a log file) and ask "is there a secret here?". secrecho asks a different question about **agent runs**:

- **Provenance gate**: a value only becomes tracked when it first appears in a tool *result*. Secrets the user already typed into the prompt are ignored, so you do not get noise from "here is my token, please use it".
- **Cross-turn echo kinds**:
  - `result-to-arg` — the secret is pasted into a later tool call (credential reuse / lateral movement smell)
  - `result-to-reply` — the assistant (or user) message repeats it in the open
  - `result-to-memory` — it is persisted into a memory/journal write
- **Pattern set tuned for agent traces**: GitHub PATs, OpenAI keys, Slack/Stripe tokens, JWTs, Bearer headers, AWS keys, PEM private keys, labeled `password=` / `api_key=` values, and DB connection strings.
- **Placeholder filter**: `changeme`, `YOUR_API_KEY`, `${SECRET}`, and similar fixtures are dropped.
- **CI gate**: `--fail-on high|medium|low|info` with text / json / md output.

Severity: `high` for result-to-arg and for replies that echo high-impact kinds (PATs, cloud keys, private keys, connection strings); `medium` for other reply echoes and memory writes; `low` when a tool-born secret reappears in a later user turn.

## Install

```bash
pip install git+https://github.com/rashedhasan090/secrecho
# or, no install
git clone https://github.com/rashedhasan090/secrecho && cd secrecho && python3 -m secrecho --help
```

Pure Python standard library, 3.8+.

## Usage

```bash
secrecho trace.jsonl
secrecho trace.jsonl --format json
secrecho trace.jsonl --format md --fail-on high   # CI gate
secrecho trace.jsonl --ignore-kind jwt --min-len 16
```

Trace format: JSONL (or one JSON array), one message per line.

```json
{"role": "tool_call", "tool": "secrets_get", "args": {"path": "staging/db"}}
{"role": "tool", "tool": "secrets_get", "content": "password=StgDb_Rotate9xQ2mL7p"}
{"role": "assistant", "content": "Got password StgDb_Rotate9xQ2mL7p"}
{"role": "tool_call", "tool": "http_request", "args": {"body": {"db_password": "StgDb_Rotate9xQ2mL7p"}}}
```

Supported roles: `system`, `user`, `assistant`, `tool` / `tool_result`, `tool_call`, `memory` / `journal`. Tool name may live in `tool`, `name`, or `tool_name`. Arguments may be an object under `args` or serialized into `content`.

## Demo

`examples/leak_trace.jsonl` is a staging deploy where a vault read leaks into chat, an HTTP config update, a shell export, and a memory note.

```
$ python3 -m secrecho examples/leak_trace.jsonl
secrecho: 9 messages, 4 finding(s)
[MEDIUM] result-to-reply generic_api_key StgDb_…Q2mL7p step 3 -> 4 (assistant)
    secret from tool result at step 3 (secrets_get) echoed in assistant reply
[HIGH] result-to-arg generic_api_key StgDb_…Q2mL7p step 3 -> 5 (tool_call tool=`http_request`)
    secret from tool result at step 3 (secrets_get) reappears in tool call `http_request` args
[HIGH] result-to-arg github_pat ghp_ab…89ABCD step 6 -> 7 (tool_call tool=`shell`)
    secret from tool result at step 6 (http_request) reappears in tool call `shell` args
[MEDIUM] result-to-memory github_pat ghp_ab…89ABCD step 6 -> 8 (memory)
    secret from tool result at step 6 (http_request) persisted into a memory/journal write
```

`examples/clean_trace.jsonl` has no secrets and exits 0 under `--fail-on low`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limits

Pattern matching is a heuristic: short or unusual secrets can be missed, and high-entropy blobs without a recognizable shape are not scored. It audits recorded traces; it does not hook a live agent or redact anything in place.

## License

MIT
