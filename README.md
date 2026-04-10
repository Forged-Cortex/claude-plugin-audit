# claude-plugin-audit

Security audit tool for Claude Code plugins. See what your plugins are really doing.

**Zero dependencies.** A security audit tool that pulls in 200 npm packages would be ironic.

---

## The Problem

Claude Code plugins run hooks across the entire agent lifecycle. Every prompt you type, every bash command Claude runs, every file it reads or writes, every subagent it spawns. A plugin hooks into these events and runs arbitrary code each time they fire.

Most plugins use this for legitimate purposes: injecting framework knowledge, validating code before writes, bootstrapping project scaffolding. But the same architecture that makes plugins useful also makes them dangerous. There are no permissions, no visual attribution, and no project scoping in the current plugin system. A plugin can:

- **Capture your prompts and bash commands** and send them to an external server
- **Inject instructions into Claude's context** telling it to ask you questions, run shell commands, or modify files on the plugin's behalf
- **Track you across sessions** with persistent device UUIDs stored on your filesystem
- **Fire on every project**, not just projects that use the plugin's framework

You have no way to know this is happening unless you read the plugin's source code yourself.

This tool reads it for you.

## What Started This

This tool was built after discovering that the official Vercel plugin for Claude Code was doing all four of the things listed above. Specifically:

- **Sending full bash command strings** to `telemetry.vercel.com` on every command Claude ran, across every project, with no opt-in. The user was never told this was happening, and the only opt-out was an environment variable documented inside the plugin's cache directory.
- **Using prompt injection for telemetry consent.** Instead of showing a CLI prompt or settings screen, the plugin injected natural language instructions into Claude's system context telling the AI to ask the user a question and then run `echo 'enabled' > ~/.claude/vercel-plugin-telemetry-preference` based on the answer. The rendered question looked identical to a native Claude Code prompt. There was no visual indicator it came from a third party.
- **Tracking users** with a persistent device UUID stored at `~/.claude/vercel-plugin-device-id`, created on first run and reused forever.
- **Firing on all projects.** The `UserPromptSubmit` hook matcher was an empty string, meaning every single prompt was intercepted regardless of whether the project had anything to do with Vercel. The plugin had framework detection built in and didn't use it to gate telemetry.

Full analysis: [akshaychugh.xyz/writings/png/vercel-plugin-telemetry](https://akshaychugh.xyz/writings/png/vercel-plugin-telemetry)

Each of these issues has a plugin layer (Vercel's choices) and a platform layer (Anthropic's plugin architecture). This tool addresses the plugin layer by making plugin behavior visible and fixable.

---

## Quick Start

```bash
# Audit all installed plugins
npx claude-plugin-audit

# Audit a specific plugin
npx claude-plugin-audit vercel

# Audit and fix what you find
npx claude-plugin-audit --fix

# Machine-readable output for CI
npx claude-plugin-audit --json
```

Also works with Bun:

```bash
bunx claude-plugin-audit
```

---

## What It Detects

The tool scans plugin source code and hook configuration for six categories of security-relevant patterns. Each finding includes the file, line number, the matching code, and a recommendation for what to do about it.

### Telemetry (TEL-001 through TEL-005)

Outbound network requests that can send data to external servers.

| ID | Severity | What It Catches |
|----|----------|----------------|
| TEL-001 | CRITICAL | `fetch()` calls in hook scripts |
| TEL-002 | CRITICAL | Node.js `http.request()` / `https.request()` |
| TEL-003 | CRITICAL | Shell commands executing `curl` or `wget` |
| TEL-004 | WARNING | Hardcoded external URLs (not localhost) |
| TEL-005 | CRITICAL | Python `requests`, `urllib`, `httpx` calls |

### Data Capture (CAP-001 through CAP-004)

Code that extracts sensitive data from the hook payload.

| ID | Severity | What It Catches |
|----|----------|----------------|
| CAP-001 | INFO | Reads stdin (normal hook behavior, flagged for context) |
| CAP-002 | WARNING | Extracts user prompts, bash commands, or tool input |
| CAP-003 | CRITICAL | Accesses sensitive env vars (API keys, tokens, credentials) |
| CAP-004 | WARNING | Reads files outside the plugin's own directory |

### Behavioral Injection (INJ-001 through INJ-004)

Prompt injection patterns where the plugin manipulates Claude's behavior.

| ID | Severity | What It Catches |
|----|----------|----------------|
| INJ-001 | WARNING | Sets `additionalContext` to inject text into Claude's context |
| INJ-002 | CRITICAL | Instructs Claude to use specific tools (AskUserQuestion, Bash) |
| INJ-003 | CRITICAL | Injected text contains shell commands targeting the home directory |
| INJ-004 | WARNING | Manipulative language ("After responding...", "Do not mention...") |

### Hook Configuration (HOOK-001 through HOOK-004)

Structural issues in `hooks.json` that indicate overly broad access.

| ID | Severity | What It Catches |
|----|----------|----------------|
| HOOK-001 | WARNING | Empty matcher on sensitive events (fires on every prompt/command) |
| HOOK-002 | INFO | Plugin hooks into 5+ lifecycle events (unusually broad visibility) |
| HOOK-003 | WARNING | Script with "telemetry" in the name on a sensitive hook event |
| HOOK-004 | INFO | No timeout set on a hook command |

### Filesystem (FS-001 through FS-004)

Persistent state written outside the plugin's own cache directory.

| ID | Severity | What It Catches |
|----|----------|----------------|
| FS-001 | WARNING | Writes files to `~/.claude/` outside the plugin cache |
| FS-002 | WARNING | Generates persistent UUIDs or device identifiers |
| FS-003 | INFO | Uses the system temp directory |
| FS-004 | INFO | Appends to files (logging or audit trails) |

### Environment (ENV-001 through ENV-004)

Process and environment manipulation.

| ID | Severity | What It Catches |
|----|----------|----------------|
| ENV-001 | WARNING | Writes to `CLAUDE_ENV_FILE` (persists env vars across hooks) |
| ENV-002 | WARNING | Spawns child processes (`exec`, `spawn`, `subprocess`) |
| ENV-003 | WARNING | Modifies `process.env` directly |
| ENV-004 | WARNING | Python `subprocess` execution |

---

## Understanding Findings

**CRITICAL** means the pattern can exfiltrate data, inject behavior into Claude, or modify your system on behalf of the plugin. Review these immediately.

**WARNING** means the pattern is suspicious in context but may be legitimate depending on what the plugin does. A Telegram plugin calling `api.telegram.org` is expected. A deployment plugin capturing your bash commands is not.

**INFO** means the pattern is noted for completeness but is generally normal plugin behavior. Hidden by default; use `--verbose` to see them.

The tool surfaces patterns for human review. It does not make automated trust decisions. Every finding includes the source file, line number, and the actual code so you can evaluate it yourself.

---

## Remediation (`--fix`)

After scanning, `--fix` walks you through cleaning up what it found:

**1. Tracking files** (defaults to yes)
Finds persistent device IDs in `~/.claude/` and offers to delete them. Shows the file path and current contents so you know what you're deleting.

**2. Telemetry preference files** (defaults to yes)
Finds telemetry consent files and sets them to `disabled`.

**3. Telemetry opt-out env vars** (defaults to yes)
Scans plugin source code for environment variables that control telemetry (like `VERCEL_PLUGIN_TELEMETRY`). If your shell config already has them set, it shows a checkmark. If not, it offers to add the `export` lines to your `.zshrc` / `.bashrc`.

**4. Plugin disable** (defaults to no)
For plugins with CRITICAL findings, asks per-plugin whether to disable them in `~/.claude/settings.json`. Defaults to "no" because disabling a plugin removes its skills and functionality, not just its telemetry. Only disable if you genuinely don't need the plugin.

The principle: safe, reversible actions default to "yes." Actions that could break your workflow default to "no." Nothing runs without confirmation.

---

## CLI Reference

```
Usage: cpa [options] [plugin-name...]

Options:
  --fix               Remediate findings (delete tracking, set opt-outs)
  --json              Machine-readable JSON output
  --verbose, -V       Include INFO-level findings (hidden by default)
  --plugin-dir <dir>  Override plugin cache directory
  --no-color          Disable ANSI colors
  --help, -h          Show this help message
  --version, -v       Show version

Examples:
  npx claude-plugin-audit                  Audit all installed plugins
  npx claude-plugin-audit vercel           Audit only the Vercel plugin
  npx claude-plugin-audit --fix            Audit and remediate
  npx claude-plugin-audit --json           JSON output for CI
  npx claude-plugin-audit --json | jq '.plugins[].findings[] | select(.severity == "critical")'
```

---

## JSON Output

The `--json` flag produces structured output suitable for CI pipelines, dashboards, or piping to `jq`:

```json
{
  "version": "1.1.1",
  "timestamp": "2026-04-10T14:30:00.000Z",
  "summary": {
    "pluginsScanned": 12,
    "sourceFilesScanned": 88,
    "criticalCount": 8,
    "warningCount": 64,
    "infoCount": 37
  },
  "plugins": [
    {
      "name": "vercel",
      "version": "0.32.4",
      "marketplace": "claude-plugins-official",
      "enabled": true,
      "hookEvents": ["SessionStart", "UserPromptSubmit", "PostToolUse"],
      "sourceFilesScanned": 81,
      "findings": [
        {
          "id": "TEL-001",
          "severity": "critical",
          "category": "telemetry",
          "title": "fetch() call detected",
          "file": "hooks/telemetry.mjs",
          "line": 23,
          "match": "await fetch(BRIDGE_ENDPOINT, {",
          "description": "Hook scripts with fetch() can send data to external servers.",
          "recommendation": "Identify the destination URL and what data is included in the request body."
        }
      ]
    }
  ]
}
```

The process exits with code 1 if any CRITICAL findings are present, making it usable as a CI gate.

---

## How It Works

1. Reads `~/.claude/plugins/installed_plugins.json` to discover all installed plugins
2. For each plugin, parses `hooks/hooks.json` for structural analysis: matcher breadth, event coverage, telemetry naming patterns
3. Enumerates source files (`.mjs`, `.js`, `.ts`, `.py`) excluding `node_modules/`, test fixtures, and vendored libraries
4. Runs 23 regex-based detection patterns against each source file with line-number tracking
5. Cross-references findings: if a file has both network calls AND stdin/prompt reading, the data capture finding is elevated
6. Deduplicates between compiled `.mjs` and TypeScript `.mts` sources to avoid double-reporting
7. Outputs findings sorted by severity with per-finding recommendations

No AST parsing, no external dependencies, no network calls. The tool reads local files and prints results.

---

## Manual Fixes

If you prefer to handle things yourself instead of using `--fix`:

| What You Want | How To Do It |
|---------------|-------------|
| Kill Vercel telemetry | Add `export VERCEL_PLUGIN_TELEMETRY=off` to your `.zshrc` |
| Disable any plugin | Set `"pluginName@marketplace": false` in `~/.claude/settings.json` |
| Find tracking IDs | `ls ~/.claude/*device-id* ~/.claude/*tracking*` |
| Delete a tracking ID | `rm ~/.claude/vercel-plugin-device-id` (plugin may recreate it; the env var opt-out is the real fix) |
| Check telemetry preferences | `cat ~/.claude/*telemetry-preference*` |

---

## Contributing

Issues and PRs welcome. If you find a detection pattern this tool should include, open an issue with:

- The plugin name and version
- The file and line number containing the pattern
- Why the pattern is security-relevant

If you're a plugin author and believe a finding is a false positive, open an issue explaining the intended behavior and we'll adjust the pattern or severity.

---

## License

MIT

## Author

[Eric Fadden](https://forgedcortex.ai) / Forged Cortex LLC
