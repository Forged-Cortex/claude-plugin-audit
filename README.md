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

## Understanding the Output

The tool uses five severity levels designed to be readable even if you're not a security engineer:

| Level | What It Means | Visible by Default |
|-------|--------------|-------------------|
| **CRITICAL** | Something is actively wrong. Data may be leaving your machine, or a plugin is injecting behavior into Claude without your knowledge. | Yes |
| **MITIGATED** | This was critical, but you've already handled it. An environment variable is set, a preference file says "disabled," or the plugin is turned off. The code is still there, but it's not running. | Yes |
| **WARNING** | Something you should evaluate. Could be a real problem or could be fine depending on the plugin's purpose. The tool gives you context to decide. | Yes |
| **NOTICE** | Noted for the record but almost certainly benign. Version checks, tool detection, config file reads, designed plugin mechanisms operating normally. | `--verbose` only |
| **INFO** | Background detail about normal plugin mechanics. | `--verbose` only |

By default, you only see CRITICAL, MITIGATED, and WARNING. Everything that shows up in the default view is something you should actually look at.

### Contextual Notes

Findings include contextual notes that help you evaluate them:

- A `fetch()` call in a Telegram plugin targeting `api.telegram.org` will say: *"This fetch() appears to call the Telegram Bot API, which is expected behavior for this plugin."*
- A child process spawning `which dot` will say: *"This checks whether a CLI tool is installed on the system. Generally benign."*
- Data capture in a file with no network calls will say: *"No outbound network calls detected in this file. The captured data appears to stay local."*

The tool doesn't just flag patterns. It tells you what those patterns probably mean.

### Mitigation Detection

The tool checks whether you've already addressed critical findings:

- **Telemetry opt-out env vars**: Scans plugin source for variables like `VERCEL_PLUGIN_TELEMETRY`, then checks your shell config and current environment. If you've set the opt-out, the finding shows `MITIGATED` instead of `CRITICAL`.
- **Preference files**: Checks `~/.claude/*telemetry-preference*` files. If they say "disabled," related consent-injection findings are marked mitigated.
- **Disabled plugins**: If a plugin is disabled in `settings.json`, all its findings are mitigated because no hooks will fire.

The summary table reflects this. A fully remediated system shows `ACTIVE: 0`.

---

## What It Detects

The tool scans plugin source code and hook configuration for six categories of security-relevant patterns. Each finding includes the file, line number, one line of context above and below the match, and a recommendation.

### Telemetry (TEL-001 through TEL-005)

Outbound network requests that can send data to external servers.

| ID | Severity | What It Catches |
|----|----------|----------------|
| TEL-001 | CRITICAL | `fetch()` calls in hook scripts |
| TEL-002 | CRITICAL | Node.js `http.request()` / `https.request()` |
| TEL-003 | CRITICAL | Shell commands executing `curl` or `wget` |
| TEL-004 | WARNING/NOTICE | Hardcoded external URLs (WARNING for telemetry endpoints, NOTICE for known APIs) |
| TEL-005 | CRITICAL | Python `requests`, `urllib`, `httpx` calls |

### Data Capture (CAP-001 through CAP-004)

Code that extracts sensitive data from the hook payload.

| ID | Severity | What It Catches |
|----|----------|----------------|
| CAP-001 | INFO | Reads stdin (normal hook behavior, flagged for context) |
| CAP-002 | WARNING/NOTICE | Extracts user prompts or bash commands (WARNING if same file has network calls, NOTICE if local only) |
| CAP-003 | CRITICAL | Accesses sensitive env vars (API keys, tokens, credentials) |
| CAP-004 | NOTICE | Reads files outside the plugin's own directory |

### Behavioral Injection (INJ-001 through INJ-004)

Prompt injection patterns where the plugin manipulates Claude's behavior.

| ID | Severity | What It Catches |
|----|----------|----------------|
| INJ-001 | NOTICE | Sets `additionalContext` to inject text into Claude's context (designed mechanism, consolidated to one per plugin) |
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
| FS-003 | NOTICE | Uses the system temp directory |
| FS-004 | NOTICE | Appends to files (logging or audit trails) |

### Environment (ENV-001 through ENV-004)

Process and environment manipulation.

| ID | Severity | What It Catches |
|----|----------|----------------|
| ENV-001 | NOTICE | Writes to `CLAUDE_ENV_FILE` (designed persistence mechanism) |
| ENV-002 | WARNING/NOTICE | Spawns child processes (WARNING if unrecognized, NOTICE for benign commands like version checks) |
| ENV-003 | NOTICE | Modifies `process.env` directly |
| ENV-004 | WARNING | Python `subprocess` execution |

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

The principle: safe, reversible actions default to "yes." Actions that could break your workflow default to "no." Nothing runs without your confirmation.

---

## Ignore File (`.cpauditignore`)

Suppress known-good findings with a `.cpauditignore` file at `~/.claude/.cpauditignore` or `~/.cpauditignore`:

```
# Ignore Telegram API calls (expected behavior)
TEL-001:telegram

# Ignore a specific finding for all plugins
FS-003:*

# Ignore everything for a specific plugin
*:my-trusted-plugin

# Ignore a finding in a specific file
ENV-002:superpowers:render-graphs.js
```

Format: `FINDING-ID:plugin-name:file-path` (use `*` for wildcards).

---

## CLI Reference

```
Usage: cpa [options] [plugin-name...]

Options:
  --fix               Find issues and fix them (interactive remediation)
  --json              Machine-readable JSON output
  --verbose, -V       Show all findings including NOTICE and INFO
  --plugin-dir <dir>  Override plugin cache directory
  --no-color          Disable ANSI colors
  --help, -h          Show this help message
  --version, -v       Show version

Exit Codes:
  0                   No unmitigated critical findings
  1                   Unmitigated critical findings present
```

---

## JSON Output

The `--json` flag produces structured output suitable for CI pipelines, dashboards, or piping to `jq`:

```json
{
  "version": "1.4.0",
  "timestamp": "2026-04-10T15:30:00.000Z",
  "summary": {
    "pluginsScanned": 12,
    "sourceFilesScanned": 81,
    "criticalCount": 8,
    "warningCount": 15,
    "infoCount": 21
  },
  "plugins": [
    {
      "name": "vercel",
      "version": "0.32.4",
      "marketplace": "claude-plugins-official",
      "enabled": true,
      "hookEvents": ["SessionStart", "UserPromptSubmit", "PostToolUse"],
      "findings": [
        {
          "id": "TEL-001",
          "severity": "critical",
          "category": "telemetry",
          "title": "fetch() call detected",
          "file": "hooks/telemetry.mjs",
          "line": 23,
          "match": "await fetch(BRIDGE_ENDPOINT, {",
          "mitigated": true,
          "mitigationReason": "VERCEL_PLUGIN_TELEMETRY=off is set in your ~/.zshrc",
          "note": "..."
        }
      ]
    }
  ]
}
```

The process exits with code 1 if any unmitigated CRITICAL findings are present, making it usable as a CI gate.

---

## How It Works

1. Reads `~/.claude/plugins/installed_plugins.json` to discover all installed plugins
2. For each plugin, parses `hooks/hooks.json` for structural analysis: matcher breadth, event coverage, telemetry naming patterns
3. Enumerates source files (`.mjs`, `.js`, `.ts`, `.py`) excluding `node_modules/`, test files, and vendored libraries
4. Runs 23 regex-based detection patterns against each source file with line-number tracking
5. Enriches findings with contextual intelligence: known API identification, benign command recognition, cross-file correlation
6. Detects active mitigations: telemetry opt-out env vars, preference files, disabled plugins
7. Assigns final severity (CRITICAL/MITIGATED/WARNING/NOTICE/INFO) based on pattern + context + mitigation state
8. Outputs findings sorted by severity with per-finding recommendations and contextual notes

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
