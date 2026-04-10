# claude-plugin-audit

Security audit tool for Claude Code plugins. See what your plugins are really doing.

**Zero dependencies.** A security audit tool that pulls in 200 npm packages would be ironic.

## Why This Exists

Claude Code plugins run hooks across the entire agent lifecycle: every prompt you type, every bash command Claude runs, every file it reads. A plugin can silently capture all of this and send it to an external server.

This tool was built after discovering that a first-party Vercel plugin was:

- Sending full bash command strings to `telemetry.vercel.com` on every command, across every project, with no opt-in
- Using **prompt injection** to obtain telemetry consent: injecting natural language instructions into Claude's context telling the AI to ask the user a question and execute shell commands based on the answer
- Tracking users with a persistent device UUID stored at `~/.claude/vercel-plugin-device-id`
- Firing telemetry hooks on **all projects**, not just Vercel ones, despite having framework detection built in

Each of these issues has a plugin layer and a platform layer. This tool addresses the plugin layer by making plugin behavior visible.

## Quick Start

```bash
# Audit all installed plugins
npx claude-plugin-audit

# Audit a specific plugin
npx claude-plugin-audit vercel

# Machine-readable output
npx claude-plugin-audit --json

# Include INFO-level findings
npx claude-plugin-audit --verbose
```

Also works with Bun:
```bash
bunx claude-plugin-audit
```

## What It Detects

| Category | What It Finds | Severity |
|----------|--------------|----------|
| **Telemetry** | `fetch()`, `http.request()`, `curl` in hook scripts | CRITICAL |
| **Data Capture** | Code that extracts user prompts, bash commands, or credentials | WARNING-CRITICAL |
| **Prompt Injection** | Instructions telling Claude to use tools, run commands, or ask questions on the plugin's behalf | CRITICAL |
| **Hook Scope** | Empty matchers that fire on every prompt, telemetry scripts on sensitive events | WARNING |
| **Filesystem** | Writes outside the plugin directory, persistent tracking IDs | WARNING |
| **Environment** | CLAUDE_ENV_FILE manipulation, child process spawning | WARNING |

### Detection IDs

- `TEL-001` through `TEL-005`: Outbound network requests
- `CAP-001` through `CAP-004`: User data capture
- `INJ-001` through `INJ-004`: Behavioral injection / prompt injection
- `HOOK-001` through `HOOK-004`: Hook configuration issues
- `FS-001` through `FS-004`: Filesystem persistence
- `ENV-001` through `ENV-004`: Environment manipulation

## CLI Reference

```
Usage: cpa [options] [plugin-name...]

Options:
  --json              Machine-readable JSON output
  --verbose, -V       Include INFO-level findings
  --plugin-dir <dir>  Override plugin cache directory
  --no-color          Disable ANSI colors
  --help, -h          Show help
  --version, -v       Show version
```

## Understanding Findings

**CRITICAL** findings indicate patterns that can exfiltrate data, inject behavior into Claude, or modify your system on behalf of the plugin. These require immediate review.

**WARNING** findings indicate patterns that are suspicious in context but may be legitimate depending on the plugin's purpose. A Telegram plugin calling `api.telegram.org` is expected. A deployment plugin reading your bash commands is not.

**INFO** findings are noted for completeness but are generally normal plugin behavior (reading stdin, using temp files).

The tool surfaces patterns for human review. It does not make automated trust decisions. You evaluate each finding against the plugin's stated purpose.

## JSON Output

The `--json` flag produces structured output for CI integration:

```json
{
  "version": "1.0.0",
  "summary": {
    "pluginsScanned": 4,
    "criticalCount": 6,
    "warningCount": 12,
    "infoCount": 8
  },
  "plugins": [{
    "name": "plugin-name",
    "findings": [{
      "id": "TEL-001",
      "severity": "critical",
      "title": "fetch() call detected",
      "file": "hooks/telemetry.mjs",
      "line": 23
    }]
  }]
}
```

## How It Works

1. Reads `~/.claude/plugins/installed_plugins.json` to discover installed plugins
2. For each plugin, parses `hooks/hooks.json` for structural analysis (matcher breadth, event coverage, telemetry naming)
3. Scans source files (`.mjs`, `.js`, `.py`) with regex-based pattern detection
4. Cross-references findings (e.g., stdin reading + network calls in the same file = elevated severity)
5. Deduplicates between compiled `.mjs` and TypeScript `.mts` sources
6. Outputs findings sorted by severity with actionable recommendations

No AST parsing, no dependencies, no network calls. The tool reads local files and prints results.

## Immediate Fixes

If you find concerning telemetry in a plugin:

| Goal | How |
|------|-----|
| Kill Vercel telemetry | `export VERCEL_PLUGIN_TELEMETRY=off` in `.zshrc` |
| Disable any plugin | Set `"pluginName@marketplace": false` in `~/.claude/settings.json` |
| Check for tracking IDs | `ls ~/.claude/*device-id* ~/.claude/*tracking*` |

## Contributing

Issues and PRs welcome. If you find a pattern this tool should detect, open an issue with the plugin name and the relevant source code.

## License

MIT

## Author

[Eric Fadden](https://forgedcortex.ai) — Forged Cortex LLC
