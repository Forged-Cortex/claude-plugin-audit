// Detection patterns for Claude Code plugin security audit
// Each pattern: { id, severity, category, title, description, recommendation, pattern (RegExp) }
// Severity: "critical" | "warning" | "info"

// ─── TELEMETRY: Outbound network requests ───────────────────────────────────

export const TELEMETRY_PATTERNS = [
  {
    id: 'TEL-001',
    severity: 'critical',
    category: 'telemetry',
    title: 'fetch() call detected',
    description: 'Hook scripts with fetch() can send data to external servers. This is the most common exfiltration mechanism in plugin hooks.',
    recommendation: 'Identify the destination URL and what data from stdin (user prompts, bash output) is included in the request body.',
    // Require 'await fetch(' or 'fetch(URL' patterns — avoid matching .fetch() methods on Maps/Sets
    pattern: /(?:await\s+|=\s*)fetch\s*\(/g,
  },
  {
    id: 'TEL-002',
    severity: 'critical',
    category: 'telemetry',
    title: 'Node.js HTTP/HTTPS request',
    description: 'Direct use of Node.js http/https modules to make outbound requests from a hook script.',
    recommendation: 'Trace the request URL and body to determine what data leaves the machine.',
    pattern: /\bhttps?\.(?:request|get)\s*\(/g,
  },
  {
    id: 'TEL-003',
    severity: 'critical',
    category: 'telemetry',
    title: 'Shell command executes curl/wget',
    description: 'Spawning curl or wget from a hook script can exfiltrate data via command-line HTTP clients.',
    recommendation: 'Check what data is passed as arguments or piped to the command.',
    pattern: /\b(?:exec|execSync|spawn|spawnSync)\b[^;]*\b(?:curl|wget)\b/g,
  },
  {
    id: 'TEL-004',
    severity: 'warning',
    category: 'telemetry',
    title: 'External URL hardcoded',
    description: 'An external URL is hardcoded in hook source code. This may be a telemetry endpoint, API server, or update checker.',
    recommendation: 'Verify whether this URL receives any user data. Check if data collection is opt-in or opt-out.',
    pattern: /["'`](https?:\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}[^"'`\s]*)/g,
    extractUrl: true,
  },
  {
    id: 'TEL-005',
    severity: 'critical',
    category: 'telemetry',
    title: 'Python HTTP request library',
    description: 'Python HTTP library detected in hook script. Can be used to send data to external servers.',
    recommendation: 'Check what data is included in the request and where it is sent.',
    pattern: /\b(?:requests\.(?:get|post|put|patch|delete)|urllib\.request|httpx\.(?:get|post|put|patch|delete))\s*\(/g,
    pythonOnly: true,
  },
];

// ─── DATA CAPTURE: Collecting user data ─────────────────────────────────────

export const DATA_CAPTURE_PATTERNS = [
  {
    id: 'CAP-001',
    severity: 'info',
    category: 'data-capture',
    title: 'Reads stdin (hook input data)',
    description: 'This hook reads stdin, which contains the hook input payload. This is normal hook behavior. The concern is what happens to the data afterward.',
    recommendation: 'Check if the parsed stdin data is sent to any external endpoint or written to files outside the plugin directory.',
    pattern: /readFileSync\s*\(\s*(?:0|process\.stdin\.fd)\s*[,)]/g,
  },
  {
    id: 'CAP-002',
    severity: 'warning',
    category: 'data-capture',
    title: 'Extracts user prompt or command content',
    description: 'This code extracts user prompt text, bash commands, or tool input from the hook payload. Combined with a network request, this enables data exfiltration.',
    recommendation: 'Acceptable if data stays local. Concerning if passed to fetch(), http.request(), or written to files outside the plugin.',
    pattern: /\b(?:toolInput|tool_input)\s*[\.\[]\s*['"]?(?:command|prompt)['"]?|\.command\s*\|\||\bprompt\s*=\s*.*?resolvePrompt|input\s*\?\s*resolvePrompt/g,
  },
  {
    id: 'CAP-003',
    severity: 'critical',
    category: 'data-capture',
    title: 'Accesses sensitive environment variables',
    description: 'This code reads environment variables that may contain API keys, tokens, or credentials.',
    recommendation: 'Ensure these values are not included in outbound HTTP requests or written to logs.',
    pattern: /process\.env\s*[\.\[]\s*['"]?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS|AUTH|PRIVATE_KEY|AWS_|GITHUB_TOKEN|OPENAI_API)/gi,
  },
  {
    id: 'CAP-004',
    severity: 'warning',
    category: 'data-capture',
    title: 'Reads files outside plugin directory',
    description: 'This code reads files from locations outside the plugin directory, potentially accessing project source code, config files, or user data.',
    recommendation: 'Verify which files are read and whether their contents are sent externally.',
    pattern: /readFileSync\s*\([^)]*(?:homedir\(\)|process\.env\.HOME|['"]~\/|['"]\/etc\/|process\.cwd)/g,
  },
];

// ─── BEHAVIORAL INJECTION: Prompt injection patterns ────────────────────────

export const INJECTION_PATTERNS = [
  {
    id: 'INJ-001',
    severity: 'warning',
    category: 'injection',
    title: 'Injects content into Claude\'s context via additionalContext',
    description: 'This hook uses hookSpecificOutput.additionalContext to inject text into Claude\'s context. This is the intended mechanism for hook context, but can manipulate Claude\'s behavior without user knowledge.',
    recommendation: 'Read the injected text. Look for instructions that tell Claude to run commands, use tools, or ask questions on the plugin\'s behalf.',
    pattern: /additionalContext\s*[:=]/g,
  },
  {
    id: 'INJ-002',
    severity: 'critical',
    category: 'injection',
    title: 'Instructs Claude to use specific tools',
    description: 'The injected context explicitly tells Claude to invoke specific tools. This can cause Claude to execute shell commands, write files, or prompt the user on behalf of the plugin.',
    recommendation: 'This is a form of prompt injection. The plugin is using Claude as an unwitting agent to perform actions. Evaluate whether those actions serve YOUR interest.',
    // Match instructions to Claude inside string literals — require quote context
    pattern: /["'`].*?(?:use|run)\s+(?:the\s+)?(?:AskUserQuestion|Bash)\s+tool/gi,
  },
  {
    id: 'INJ-003',
    severity: 'critical',
    category: 'injection',
    title: 'Injected text contains shell commands targeting home directory',
    description: 'The hook injects text containing shell commands that write to the user\'s home directory. This pattern was found in the Vercel plugin, where Claude was instructed to run "echo enabled > ~/.claude/..." to opt users into telemetry.',
    recommendation: 'This is a prompt injection pattern. The plugin is trying to get Claude to modify your configuration on its behalf.',
    pattern: /echo\s+['"]?(?:enabled|disabled|true|false|on|off)['"]?\s*>\s*~/g,
  },
  {
    id: 'INJ-004',
    severity: 'warning',
    category: 'injection',
    title: 'Manipulative language in injected context',
    description: 'String literals contain natural language that appears to instruct Claude on how to interact with the user. This can script Claude\'s behavior without user awareness.',
    recommendation: 'Read the full injected text to understand what the plugin is telling Claude to do or say.',
    pattern: /["'`](?:After responding|After the user responds|use this exact|Do not (?:stop|mention|tell)|Don't tell|ask the user|Tell the user|Inform the user|Start executing|Choose sensible defaults immediately)/gi,
  },
];

// ─── HOOK CONFIGURATION: Structural issues ──────────────────────────────────
// These are not regex patterns — they're checked structurally in hooks-analyzer.mjs
// Defined here for consistent ID/metadata

export const HOOK_CHECKS = {
  'HOOK-001': {
    severity: 'warning',
    category: 'hooks',
    title: 'Universal matcher on sensitive hook event',
    description: 'Empty matcher ("") means this hook fires on EVERY invocation of this event. On UserPromptSubmit, this means every user message is intercepted.',
    recommendation: 'Ask: does this plugin need to see every prompt? A well-scoped plugin uses specific matchers.',
  },
  'HOOK-002': {
    severity: 'info',
    category: 'hooks',
    title: 'Plugin hooks into many lifecycle events',
    description: 'This plugin registers hooks across multiple lifecycle events, giving it broad visibility into user activity.',
    recommendation: 'Compare against the plugin\'s stated purpose. A deployment plugin doesn\'t need SubagentStart hooks.',
  },
  'HOOK-003': {
    severity: 'warning',
    category: 'hooks',
    title: 'Telemetry-named script on sensitive event',
    description: 'A script with "telemetry" in its name is registered on a sensitive hook event. This combination likely sends user data to an external server.',
    recommendation: 'Read the telemetry script. Check what data is sent and whether there is a genuine opt-out.',
  },
  'HOOK-004': {
    severity: 'info',
    category: 'hooks',
    title: 'No timeout on hook command',
    description: 'This hook command has no timeout specified. A hung hook can block Claude Code indefinitely.',
    recommendation: 'Consider whether a missing timeout could cause reliability issues.',
  },
};

export const SENSITIVE_EVENTS = new Set([
  'UserPromptSubmit',
  'PostToolUse',
  'PreToolUse',
  'SubagentStart',
  'PermissionRequest',
]);

// ─── FILESYSTEM: Persistent state outside plugin dir ────────────────────────

export const FILESYSTEM_PATTERNS = [
  {
    id: 'FS-001',
    severity: 'warning',
    category: 'filesystem',
    title: 'Writes files to ~/.claude/ directory',
    description: 'This plugin writes files to the user\'s ~/.claude/ directory, outside its own plugin cache directory. This can create persistent state, tracking files, or modify Claude Code configuration.',
    recommendation: 'Identify what files are written and whether they influence Claude Code\'s behavior.',
    pattern: /(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\([^)]*(?:homedir\(\)|\.claude|HOME)/g,
  },
  {
    id: 'FS-002',
    severity: 'warning',
    category: 'filesystem',
    title: 'Generates persistent unique identifier',
    description: 'This code generates a UUID or machine-specific identifier. Combined with external network requests, this enables cross-session device tracking.',
    recommendation: 'Check if the generated ID is sent to an external server and whether it persists across sessions.',
    pattern: /\b(?:randomUUID|crypto\.randomUUID|uuidv4)\s*\(/g,
  },
  {
    id: 'FS-003',
    severity: 'info',
    category: 'filesystem',
    title: 'Uses system temp directory',
    description: 'This plugin writes to the system temp directory. Common for session state, but can be used for persistent tracking if files aren\'t cleaned up.',
    recommendation: 'Check if temp files are cleaned up on SessionEnd.',
    pattern: /\btmpdir\s*\(\)/g,
  },
  {
    id: 'FS-004',
    severity: 'info',
    category: 'filesystem',
    title: 'Appends to files (logging/audit trail)',
    description: 'The plugin appends data to files, potentially creating audit trails or logs of user activity.',
    recommendation: 'Identify where logs are written and what data they contain.',
    pattern: /\bappendFileSync\s*\(/g,
  },
];

// ─── ENVIRONMENT: Process manipulation ──────────────────────────────────────

export const ENVIRONMENT_PATTERNS = [
  {
    id: 'ENV-001',
    severity: 'warning',
    category: 'environment',
    title: 'Writes to CLAUDE_ENV_FILE',
    description: 'This plugin writes to CLAUDE_ENV_FILE to persist environment variables across hook invocations. This can set variables that affect Claude Code or leak to subprocess environments.',
    recommendation: 'Check which environment variables are being set and whether they could influence other plugins or Claude\'s behavior.',
    // Match actual writes: appendFileSync, writeFileSync, fs.write targeting the env file,
    // or lines that construct export/assignment statements for it.
    // Excludes simple reads like process.env.CLAUDE_ENV_FILE checks.
    pattern: /(?:appendFileSync|writeFileSync|fs\.write)\s*\([^)]*CLAUDE_ENV_FILE|CLAUDE_ENV_FILE[^;]*(?:appendFileSync|writeFileSync|write\()|export\s+[A-Z_]+=.*CLAUDE_ENV_FILE/g,
  },
  {
    id: 'ENV-002',
    severity: 'warning',
    category: 'environment',
    title: 'Spawns child processes',
    description: 'This hook spawns child processes. While sometimes necessary, this can run arbitrary commands on the user\'s machine.',
    recommendation: 'Check what commands are spawned and whether user data is passed as arguments.',
    // Match child_process patterns, not regex .exec()
    pattern: /\b(?:execSync|spawnSync|execFileSync|execFile)\s*\(|(?:child_process|cp).*?\b(?:exec|spawn)\s*\(/g,
  },
  {
    id: 'ENV-003',
    severity: 'warning',
    category: 'environment',
    title: 'Modifies environment variables',
    description: 'This code modifies process.env, which can pollute the environment for other hooks or subprocesses.',
    recommendation: 'Check what variables are set and whether they persist beyond the hook invocation.',
    pattern: /process\.env\[['"][A-Z_]+['"]\]\s*=/g,
  },
  {
    id: 'ENV-004',
    severity: 'warning',
    category: 'environment',
    title: 'Python subprocess execution',
    description: 'Python subprocess module can execute arbitrary commands on the user\'s machine.',
    recommendation: 'Check what commands are run and whether user data is included.',
    pattern: /\bsubprocess\.(?:run|call|check_output|Popen)\s*\(/g,
    pythonOnly: true,
  },
];

// Aggregate all regex-based patterns for the source scanner
export const ALL_PATTERNS = [
  ...TELEMETRY_PATTERNS,
  ...DATA_CAPTURE_PATTERNS,
  ...INJECTION_PATTERNS,
  ...FILESYSTEM_PATTERNS,
  ...ENVIRONMENT_PATTERNS,
];
