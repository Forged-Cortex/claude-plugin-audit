import { HOOK_CHECKS, SENSITIVE_EVENTS } from './patterns.mjs';

/**
 * Analyze a plugin's hooks.json for structural security issues.
 * Returns an array of Finding objects.
 */
export function analyzeHooks(plugin) {
  const findings = [];
  const hooksJson = plugin.hooksJson;

  if (!hooksJson || !hooksJson.hooks) {
    return findings;
  }

  const hooks = hooksJson.hooks;
  const eventNames = Object.keys(hooks);

  // HOOK-002: Check total lifecycle event coverage
  if (eventNames.length >= 5) {
    findings.push({
      ...HOOK_CHECKS['HOOK-002'],
      id: 'HOOK-002',
      plugin: plugin.name,
      file: 'hooks/hooks.json',
      line: null,
      match: `Hooks into ${eventNames.length} events: ${eventNames.join(', ')}`,
    });
  }

  for (const [eventName, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const matcher = entry.matcher ?? '';
      const entryHooks = entry.hooks || [];

      // HOOK-001: Empty matcher on sensitive event
      if (matcher === '' && SENSITIVE_EVENTS.has(eventName)) {
        findings.push({
          ...HOOK_CHECKS['HOOK-001'],
          id: 'HOOK-001',
          plugin: plugin.name,
          file: 'hooks/hooks.json',
          line: null,
          match: `${eventName}[${i}] matcher: "" (fires on every ${eventName} event)`,
        });
      }

      for (const hook of entryHooks) {
        const command = hook.command || '';
        const scriptName = extractScriptName(command);

        // HOOK-003: Telemetry-named script on sensitive event
        if (scriptName && /telemetry/i.test(scriptName) && SENSITIVE_EVENTS.has(eventName)) {
          findings.push({
            ...HOOK_CHECKS['HOOK-003'],
            id: 'HOOK-003',
            plugin: plugin.name,
            file: 'hooks/hooks.json',
            line: null,
            match: `${eventName}[${i}]: ${scriptName} (telemetry script on ${eventName})`,
          });
        }

        // HOOK-004: No timeout
        if (hook.timeout === undefined || hook.timeout === null) {
          findings.push({
            ...HOOK_CHECKS['HOOK-004'],
            id: 'HOOK-004',
            plugin: plugin.name,
            file: 'hooks/hooks.json',
            line: null,
            match: `${eventName}[${i}]: ${scriptName || command} (no timeout set)`,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Extract the script filename from a hook command string.
 * e.g., "node '${CLAUDE_PLUGIN_ROOT}/hooks/telemetry.mjs'" -> "telemetry.mjs"
 */
function extractScriptName(command) {
  // Match the last path component before any trailing quotes/arguments
  const match = command.match(/([a-zA-Z0-9_-]+\.(?:mjs|js|py|sh|cmd))/);
  return match ? match[1] : null;
}

/**
 * Get a summary of hook events registered by this plugin.
 */
export function getHookSummary(plugin) {
  if (!plugin.hooksJson?.hooks) return [];
  return Object.keys(plugin.hooksJson.hooks);
}
