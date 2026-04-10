import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const IGNORE_PATHS = [
  join(homedir(), '.claude', '.cpauditignore'),
  join(homedir(), '.cpauditignore'),
];

/**
 * Load ignore rules from .cpauditignore files.
 *
 * Format: one rule per line
 *   # Comment
 *   TEL-001:telegram          # Ignore TEL-001 for the telegram plugin
 *   TEL-001:*                 # Ignore TEL-001 for all plugins
 *   *:telegram                # Ignore all findings for telegram
 *   TEL-001:telegram:server.ts  # Ignore TEL-001 in a specific file
 *
 * Returns a function: (findingId, pluginName, filePath?) => boolean
 */
export function loadIgnoreRules() {
  const rules = [];

  for (const ignorePath of IGNORE_PATHS) {
    if (!existsSync(ignorePath)) continue;

    try {
      const content = readFileSync(ignorePath, 'utf-8');
      for (const raw of content.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;

        const parts = line.split(':');
        const idPattern = parts[0] || '*';
        const pluginPattern = parts[1] || '*';
        const filePattern = parts[2] || '*';

        rules.push({ id: idPattern, plugin: pluginPattern, file: filePattern, raw: line });
      }
    } catch {
      // Ignore read errors
    }
  }

  return {
    shouldIgnore(findingId, pluginName, filePath = '') {
      for (const rule of rules) {
        const idMatch = rule.id === '*' || rule.id === findingId;
        const pluginMatch = rule.plugin === '*' || rule.plugin === pluginName;
        const fileMatch = rule.file === '*' || filePath.includes(rule.file);
        if (idMatch && pluginMatch && fileMatch) return true;
      }
      return false;
    },
    ruleCount: rules.length,
  };
}
