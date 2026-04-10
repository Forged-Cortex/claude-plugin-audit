import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { readFileSafe } from './utils.mjs';

const CLAUDE_DIR = join(homedir(), '.claude');

/**
 * Detect active mitigations for a plugin's findings.
 * Returns a function that can annotate individual findings.
 */
export function detectMitigations(plugin) {
  const mitigations = {
    telemetryEnvVars: detectTelemetryEnvVars(plugin),
    preferenceFiles: detectPreferenceFiles(),
    pluginDisabled: !plugin.enabled,
    trackingIds: detectTrackingIds(plugin.name),
  };

  return {
    raw: mitigations,

    /**
     * Check if a finding is mitigated. Returns { mitigated: bool, reason: string }
     */
    check(finding) {
      // Plugin is disabled entirely
      if (mitigations.pluginDisabled) {
        return {
          mitigated: true,
          reason: 'Plugin is disabled in settings.json. No hooks will fire.',
        };
      }

      // TEL-001, TEL-002, TEL-003: Outbound network in telemetry files
      if (['TEL-001', 'TEL-002', 'TEL-003'].includes(finding.id)) {
        if (isTelemetryFile(finding.file)) {
          const envMit = mitigations.telemetryEnvVars.find(v => v.isSet);
          if (envMit) {
            return {
              mitigated: true,
              reason: `${envMit.name}=${envMit.setValue} is set in your ${envMit.source}. The telemetry code is present but will not execute.`,
            };
          }
        }
      }

      // INJ-002, INJ-003: Prompt injection in telemetry consent flow
      if (['INJ-002', 'INJ-003'].includes(finding.id)) {
        if (isTelemetryFile(finding.file)) {
          // Check preference file
          const pref = mitigations.preferenceFiles.find(p =>
            p.path.includes(plugin.name) || p.path.includes('telemetry-preference')
          );
          if (pref && (pref.value === 'disabled' || pref.value === 'asked')) {
            return {
              mitigated: true,
              reason: `Telemetry preference at ${pref.filename} is set to "${pref.value}". This consent flow will not trigger again.`,
            };
          }

          // Also mitigated if telemetry env var is off
          const envMit = mitigations.telemetryEnvVars.find(v => v.isSet);
          if (envMit) {
            return {
              mitigated: true,
              reason: `${envMit.name}=${envMit.setValue} is set in your ${envMit.source}. The consent flow is bypassed entirely.`,
            };
          }
        }
      }

      // FS-002: Device tracking UUID
      if (finding.id === 'FS-002') {
        const tid = mitigations.trackingIds;
        if (tid.length === 0) {
          return {
            mitigated: true,
            reason: 'No tracking ID file found on disk. The code can generate one, but none currently exists.',
          };
        }
        // If telemetry is off, the ID exists but isn't being sent anywhere
        const envMit = mitigations.telemetryEnvVars.find(v => v.isSet);
        if (envMit) {
          return {
            mitigated: true,
            reason: `Tracking ID exists on disk but telemetry is disabled (${envMit.name}=${envMit.setValue}). The ID is not being transmitted.`,
          };
        }
      }

      return { mitigated: false, reason: null };
    },
  };
}

function isTelemetryFile(filePath) {
  return /telemetry|setup-telemetry/i.test(filePath);
}

/**
 * Scan plugin source for env vars that gate telemetry,
 * then check if they're set in the environment or shell config.
 */
function detectTelemetryEnvVars(plugin) {
  const vars = [];
  const seen = new Set();

  for (const file of plugin.sourceFiles) {
    if (!file.relative.includes('telemetry')) continue;
    const content = readFileSafe(file.absolute);
    if (!content) continue;

    const matches = content.matchAll(/(?:process\.env|env)[\.\[]\s*['"]?([A-Z_]*(?:TELEMETRY|ANALYTICS|TRACKING)[A-Z_]*)/g);
    for (const match of matches) {
      const varName = match[1];
      if (seen.has(varName)) continue;
      seen.add(varName);

      // Check current process environment
      const currentValue = process.env[varName];
      if (currentValue) {
        vars.push({
          name: varName,
          isSet: true,
          setValue: currentValue,
          source: 'environment',
        });
        continue;
      }

      // Check shell config files
      const shellResult = checkShellConfig(varName);
      if (shellResult) {
        vars.push({
          name: varName,
          isSet: true,
          setValue: shellResult.value,
          source: shellResult.file,
        });
        continue;
      }

      vars.push({ name: varName, isSet: false, setValue: null, source: null });
    }
  }

  return vars;
}

function checkShellConfig(varName) {
  const home = homedir();
  const configs = ['.zshrc', '.bashrc', '.bash_profile', '.profile'];

  for (const file of configs) {
    const content = readFileSafe(join(home, file));
    if (!content) continue;

    const regex = new RegExp(`export\\s+${varName}\\s*=\\s*['"]?([^'"\\s]+)`, 'g');
    const match = regex.exec(content);
    if (match) {
      return { file: `~/${file}`, value: match[1] };
    }
  }

  return null;
}

function detectPreferenceFiles() {
  const found = [];
  try {
    for (const entry of readdirSync(CLAUDE_DIR)) {
      if (entry.includes('telemetry-preference') || entry.includes('telemetry-consent')) {
        const fullPath = join(CLAUDE_DIR, entry);
        const content = readFileSafe(fullPath);
        found.push({
          path: fullPath,
          filename: entry,
          value: content ? content.trim() : null,
        });
      }
    }
  } catch {}
  return found;
}

function detectTrackingIds(pluginName) {
  const found = [];
  try {
    for (const entry of readdirSync(CLAUDE_DIR)) {
      if (entry.includes('device-id') || entry.includes('tracking-id') || entry.includes('machine-id')) {
        if (pluginName && !entry.includes(pluginName)) continue;
        found.push(join(CLAUDE_DIR, entry));
      }
    }
  } catch {}
  return found;
}
