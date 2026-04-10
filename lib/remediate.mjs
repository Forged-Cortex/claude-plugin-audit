import { existsSync, readdirSync, unlinkSync, readFileSync, writeFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { color, c, readJsonSafe, readFileSafe } from './utils.mjs';

const CLAUDE_DIR = join(homedir(), '.claude');
const SETTINGS_FILE = join(CLAUDE_DIR, 'settings.json');

/**
 * Run the remediation flow after an audit.
 * - Auto: delete tracking IDs, set telemetry preferences to disabled
 * - Auto: detect and output telemetry opt-out env vars
 * - Interactive: offer to disable plugins with CRITICAL findings
 */
export async function remediate(results) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  console.log('');
  console.log(color(c.boldWhite, '  REMEDIATION'));
  console.log(color(c.dim, '  Automated fixes for safe actions, interactive for the rest.'));
  console.log('');

  let actionsApplied = 0;

  // ── 1. Find and delete tracking ID files ──────────────────────────────
  const trackingFiles = findTrackingFiles();
  if (trackingFiles.length > 0) {
    console.log(color(c.boldWhite, '  Tracking Files'));
    for (const file of trackingFiles) {
      const content = readFileSafe(file);
      const preview = content ? content.trim().slice(0, 40) : '(empty)';
      console.log(color(c.yellow, `    ${file}`));
      console.log(color(c.dim, `    Contains: ${preview}`));
    }
    console.log('');
    const answer = await ask(color(c.green, '  Delete these tracking files? [Y/n] '));
    if (answer.trim().toLowerCase() !== 'n') {
      for (const file of trackingFiles) {
        try {
          unlinkSync(file);
          console.log(color(c.green, `    Deleted: ${basename(file)}`));
          actionsApplied++;
        } catch (e) {
          console.log(color(c.red, `    Failed to delete ${basename(file)}: ${e.message}`));
        }
      }
    }
    console.log('');
  }

  // ── 2. Set telemetry preference files to 'disabled' ───────────────────
  const prefFiles = findTelemetryPreferenceFiles();
  if (prefFiles.length > 0) {
    console.log(color(c.boldWhite, '  Telemetry Preference Files'));
    for (const { file, currentValue } of prefFiles) {
      console.log(color(c.yellow, `    ${file}`));
      console.log(color(c.dim, `    Current value: "${currentValue}"`));
    }
    console.log('');
    const answer = await ask(color(c.green, '  Set all telemetry preferences to "disabled"? [Y/n] '));
    if (answer.trim().toLowerCase() !== 'n') {
      for (const { file } of prefFiles) {
        try {
          writeFileSync(file, 'disabled', 'utf-8');
          console.log(color(c.green, `    Set to "disabled": ${basename(file)}`));
          actionsApplied++;
        } catch (e) {
          console.log(color(c.red, `    Failed: ${e.message}`));
        }
      }
    }
    console.log('');
  }

  // ── 3. Detect telemetry opt-out env vars from plugin source ───────────
  const envVars = detectTelemetryEnvVars(results);
  if (envVars.length > 0) {
    console.log(color(c.boldWhite, '  Telemetry Opt-Out Environment Variables'));
    console.log(color(c.dim, '  These env vars control telemetry in your plugins.'));
    console.log('');

    const shellConfig = detectShellConfig();
    const existingVars = readExistingEnvVars(shellConfig);
    const newVars = envVars.filter(v => !existingVars.has(v.name));
    const alreadySet = envVars.filter(v => existingVars.has(v.name));

    for (const v of alreadySet) {
      console.log(color(c.green, `    ${v.name}=off  (already in ${basename(shellConfig)})`));
    }

    if (newVars.length > 0) {
      for (const v of newVars) {
        console.log(color(c.yellow, `    export ${v.name}=off`));
        console.log(color(c.dim, `    Plugin: ${v.plugin}, found in: ${v.file}`));
      }
      console.log('');
      const answer = await ask(color(c.green, `  Add these to ${shellConfig}? [Y/n] `));
      if (answer.trim().toLowerCase() !== 'n') {
        const lines = newVars.map(v =>
          `\n# Disable ${v.plugin} plugin telemetry (added by claude-plugin-audit)\nexport ${v.name}=off`
        ).join('');
        try {
          const existing = readFileSafe(shellConfig) || '';
          writeFileSync(shellConfig, existing + lines + '\n', 'utf-8');
          console.log(color(c.green, `    Added ${newVars.length} env var(s) to ${shellConfig}`));
          actionsApplied += newVars.length;
        } catch (e) {
          console.log(color(c.red, `    Failed to write ${shellConfig}: ${e.message}`));
        }
      }
    } else if (alreadySet.length > 0) {
      console.log(color(c.dim, '  All telemetry opt-outs already configured.'));
    }
    console.log('');
  }

  // ── 4. Interactive: offer to disable plugins with CRITICAL findings ───
  const criticalPlugins = results
    .filter(r => r.findings.some(f => f.severity === 'critical'))
    .map(r => ({
      name: r.plugin.name,
      marketplace: r.plugin.marketplace,
      key: `${r.plugin.name}@${r.plugin.marketplace}`,
      criticalCount: r.findings.filter(f => f.severity === 'critical').length,
      enabled: r.plugin.enabled,
    }))
    .filter(p => p.enabled);

  if (criticalPlugins.length > 0) {
    console.log(color(c.boldWhite, '  Plugins with CRITICAL Findings'));
    console.log(color(c.dim, '  Disabling a plugin stops ALL its hooks but also removes its skills.'));
    console.log(color(c.dim, '  Only disable if you don\'t need the plugin\'s functionality.'));
    console.log('');

    const settings = readJsonSafe(SETTINGS_FILE);
    let settingsChanged = false;

    for (const p of criticalPlugins) {
      console.log(color(c.yellow, `    ${p.name} (${p.criticalCount} CRITICAL findings)`));
      const answer = await ask(color(c.green, `    Disable ${p.name}? [y/N] `));
      if (answer.trim().toLowerCase() === 'y') {
        if (settings && settings.enabledPlugins) {
          settings.enabledPlugins[p.key] = false;
          settingsChanged = true;
          console.log(color(c.green, `    Disabled ${p.name}`));
          actionsApplied++;
        }
      } else {
        console.log(color(c.dim, `    Skipped ${p.name}`));
      }
    }

    if (settingsChanged) {
      try {
        writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
        console.log(color(c.green, '\n    Updated ~/.claude/settings.json'));
      } catch (e) {
        console.log(color(c.red, `\n    Failed to update settings.json: ${e.message}`));
      }
    }
    console.log('');
  }

  // ── Summary ───────────────────────────────────────────────────────────
  console.log(color(c.boldWhite, '  ' + '='.repeat(64)));
  if (actionsApplied > 0) {
    console.log(color(c.green, `  ${actionsApplied} remediation action(s) applied.`));
    console.log(color(c.dim, '  Restart Claude Code for changes to take effect.'));
  } else {
    console.log(color(c.dim, '  No changes made.'));
  }
  console.log('');

  rl.close();
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function findTrackingFiles() {
  const patterns = ['device-id', 'tracking-id', 'machine-id'];
  const found = [];
  try {
    for (const entry of readdirSync(CLAUDE_DIR)) {
      for (const pattern of patterns) {
        if (entry.includes(pattern)) {
          found.push(join(CLAUDE_DIR, entry));
        }
      }
    }
  } catch {}
  return found;
}

function findTelemetryPreferenceFiles() {
  const found = [];
  try {
    for (const entry of readdirSync(CLAUDE_DIR)) {
      if (entry.includes('telemetry-preference') || entry.includes('telemetry-consent')) {
        const file = join(CLAUDE_DIR, entry);
        const content = readFileSafe(file);
        if (content && content.trim() !== 'disabled') {
          found.push({ file, currentValue: content.trim() });
        }
      }
    }
  } catch {}
  return found;
}

function detectTelemetryEnvVars(results) {
  const envVars = [];
  const seen = new Set();

  for (const result of results) {
    if (!result.findings.some(f => f.category === 'telemetry')) continue;

    for (const file of result.plugin.sourceFiles) {
      if (!file.relative.includes('telemetry')) continue;
      const content = readFileSafe(file.absolute);
      if (!content) continue;

      // Look for env var checks that gate telemetry
      // Match both process.env.VAR and destructured env.VAR patterns
      const matches = content.matchAll(/(?:process\.env|env)[\.\[]\s*['"]?([A-Z_]*(?:TELEMETRY|ANALYTICS|TRACKING)[A-Z_]*)/g);
      for (const match of matches) {
        const varName = match[1];
        if (!seen.has(varName)) {
          seen.add(varName);
          envVars.push({
            name: varName,
            plugin: result.plugin.name,
            file: file.relative,
          });
        }
      }
    }
  }

  return envVars;
}

function detectShellConfig() {
  const home = homedir();
  // Check which shell config exists, prefer .zshrc on macOS
  for (const file of ['.zshrc', '.bashrc', '.bash_profile', '.profile']) {
    if (existsSync(join(home, file))) return join(home, file);
  }
  return join(home, '.zshrc'); // default
}

function readExistingEnvVars(shellConfig) {
  const content = readFileSafe(shellConfig) || '';
  const vars = new Set();
  const matches = content.matchAll(/export\s+([A-Z_]+)=/g);
  for (const match of matches) {
    vars.add(match[1]);
  }
  return vars;
}
