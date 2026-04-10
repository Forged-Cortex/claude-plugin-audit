#!/usr/bin/env node

import { discoverPlugins } from '../lib/discovery.mjs';
import { analyzeHooks, getHookSummary } from '../lib/hooks-analyzer.mjs';
import { scanPlugin } from '../lib/source-scanner.mjs';
import { reportTerminal, reportJson } from '../lib/reporter.mjs';
import { remediate } from '../lib/remediate.mjs';
import { disableColor } from '../lib/utils.mjs';

// ─── Argument Parsing (no dependency needed) ────────────────────────────────

const args = process.argv.slice(2);
const flags = {
  json: false,
  verbose: false,
  noColor: false,
  fix: false,
  help: false,
  version: false,
  pluginDir: null,
};
const pluginNames = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--json') flags.json = true;
  else if (arg === '--verbose' || arg === '-V') flags.verbose = true;
  else if (arg === '--no-color') flags.noColor = true;
  else if (arg === '--fix') flags.fix = true;
  else if (arg === '--help' || arg === '-h') flags.help = true;
  else if (arg === '--version' || arg === '-v') flags.version = true;
  else if (arg === '--plugin-dir' && i + 1 < args.length) flags.pluginDir = args[++i];
  else if (!arg.startsWith('-')) pluginNames.push(arg);
  else {
    console.error(`Unknown flag: ${arg}`);
    process.exit(1);
  }
}

if (flags.version) {
  console.log('claude-plugin-audit v1.1.0');
  process.exit(0);
}

if (flags.help) {
  console.log(`
  claude-plugin-audit — Security audit for Claude Code plugins
  See what your plugins are really doing. Zero dependencies.

  Usage: cpa [options] [plugin-name...]

  Options:
    --fix               Remediate findings (delete tracking, set opt-outs)
    --json              Machine-readable JSON output
    --verbose, -V       Include INFO-level findings
    --plugin-dir <dir>  Override plugin cache directory
    --no-color          Disable ANSI colors
    --help, -h          Show this help message
    --version, -v       Show version

  Examples:
    npx claude-plugin-audit              Audit all installed plugins
    npx claude-plugin-audit vercel       Audit only the Vercel plugin
    npx claude-plugin-audit --json       JSON output for CI
    npx claude-plugin-audit --verbose    Show all findings including INFO
`);
  process.exit(0);
}

if (flags.noColor) disableColor();

// ─── Main ───────────────────────────────────────────────────────────────────

const startTime = performance.now();

// Discover plugins
const discoverOptions = {};
if (flags.pluginDir) discoverOptions.pluginDir = flags.pluginDir;
if (pluginNames.length > 0) discoverOptions.filterNames = pluginNames;

const plugins = discoverPlugins(discoverOptions);

if (plugins.length === 0) {
  if (pluginNames.length > 0) {
    console.error(`No plugins found matching: ${pluginNames.join(', ')}`);
  } else {
    console.error('No Claude Code plugins found. Check ~/.claude/plugins/');
  }
  process.exit(1);
}

// Audit each plugin
const results = [];

for (const plugin of plugins) {
  // Analyze hooks.json structure
  const hookFindings = analyzeHooks(plugin);
  const hookEvents = getHookSummary(plugin);

  // Scan source files for patterns
  const { findings: sourceFindings, filesScanned } = scanPlugin(plugin);

  // Combine findings
  const allFindings = [...hookFindings, ...sourceFindings];

  results.push({
    plugin,
    hookEvents,
    findings: allFindings,
    filesScanned,
  });
}

const elapsed = Math.round(performance.now() - startTime);

// Output
if (flags.json) {
  console.log(reportJson(results));
} else {
  console.log(reportTerminal(results, { verbose: flags.verbose }));
  console.log(`  Completed in ${elapsed}ms\n`);
}

// Exit handling
const hasCritical = results.some(r => r.findings.some(f => f.severity === 'critical'));

if (flags.fix) {
  remediate(results).then(() => process.exit(hasCritical ? 1 : 0));
} else {
  process.exit(hasCritical ? 1 : 0);
}
