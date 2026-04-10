#!/usr/bin/env node
/**
 * Smoke tests for claude-plugin-audit.
 * Validates detection against the Vercel plugin (the golden test case).
 * No test framework needed — just assertions and exit codes.
 */

import { discoverPlugins } from '../lib/discovery.mjs';
import { analyzeHooks } from '../lib/hooks-analyzer.mjs';
import { scanPlugin } from '../lib/source-scanner.mjs';
import { loadIgnoreRules } from '../lib/ignore.mjs';
import { detectMitigations } from '../lib/mitigations.mjs';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  \x1b[32mPASS\x1b[0m  ${message}`);
    passed++;
  } else {
    console.log(`  \x1b[1;31mFAIL\x1b[0m  ${message}`);
    failed++;
  }
}

function assertHas(findings, id, message) {
  assert(findings.some(f => f.id === id), message || `Should detect ${id}`);
}

function assertNone(findings, id, message) {
  assert(!findings.some(f => f.id === id), message || `Should not detect ${id}`);
}

// ─── Discovery Tests ──────────────────────────────────────────────────────

console.log('\n\x1b[1m  Discovery\x1b[0m\n');

const allPlugins = discoverPlugins();
assert(allPlugins.length > 0, 'Should discover at least one plugin');

const vercelPlugins = discoverPlugins({ filterNames: ['vercel'] });
assert(vercelPlugins.length === 1, 'Should find exactly one Vercel plugin');

const fakePlugins = discoverPlugins({ filterNames: ['nonexistent-plugin-xyz'] });
assert(fakePlugins.length === 0, 'Should find zero plugins for nonexistent name');

// ─── Vercel Plugin Tests (Golden Test Case) ───────────────────────────────

const vercel = vercelPlugins[0];
if (!vercel) {
  console.log('\n  \x1b[1;31mSKIPPED: Vercel plugin not installed, cannot run golden tests\x1b[0m\n');
} else {
  console.log('\n\x1b[1m  Vercel Plugin — Hook Analysis\x1b[0m\n');

  const hookFindings = analyzeHooks(vercel);

  assert(vercel.hooksJson !== null, 'Should have hooks.json');
  assert(vercel.sourceFiles.length > 0, 'Should have source files');

  assertHas(hookFindings, 'HOOK-001', 'Should detect universal matcher on UserPromptSubmit');
  assertHas(hookFindings, 'HOOK-003', 'Should detect telemetry-named script on sensitive event');

  console.log('\n\x1b[1m  Vercel Plugin — Source Analysis\x1b[0m\n');

  const { findings: sourceFindings, filesScanned } = scanPlugin(vercel);

  assert(filesScanned > 0, 'Should scan at least one source file');

  // CRITICAL: Must detect these
  assertHas(sourceFindings, 'TEL-001', 'Should detect fetch() in telemetry.mjs');
  assertHas(sourceFindings, 'INJ-002', 'Should detect AskUserQuestion tool instruction');
  assertHas(sourceFindings, 'INJ-003', 'Should detect shell commands targeting ~/');

  // WARNING: Should detect these
  assertHas(sourceFindings, 'TEL-004', 'Should detect telemetry.vercel.com URL');
  assertHas(sourceFindings, 'FS-002', 'Should detect randomUUID() for device tracking');
  assertHas(sourceFindings, 'CAP-002', 'Should detect prompt/command extraction');
  assertHas(sourceFindings, 'INJ-001', 'Should detect additionalContext injection');
  assertHas(sourceFindings, 'INJ-004', 'Should detect manipulative language');

  // Context lines
  const findingWithContext = sourceFindings.find(f => f.context && f.context.length > 0);
  assert(findingWithContext !== undefined, 'Findings should include context lines');
  assert(findingWithContext.context.length === 3, 'Context should include 3 lines (before, match, after)');

  // No test file leakage
  const testFileFindings = sourceFindings.filter(f => f.file.includes('.test.'));
  assert(testFileFindings.length === 0, 'Should not scan .test. files');
}

// ─── Severity Tier Tests ──────────────────────────────────────────────────

console.log('\n\x1b[1m  Severity Tiers\x1b[0m\n');

if (vercel) {
  const { findings: svFindings } = scanPlugin(vercel);

  // NOTICE: benign patterns should be downgraded
  const notices = svFindings.filter(f => f.severity === 'notice');
  assert(notices.length > 0, 'Some findings should be downgraded to NOTICE');

  // INJ-001 (additionalContext) should be NOTICE
  const inj001 = svFindings.find(f => f.id === 'INJ-001');
  assert(inj001 && inj001.severity === 'notice', 'INJ-001 (additionalContext) should be NOTICE severity');

  // INJ-001 should be consolidated to one per plugin
  const inj001Count = svFindings.filter(f => f.id === 'INJ-001').length;
  assert(inj001Count === 1, 'INJ-001 should be consolidated to one finding per plugin');

  // CAP-002 in files without network calls should be NOTICE
  const cap002Notices = svFindings.filter(f => f.id === 'CAP-002' && f.severity === 'notice');
  assert(cap002Notices.length > 0, 'CAP-002 without network calls should be NOTICE');

  // TEL-004 for telemetry URLs should stay WARNING
  const telemetryUrl = svFindings.find(f => f.id === 'TEL-004' && f.match && f.match.includes('telemetry'));
  assert(telemetryUrl && telemetryUrl.severity === 'warning', 'TEL-004 for telemetry endpoints should stay WARNING');

  // Contextual notes should be present on enriched findings
  const withNotes = svFindings.filter(f => f.note);
  assert(withNotes.length > 0, 'Enriched findings should include contextual notes');
}

// ─── Mitigation Tests ────────────────────────────────────────────────────

console.log('\n\x1b[1m  Mitigation Detection\x1b[0m\n');

if (vercel) {
  const mitChecker = detectMitigations(vercel);

  // TEL-001 in telemetry file should be mitigated (we have VERCEL_PLUGIN_TELEMETRY=off)
  const telFinding = { id: 'TEL-001', file: 'hooks/telemetry.mjs' };
  const telResult = mitChecker.check(telFinding);
  assert(telResult.mitigated === true, 'TEL-001 in telemetry.mjs should be mitigated');
  assert(telResult.reason && telResult.reason.includes('VERCEL_PLUGIN_TELEMETRY'), 'Mitigation reason should reference the env var');

  // INJ-003 in telemetry file should be mitigated (preference file is disabled)
  const injFinding = { id: 'INJ-003', file: 'hooks/setup-telemetry.mjs' };
  const injResult = mitChecker.check(injFinding);
  assert(injResult.mitigated === true, 'INJ-003 in setup-telemetry.mjs should be mitigated');

  // A finding in a non-telemetry file should NOT be mitigated
  const otherFinding = { id: 'HOOK-001', file: 'hooks/hooks.json' };
  const otherResult = mitChecker.check(otherFinding);
  assert(otherResult.mitigated === false, 'HOOK-001 in hooks.json should NOT be mitigated');
}

// ─── False Positive Tests ─────────────────────────────────────────────────

console.log('\n\x1b[1m  False Positive Calibration\x1b[0m\n');

const secGuidance = discoverPlugins({ filterNames: ['security-guidance'] });
if (secGuidance.length > 0) {
  const { findings: sgFindings } = scanPlugin(secGuidance[0]);
  const sgWarnings = sgFindings.filter(f => f.severity === 'warning' || f.severity === 'critical');
  assert(sgWarnings.length === 0, 'security-guidance should have zero warnings/critical (string literal filter)');
} else {
  console.log('  \x1b[2mSKIPPED: security-guidance not installed\x1b[0m');
}

const cleanPlugins = ['context7', 'swift-lsp', 'github', 'frontend-design', 'code-review'];
for (const name of cleanPlugins) {
  const plugins = discoverPlugins({ filterNames: [name] });
  if (plugins.length > 0) {
    const hookF = analyzeHooks(plugins[0]);
    const { findings: srcF } = scanPlugin(plugins[0]);
    const allF = [...hookF, ...srcF];
    const criticals = allF.filter(f => f.severity === 'critical');
    assert(criticals.length === 0, `${name} should have zero CRITICAL findings`);
  }
}

// ─── Ignore Rules Tests ───────────────────────────────────────────────────

console.log('\n\x1b[1m  Ignore Rules\x1b[0m\n');

const ignoreRules = loadIgnoreRules();
assert(typeof ignoreRules.shouldIgnore === 'function', 'loadIgnoreRules should return shouldIgnore function');
assert(!ignoreRules.shouldIgnore('TEL-001', 'vercel'), 'Default should not ignore anything');

// ─── Summary ──────────────────────────────────────────────────────────────

console.log(`\n\x1b[1m  Results: ${passed} passed, ${failed} failed\x1b[0m\n`);
process.exit(failed > 0 ? 1 : 0);
