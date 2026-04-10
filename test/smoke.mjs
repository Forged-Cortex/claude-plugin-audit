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
