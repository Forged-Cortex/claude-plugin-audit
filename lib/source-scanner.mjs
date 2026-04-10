import { ALL_PATTERNS } from './patterns.mjs';
import { buildLineMap, lineAt, getLine, readFileSafe } from './utils.mjs';

/**
 * Scan a single source file against all detection patterns.
 * Returns an array of Finding objects.
 */
function scanFile(filePath, relativePath, pluginName) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  // Skip very large files (likely bundled libraries, not plugin-authored code)
  if (content.length > 500_000) return [];

  // Skip files that look like bundled/vendored library code
  const basename = relativePath.split('/').pop();
  if (basename.startsWith('lexical-index') || basename.startsWith('minisearch')) return [];

  const isPython = relativePath.endsWith('.py');
  const lineMap = buildLineMap(content);
  const findings = [];
  const seenIds = new Map(); // id -> count, for dedup

  for (const patternDef of ALL_PATTERNS) {
    // Skip Python-only patterns on non-Python files and vice versa
    if (patternDef.pythonOnly && !isPython) continue;
    if (!patternDef.pythonOnly && isPython) {
      // Still run language-agnostic patterns on Python files
    }

    // Reset the regex (global flag means it has state)
    const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const id = patternDef.id;
      const count = (seenIds.get(id) || 0) + 1;
      seenIds.set(id, count);

      // Only report the first 3 occurrences of each pattern per file
      if (count > 3) continue;

      const line = lineAt(lineMap, match.index);
      const lineText = getLine(content, lineMap, match.index);

      const finding = {
        id,
        severity: patternDef.severity,
        category: patternDef.category,
        title: patternDef.title,
        description: patternDef.description,
        recommendation: patternDef.recommendation,
        plugin: pluginName,
        file: relativePath,
        line,
        match: lineText,
      };

      // For TEL-004 (external URLs), extract the actual URL
      if (patternDef.extractUrl && match[1]) {
        finding.extractedUrl = match[1];
        finding.match = `URL: ${match[1]}`;
      }

      findings.push(finding);
    }

    // Note if there were additional occurrences beyond the limit
    const total = seenIds.get(patternDef.id) || 0;
    if (total > 3 && findings.length > 0) {
      const last = findings.findLast(f => f.id === patternDef.id && f.file === relativePath);
      if (last) {
        last.match += ` (+${total - 3} more)`;
      }
    }
  }

  return findings;
}

/**
 * Scan all source files in a plugin.
 * Returns an array of Finding objects.
 */
export function scanPlugin(plugin) {
  const findings = [];
  let filesScanned = 0;

  // Build a set of compiled .mjs basenames to skip their .mts/.ts sources
  const compiledBases = new Set();
  for (const file of plugin.sourceFiles) {
    if (file.relative.endsWith('.mjs')) {
      // "hooks/telemetry.mjs" -> "telemetry"
      const base = file.relative.replace(/\.mjs$/, '').split('/').pop();
      compiledBases.add(base);
    }
  }

  for (const file of plugin.sourceFiles) {
    // Skip TypeScript source if compiled .mjs output exists
    if (file.relative.endsWith('.mts') || (file.relative.endsWith('.ts') && !file.relative.endsWith('.d.ts'))) {
      const base = file.relative.replace(/\.m?ts$/, '').split('/').pop();
      if (compiledBases.has(base)) {
        filesScanned++;
        continue;
      }
    }
    const fileFindings = scanFile(file.absolute, file.relative, plugin.name);
    findings.push(...fileFindings);
    filesScanned++;
  }

  // Cross-reference: elevate findings when network + data capture appear in same file
  const networkFiles = new Set(
    findings
      .filter(f => f.category === 'telemetry' && f.severity === 'critical')
      .map(f => f.file)
  );

  for (const finding of findings) {
    if (finding.id === 'CAP-001' && networkFiles.has(finding.file)) {
      finding.severity = 'warning';
      finding.title += ' (in file with network calls)';
    }
  }

  return { findings, filesScanned };
}
