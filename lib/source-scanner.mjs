import { ALL_PATTERNS } from './patterns.mjs';
import { buildLineMap, lineAt, getLine, readFileSafe } from './utils.mjs';

/**
 * Check if a match appears to be inside a string literal on its line.
 * Used to filter false positives where patterns appear as data/examples
 * rather than actual code (e.g., a security plugin listing "exec(" as
 * a pattern to warn about).
 */
function isInsideStringLiteral(lineText, matchText) {
  // If the match is surrounded by quotes in the line, it's likely a string value
  const idx = lineText.indexOf(matchText);
  if (idx === -1) return false;

  // Check for common data-definition patterns
  // e.g., "substrings": ["exec(", "execSync("]
  // e.g., "reminder": "...exec()..."
  if (/["']\s*:\s*\[/.test(lineText) || /["']\s*:\s*["'`]/.test(lineText)) {
    // Line looks like a key-value definition; check if match is inside the value
    const beforeMatch = lineText.slice(0, idx);
    const quoteCount = (beforeMatch.match(/["']/g) || []).length;
    if (quoteCount % 2 === 1) return true; // odd quotes before = inside a string
  }

  return false;
}

/**
 * Get context lines around a match (1 line before, 1 after).
 */
function getContext(content, lineMap, lineNum) {
  const lines = content.split('\n');
  const ctx = [];
  if (lineNum > 1) ctx.push({ num: lineNum - 1, text: lines[lineNum - 2]?.trim() || '' });
  ctx.push({ num: lineNum, text: lines[lineNum - 1]?.trim() || '', highlight: true });
  if (lineNum < lines.length) ctx.push({ num: lineNum + 1, text: lines[lineNum]?.trim() || '' });
  return ctx;
}

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
    // Skip Python-only patterns on non-Python files
    if (patternDef.pythonOnly && !isPython) continue;

    // Reset the regex (global flag means it has state)
    const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const id = patternDef.id;
      const lineNum = lineAt(lineMap, match.index);
      const lineText = getLine(content, lineMap, match.index);

      // Skip false positives: pattern appears inside a string literal
      // (common in security-guidance plugins that list patterns as data)
      if (isInsideStringLiteral(lineText, match[0])) continue;

      const count = (seenIds.get(id) || 0) + 1;
      seenIds.set(id, count);

      // Only report the first 3 occurrences of each pattern per file
      if (count > 3) continue;

      const context = getContext(content, lineMap, lineNum);

      const finding = {
        id,
        severity: patternDef.severity,
        category: patternDef.category,
        title: patternDef.title,
        description: patternDef.description,
        recommendation: patternDef.recommendation,
        plugin: pluginName,
        file: relativePath,
        line: lineNum,
        match: lineText,
        context,
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

  // Enrich findings with contextual intelligence
  const enriched = enrichFindings(findings, plugin.name);

  return { findings: enriched, filesScanned };
}

// ─── Contextual Intelligence ────────────────────────────────────────────────

const KNOWN_APIS = {
  'api.telegram.org': 'Telegram Bot API',
  'api.github.com': 'GitHub API',
  'registry.npmjs.org': 'npm registry',
  'api.vercel.com': 'Vercel API',
  'api.openai.com': 'OpenAI API',
  'api.anthropic.com': 'Anthropic API',
};

const BENIGN_COMMANDS = [
  { pattern: /\bwhich\s+\w+/, note: 'This checks whether a CLI tool is installed on the system. Generally benign.' },
  { pattern: /--version\b|VERSION_ARGS/i, note: 'This appears to be a version check for an installed tool. Generally benign.' },
  { pattern: /\bnpm\s+view\b/, note: 'This queries the npm registry for package metadata. Generally benign.' },
  { pattern: /\bdot\s+-T/, note: 'This renders a Graphviz diagram. Benign if you use this plugin for graph visualization.' },
  { pattern: /\bgit\s+(?:rev-parse|status|log|diff)\b/, note: 'This runs a read-only git command. Generally benign.' },
];

function enrichFindings(findings, pluginName) {
  // Build URL map: file -> extracted URLs
  const urlsByFile = new Map();
  for (const f of findings) {
    if (f.extractedUrl) {
      if (!urlsByFile.has(f.file)) urlsByFile.set(f.file, []);
      urlsByFile.get(f.file).push(f.extractedUrl);
    }
  }

  // Enrich TEL-001: cross-reference with URLs found in same file
  for (const f of findings) {
    if (f.id === 'TEL-001') {
      const urls = urlsByFile.get(f.file) || [];
      // Also check context lines for URLs
      const contextText = (f.context || []).map(c => c.text).join(' ');
      for (const [domain, apiName] of Object.entries(KNOWN_APIS)) {
        if (urls.some(u => u.includes(domain)) || contextText.includes(domain)) {
          f.note = `This fetch() appears to call the ${apiName} (${domain}), which may be expected behavior for this plugin. Still verify what data is included in the request body.`;
          break;
        }
      }
    }
  }

  // Enrich ENV-002: identify benign command spawns
  for (const f of findings) {
    if (f.id === 'ENV-002') {
      const searchText = f.match + ' ' + (f.context || []).map(c => c.text).join(' ');
      for (const bc of BENIGN_COMMANDS) {
        if (bc.pattern.test(searchText)) {
          f.note = bc.note;
          break;
        }
      }
    }
  }

  // Consolidate INJ-001: one per plugin with count
  const inj001Count = findings.filter(f => f.id === 'INJ-001').length;
  if (inj001Count > 1) {
    const first = findings.find(f => f.id === 'INJ-001');
    if (first) {
      first.match += ` (+${inj001Count - 1} more across this plugin)`;
      first.note = 'additionalContext is the designed mechanism for plugin context injection in Claude Code. This is expected behavior. The security concern is not that injection happens, but WHAT is being injected. Review the injected content for behavioral instructions, not just the presence of additionalContext.';
    }
    // Remove subsequent INJ-001s
    const result = [];
    let kept = false;
    for (const f of findings) {
      if (f.id === 'INJ-001') {
        if (!kept) { result.push(f); kept = true; }
      } else {
        result.push(f);
      }
    }
    return result;
  }

  return findings;
}
