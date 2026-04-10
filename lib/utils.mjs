import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

// ANSI color codes — no chalk needed
export const c = {
  reset:    '\x1b[0m',
  bold:     '\x1b[1m',
  dim:      '\x1b[2m',
  red:      '\x1b[31m',
  green:    '\x1b[32m',
  yellow:   '\x1b[33m',
  cyan:     '\x1b[36m',
  white:    '\x1b[37m',
  boldRed:  '\x1b[1;31m',
  boldWhite:'\x1b[1;37m',
};

let colorEnabled = true;

export function disableColor() { colorEnabled = false; }

export function color(code, text) {
  return colorEnabled ? `${code}${text}${c.reset}` : text;
}

// Build a line-offset map for fast line-number lookups
export function buildLineMap(content) {
  const offsets = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') offsets.push(i + 1);
  }
  return offsets;
}

// Binary search to find 1-based line number from character index
export function lineAt(offsets, charIndex) {
  let lo = 0, hi = offsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (offsets[mid] <= charIndex) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

// Get the full text of the line containing charIndex
export function getLine(content, offsets, charIndex) {
  const lineNum = lineAt(offsets, charIndex);
  const start = offsets[lineNum - 1];
  const end = lineNum < offsets.length ? offsets[lineNum] - 1 : content.length;
  return content.slice(start, end).trim();
}

// Recursively walk a directory, collecting files matching extensions
const SOURCE_EXTENSIONS = new Set(['.mjs', '.js', '.mts', '.ts', '.py', '.sh', '.cmd']);
const SKIP_DIRS = new Set(['node_modules', 'tests', 'test', '.git', 'fixtures', 'scripts', 'docs', 'examples']);

export function walkSourceFiles(dir, rootDir = dir) {
  const results = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        results.push(...walkSourceFiles(fullPath, rootDir));
      }
    } else if (entry.isFile()) {
      // Skip test/spec files — not runtime code
      if (/\.(?:test|spec)\.[a-z]+$/i.test(entry.name)) continue;

      const ext = entry.name.slice(entry.name.lastIndexOf('.'));
      if (SOURCE_EXTENSIONS.has(ext)) {
        results.push({
          absolute: fullPath,
          relative: relative(rootDir, fullPath),
        });
      }
    }
  }
  return results;
}

// Safe JSON file reader
export function readJsonSafe(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch {
    return null;
  }
}

// Safe text file reader
export function readFileSafe(filePath) {
  try {
    return readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

// Truncate a string for display
export function truncate(str, maxLen = 80) {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}
