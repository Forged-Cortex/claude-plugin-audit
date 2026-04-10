import { c, color, truncate } from './utils.mjs';

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };
const VERSION = '1.2.0';

// ─── Terminal Reporter ──────────────────────────────────────────────────────

export function reportTerminal(results, options = {}) {
  const showInfo = options.verbose || false;
  const lines = [];

  // Header
  lines.push('');
  lines.push(color(c.boldWhite, '  CLAUDE PLUGIN AUDIT'));
  lines.push(color(c.dim, `  v${VERSION} — See what your plugins are really doing.`));
  lines.push('');

  // Scan summary
  const totalFiles = results.reduce((sum, r) => sum + r.filesScanned, 0);
  const totalPlugins = results.length;
  lines.push(color(c.dim, `  Scanned ${totalPlugins} plugin${totalPlugins !== 1 ? 's' : ''}, ${totalFiles} source files`));
  lines.push('');

  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  const summaryRows = [];

  for (const result of results) {
    const { plugin, hookEvents, findings, filesScanned } = result;

    // Filter findings by verbosity
    const shown = showInfo
      ? findings
      : findings.filter(f => f.severity !== 'info');

    const critCount = findings.filter(f => f.severity === 'critical').length;
    const warnCount = findings.filter(f => f.severity === 'warning').length;
    const infoCount = findings.filter(f => f.severity === 'info').length;
    totalCritical += critCount;
    totalWarning += warnCount;
    totalInfo += infoCount;

    summaryRows.push({ name: plugin.name, critical: critCount, warning: warnCount, info: infoCount });

    // Plugin header
    lines.push(color(c.boldWhite, '  ' + '='.repeat(64)));
    const enabledStr = plugin.enabled ? color(c.green, 'enabled') : color(c.dim, 'disabled');
    lines.push(color(c.boldWhite, `  ${plugin.name}`) + color(c.dim, ` (v${plugin.version}) — ${plugin.marketplace} [${enabledStr}]`));

    if (hookEvents.length > 0) {
      lines.push(color(c.dim, `  Hook events: ${hookEvents.join(', ')}`));
    } else {
      lines.push(color(c.dim, '  No hooks registered'));
    }
    lines.push(color(c.dim, `  Source files analyzed: ${filesScanned}`));
    lines.push('');

    if (shown.length === 0) {
      lines.push(color(c.green, '  No findings.'));
      lines.push('');
      continue;
    }

    // Sort findings by severity
    shown.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    for (const finding of shown) {
      const badge = severityBadge(finding.severity);
      const id = color(c.dim, finding.id);
      lines.push(`  ${badge}  ${id}  ${finding.title}`);

      if (finding.file) {
        const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
        lines.push(color(c.dim, `  ${' '.repeat(12)}${loc}`));
      }

      // Show context lines if available, otherwise fall back to match line
      if (finding.context && finding.context.length > 0) {
        const pad = ' '.repeat(12);
        for (const ctx of finding.context) {
          const numStr = color(c.dim, String(ctx.num).padStart(4) + ' |');
          if (ctx.highlight) {
            lines.push(`  ${pad}${numStr} ${finding.match}`);
          } else {
            lines.push(color(c.dim, `  ${pad}${numStr} ${ctx.text}`));
          }
        }
      } else if (finding.match) {
        lines.push(color(c.dim, `  ${' '.repeat(12)}${finding.match}`));
      }

      if (finding.recommendation) {
        lines.push(color(c.green, `  ${' '.repeat(12)}> ${finding.recommendation}`));
      }

      if (finding.note) {
        lines.push(color(c.cyan, `  ${' '.repeat(12)}  ${finding.note}`));
      }

      lines.push('');
    }
  }

  // Summary table
  lines.push(color(c.boldWhite, '  ' + '='.repeat(64)));
  lines.push(color(c.boldWhite, '  SUMMARY'));
  lines.push('');

  const nameWidth = Math.max(20, ...summaryRows.map(r => r.name.length + 2));
  const header = `  ${'Plugin'.padEnd(nameWidth)}${'CRITICAL'.padStart(10)}${'WARNING'.padStart(10)}${'INFO'.padStart(8)}`;
  lines.push(color(c.dim, header));
  lines.push(color(c.dim, `  ${'-'.repeat(nameWidth + 28)}`));

  for (const row of summaryRows) {
    const critStr = row.critical > 0 ? color(c.boldRed, String(row.critical).padStart(10)) : color(c.dim, String(row.critical).padStart(10));
    const warnStr = row.warning > 0 ? color(c.yellow, String(row.warning).padStart(10)) : color(c.dim, String(row.warning).padStart(10));
    const infoStr = color(c.dim, String(row.info).padStart(8));
    lines.push(`  ${row.name.padEnd(nameWidth)}${critStr}${warnStr}${infoStr}`);
  }

  lines.push(color(c.dim, `  ${'-'.repeat(nameWidth + 28)}`));

  const totalCritStr = totalCritical > 0 ? color(c.boldRed, String(totalCritical).padStart(10)) : color(c.dim, '0'.padStart(10));
  const totalWarnStr = totalWarning > 0 ? color(c.yellow, String(totalWarning).padStart(10)) : color(c.dim, '0'.padStart(10));
  const totalInfoStr = color(c.dim, String(totalInfo).padStart(8));
  lines.push(`  ${'TOTAL'.padEnd(nameWidth)}${totalCritStr}${totalWarnStr}${totalInfoStr}`);
  lines.push('');

  if (totalCritical > 0) {
    lines.push(color(c.boldRed, `  ${totalCritical} critical finding${totalCritical !== 1 ? 's' : ''} require immediate attention.`));
  } else if (totalWarning > 0) {
    lines.push(color(c.yellow, `  ${totalWarning} warning${totalWarning !== 1 ? 's' : ''} found. Review recommended.`));
  } else {
    lines.push(color(c.green, '  All clear. No critical or warning findings.'));
  }
  lines.push('');

  return lines.join('\n');
}

function severityBadge(severity) {
  switch (severity) {
    case 'critical': return color(c.boldRed, 'CRITICAL');
    case 'warning':  return color(c.yellow, ' WARNING');
    case 'info':     return color(c.cyan, '    INFO');
    default:         return severity.toUpperCase().padStart(8);
  }
}

// ─── JSON Reporter ──────────────────────────────────────────────────────────

export function reportJson(results) {
  const totalFiles = results.reduce((sum, r) => sum + r.filesScanned, 0);

  const output = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    summary: {
      pluginsScanned: results.length,
      sourceFilesScanned: totalFiles,
      criticalCount: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'critical').length, 0),
      warningCount: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'warning').length, 0),
      infoCount: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'info').length, 0),
    },
    plugins: results.map(r => ({
      name: r.plugin.name,
      version: r.plugin.version,
      marketplace: r.plugin.marketplace,
      enabled: r.plugin.enabled,
      installPath: r.plugin.installPath,
      hookEvents: r.hookEvents,
      sourceFilesScanned: r.filesScanned,
      findings: r.findings.map(f => ({
        id: f.id,
        severity: f.severity,
        category: f.category,
        title: f.title,
        file: f.file,
        line: f.line,
        match: f.match,
        description: f.description,
        recommendation: f.recommendation,
        ...(f.extractedUrl ? { url: f.extractedUrl } : {}),
        ...(f.note ? { note: f.note } : {}),
      })),
    })),
  };

  return JSON.stringify(output, null, 2);
}
