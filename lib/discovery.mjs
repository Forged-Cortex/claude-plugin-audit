import { existsSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import { homedir } from 'node:os';
import { readJsonSafe, walkSourceFiles } from './utils.mjs';

const DEFAULT_CLAUDE_DIR = join(homedir(), '.claude');
const DEFAULT_PLUGINS_DIR = join(DEFAULT_CLAUDE_DIR, 'plugins', 'cache');
const INSTALLED_PLUGINS_FILE = join(DEFAULT_CLAUDE_DIR, 'plugins', 'installed_plugins.json');
const SETTINGS_FILE = join(DEFAULT_CLAUDE_DIR, 'settings.json');

/**
 * Discover all installed Claude Code plugins.
 * Returns an array of PluginInfo objects.
 */
export function discoverPlugins(options = {}) {
  const pluginsDir = options.pluginDir || DEFAULT_PLUGINS_DIR;
  const filterNames = options.filterNames || null;

  // Read installed plugins registry
  const registry = readJsonSafe(INSTALLED_PLUGINS_FILE);
  // Read settings for enabled/disabled state
  const settings = readJsonSafe(SETTINGS_FILE);
  const enabledPlugins = settings?.enabledPlugins || {};

  const plugins = [];

  if (registry && registry.plugins) {
    for (const [key, installations] of Object.entries(registry.plugins)) {
      // key format: "pluginName@marketplace"
      const atIndex = key.lastIndexOf('@');
      const pluginName = atIndex > 0 ? key.slice(0, atIndex) : key;
      const marketplace = atIndex > 0 ? key.slice(atIndex + 1) : 'unknown';

      if (filterNames && !filterNames.includes(pluginName)) continue;

      for (const install of installations) {
        const installPath = install.installPath;
        if (!installPath || !existsSync(installPath)) continue;

        const pluginJson = readJsonSafe(join(installPath, '.claude-plugin', 'plugin.json'));
        const hooksJson = readJsonSafe(join(installPath, 'hooks', 'hooks.json'));
        const sourceFiles = walkSourceFiles(installPath);
        const enabled = enabledPlugins[key] === true;

        plugins.push({
          name: pluginName,
          version: install.version || 'unknown',
          marketplace,
          installPath,
          scope: install.scope || 'unknown',
          projectPath: install.projectPath || null,
          enabled,
          pluginJson,
          hooksJson,
          sourceFiles,
          installedAt: install.installedAt,
        });
      }
    }
  }

  // Fallback: if no registry, scan the cache directory directly
  if (plugins.length === 0 && existsSync(pluginsDir)) {
    for (const marketplace of safeReaddir(pluginsDir)) {
      const marketDir = join(pluginsDir, marketplace);
      for (const pluginName of safeReaddir(marketDir)) {
        if (filterNames && !filterNames.includes(pluginName)) continue;
        const pluginDir = join(marketDir, pluginName);
        for (const version of safeReaddir(pluginDir)) {
          const versionDir = join(pluginDir, version);
          const pluginJson = readJsonSafe(join(versionDir, '.claude-plugin', 'plugin.json'));
          const hooksJson = readJsonSafe(join(versionDir, 'hooks', 'hooks.json'));
          const sourceFiles = walkSourceFiles(versionDir);
          const key = `${pluginName}@${marketplace}`;
          const enabled = enabledPlugins[key] === true;

          plugins.push({
            name: pluginName,
            version,
            marketplace,
            installPath: versionDir,
            scope: 'unknown',
            projectPath: null,
            enabled,
            pluginJson,
            hooksJson,
            sourceFiles,
          });
        }
      }
    }
  }

  // Deduplicate: if same plugin+version appears multiple times (multiple scopes),
  // keep only one instance but note the scopes
  const seen = new Map();
  const deduped = [];
  for (const p of plugins) {
    const key = `${p.name}@${p.marketplace}@${p.version}`;
    if (!seen.has(key)) {
      seen.set(key, true);
      deduped.push(p);
    }
  }

  return deduped;
}

function safeReaddir(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter(e => e.isDirectory())
      .map(e => e.name);
  } catch {
    return [];
  }
}
