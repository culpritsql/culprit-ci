import { readdir, stat } from "node:fs/promises";
import path from "node:path";

function expandBraces(pattern: string): string[] {
  const open = pattern.indexOf("{");
  if (open === -1) return [pattern];
  const close = pattern.indexOf("}", open);
  if (close === -1) return [pattern];
  const prefix = pattern.slice(0, open);
  const suffix = pattern.slice(close + 1);
  const choices = pattern.slice(open + 1, close).split(",");
  const results: string[] = [];
  for (const choice of choices) {
    for (const expanded of expandBraces(`${prefix}${choice}${suffix}`)) {
      results.push(expanded);
    }
  }
  return results;
}

function globToRegExp(globPattern: string): RegExp {
  const normalized = globPattern.replace(/\\/g, "/").replace(/^\.\//, "");
  let regex = "^";
  let i = 0;
  while (i < normalized.length) {
    const ch = normalized[i];
    if (ch === "*") {
      if (normalized[i + 1] === "*") {
        if (normalized[i + 2] === "/") {
          regex += "(?:.*/)?";
          i += 3;
          continue;
        }
        regex += ".*";
        i += 2;
        continue;
      }
      regex += "[^/]*";
      i += 1;
      continue;
    }
    if (ch === "?") {
      regex += "[^/]";
      i += 1;
      continue;
    }
    if ("+.^$|()[]{}".includes(ch)) {
      regex += `\\${ch}`;
    } else {
      regex += ch;
    }
    i += 1;
  }
  regex += "$";
  return new RegExp(regex);
}

function hasGlobMagic(pattern: string): boolean {
  return /[*?{}]/.test(pattern);
}

function staticBaseDir(pattern: string): string {
  const normalized = pattern.replace(/\\/g, "/").replace(/^\.\//, "");
  const segments = normalized.split("/");
  const staticParts: string[] = [];
  for (const seg of segments) {
    if (hasGlobMagic(seg)) break;
    staticParts.push(seg);
  }
  if (staticParts.length === 0) return ".";
  return staticParts.join("/");
}

async function walkDirectory(dir: string, rootCwd: string, out: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkDirectory(full, rootCwd, out);
    } else if (entry.isFile()) {
      const rel = path.relative(rootCwd, full).split(path.sep).join("/");
      out.push(rel);
    }
  }
}

export function toRelativeDisplayPath(filePath: string, cwd: string = process.cwd()): string {
  const resolved = path.resolve(cwd, filePath);
  const rel = path.relative(cwd, resolved).split(path.sep).join("/");
  if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
    return rel || path.basename(resolved);
  }
  return path.basename(resolved);
}

/**
 * Resolves one or more file paths or glob patterns relative to `cwd`.
 * Returns sorted, deduplicated objects with `{ absPath, displayPath }`.
 */
export async function resolveSqlInputs(
  patterns: string[],
  cwd: string = process.cwd(),
): Promise<Array<{ absPath: string; displayPath: string }>> {
  const splitPatterns: string[] = [];
  for (const raw of patterns) {
    for (const part of raw.split(/\r?\n/)) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      for (const expanded of expandBraces(trimmed)) {
        splitPatterns.push(expanded);
      }
    }
  }

  const found = new Map<string, string>();

  for (const pat of splitPatterns) {
    if (!hasGlobMagic(pat)) {
      const abs = path.resolve(cwd, pat);
      try {
        const st = await stat(abs);
        if (st.isFile()) {
          found.set(abs, toRelativeDisplayPath(abs, cwd));
        } else if (st.isDirectory()) {
          const allInDir: string[] = [];
          await walkDirectory(abs, cwd, allInDir);
          for (const rel of allInDir) {
            if (rel.endsWith(".sql")) {
              found.set(path.resolve(cwd, rel), rel);
            }
          }
        }
      } catch {
        // Missing explicit file: caller may want error if explicit path missing, handled below
        throw new Error(`SQL input path does not exist: ${pat}`);
      }
      continue;
    }

    const isAbsGlob = path.isAbsolute(pat);
    const searchRoot = isAbsGlob ? staticBaseDir(pat) || "/" : path.resolve(cwd, staticBaseDir(pat));
    const walkBase = isAbsGlob ? searchRoot : cwd;
    const candidates: string[] = [];
    await walkDirectory(searchRoot, walkBase, candidates);
    const matcher = globToRegExp(isAbsGlob ? path.relative(walkBase, pat) : pat);
    for (const rel of candidates) {
      if (matcher.test(rel)) {
        const abs = path.resolve(walkBase, rel);
        found.set(abs, toRelativeDisplayPath(abs, cwd));
      }
    }
  }

  return [...found.entries()]
    .map(([absPath, displayPath]) => ({ absPath, displayPath }))
    .sort((a, b) => a.displayPath.localeCompare(b.displayPath));
}
