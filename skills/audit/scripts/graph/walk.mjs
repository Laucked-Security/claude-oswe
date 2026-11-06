// Scope-confined file walker for the SP10 application graph — zero dependencies, Node >= 20.
// Decides which files build-graph parses and reports, deterministically, every supported-language
// file it skipped and why. Only files whose extension maps to a parser language (langIdForFile) are
// ever returned, whether "ok" or "skipped"; everything else (images, .rb, docs) is invisible.
//
// Confinement: directory symlinks/junctions are never followed, and every candidate file goes
// through confinePath (realpath + containment), so a file symlink pointing outside the project root
// is reported as skipped/out_of_scope instead of being read.
//
// walkFiles({ projectDir, scopeRealpath, excludes, maxBytes }) -> [{ path, abs, langId, bytes, status,
// skip_reason? }] sorted by path (plain string comparison, never locale-aware). scopeRealpath is a
// confined real path equal to projectDir or a directory inside it; `path` is relative to projectDir
// with forward slashes, `abs` is the absolute path as walked.
import { readdirSync, realpathSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { confinePath } from "../confine-path.mjs";
import { langIdForFile } from "./parser.mjs";

export const DEFAULT_EXCLUDES = ["vendor", "node_modules", "dist", "build", "out", "target", "bin", "obj", ".git", ".oswe"];

const MINIFIED = /\.min\.[cm]?js$/;

function classify(projectDir, rel, maxBytes) {
  let real;
  try {
    real = confinePath(projectDir, rel);
  } catch (e) {
    // ENOENT is a dangling link / vanished file; any other rejection is a path escape.
    return { bytes: 0, status: "skipped", skip_reason: e.code === "ENOENT" ? "unreadable" : "out_of_scope" };
  }
  let bytes;
  try {
    bytes = statSync(real).size;
  } catch {
    return { bytes: 0, status: "skipped", skip_reason: "unreadable" };
  }
  if (MINIFIED.test(rel)) return { bytes, status: "skipped", skip_reason: "minified" };
  if (bytes > maxBytes) return { bytes, status: "skipped", skip_reason: "too_large" };
  return { bytes, status: "ok" };
}

// A symlink Dirent is a directory link (skip it) when its target is a directory; a dangling or
// file link falls through to the file path, where confinePath decides.
function linksToDirectory(abs) {
  try {
    return statSync(abs).isDirectory();
  } catch {
    return false;
  }
}

export function walkFiles({ projectDir, scopeRealpath, excludes = DEFAULT_EXCLUDES, maxBytes = 1048576 }) {
  const root = realpathSync(resolve(projectDir));
  const excluded = new Set(excludes);
  const results = [];

  function visit(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      if (dir === scopeRealpath) throw e; // an unreadable scope is an error; a nested dir is just skipped
      return;
    }
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!excluded.has(entry.name)) visit(abs);
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (linksToDirectory(abs)) continue;
      } else if (!entry.isFile()) {
        continue;
      }
      const rel = relative(root, abs);
      const path = rel.split(sep).join("/");
      const langId = langIdForFile(path);
      if (!langId) continue;
      results.push({ path, abs, langId, ...classify(root, rel, maxBytes) });
    }
  }

  visit(scopeRealpath);
  results.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return results;
}
