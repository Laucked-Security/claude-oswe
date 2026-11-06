// Dev-only. Regenerates ../vendor/tree-sitter/ — the committed, zero-runtime-dependency tree-sitter
// parser the SP10 application graph runs on. The runtime never touches node_modules: it loads the
// vendored loader + WASM files directly (see graph/parser.mjs). npm is needed only to GENERATE them.
//
// Usage (from skills/audit/scripts, after `npm ci`):  npm run build:grammars
//
// Vendored from node_modules (versions pinned by package-lock.json):
//   web-tree-sitter/tree-sitter.js        -> web-tree-sitter.mjs  (the ESM loader; named exports Parser, Language)
//   web-tree-sitter/tree-sitter.wasm      -> tree-sitter.wasm     (the parser runtime)
//   tree-sitter-wasms/out/tree-sitter-<id>.wasm for each id in LANG_IDS -> tree-sitter-<id>.wasm.gz
//     (gzip level 9; the seven grammars are ~11 MB raw, ~1 MB gzipped, which keeps the vendor dir
//     under check-vendor.mjs's 10 MiB budget. graph/parser.mjs gunzips them with node:zlib.)
// plus MANIFEST.json ({ "<file>": { package, version, sha256 } }, sorted by file) and LICENSES.md.
// .github/scripts/check-vendor.mjs re-hashes the directory (the committed bytes, so the .gz files) against
// MANIFEST.json in CI.
//
// Rebuilds are byte-identical: gzip output is a function of the input bytes and level only, with one
// exception — zlib stamps the build platform into the header's OS byte (0x0a on Windows, 0x03 on
// Linux), so it is pinned to 0xff (unknown). With that, Node 20, 22 and 24 produce the same bytes.
//
// This script does not run npm itself: a bare `npm install` could rewrite package-lock.json and so
// change what gets vendored. Install first (`npm ci`), then build.
// Exit 0 = vendor dir regenerated; exit 2 = could not run (e.g. node_modules missing).
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { LANG_IDS } from "./graph/parser.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const nodeModules = join(here, "node_modules");
const outDir = join(here, "..", "vendor", "tree-sitter");

const readPkg = (name) => {
  const dir = join(nodeModules, name);
  if (!existsSync(join(dir, "package.json"))) {
    console.error(`${name} is not installed in ${nodeModules} — run 'npm ci' in skills/audit/scripts first.`);
    process.exit(2);
  }
  return { dir, version: JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version };
};
const wts = readPkg("web-tree-sitter");
const wasms = readPkg("tree-sitter-wasms");

const gzip = (bytes) => {
  const gz = gzipSync(bytes, { level: 9 });
  gz[9] = 0xff; // header OS byte: pin it, see the header comment
  return gz;
};
const plain = (bytes) => bytes;

// [destination file name, source path, owning package, version, byte transform]
const files = [
  ["web-tree-sitter.mjs", join(wts.dir, "tree-sitter.js"), "web-tree-sitter", wts.version, plain],
  ["tree-sitter.wasm", join(wts.dir, "tree-sitter.wasm"), "web-tree-sitter", wts.version, plain],
  ...LANG_IDS.map((id) => [`tree-sitter-${id}.wasm.gz`, join(wasms.dir, "out", `tree-sitter-${id}.wasm`), "tree-sitter-wasms", wasms.version, gzip])
];

// Start from an empty directory so a file dropped from the list can never linger as a stale extra.
rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const manifest = {};
for (const [name, src, pkg, version, transform] of files.sort(([a], [b]) => (a < b ? -1 : 1))) {
  const bytes = transform(readFileSync(src));
  writeFileSync(join(outDir, name), bytes);
  manifest[name] = { package: pkg, version, sha256: createHash("sha256").update(bytes).digest("hex") };
}
writeFileSync(join(outDir, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");

const licenseText = (pkg) => readFileSync(join(pkg.dir, "LICENSE"), "utf8").trim();

// The compiled grammars in tree-sitter-wasms are derivative works of these upstream repositories. Each
// ships the same MIT permission text with its own copyright line(s); the lines below are copied from
// each repo's LICENSE file (github.com/tree-sitter/<repo>, master branch), the shared text once in MIT_TERMS.
const GRAMMAR_NOTICES = [
  { repo: "tree-sitter-javascript", grammars: "javascript", copyright: ["Copyright (c) 2014 Max Brunsfeld"] },
  { repo: "tree-sitter-typescript", grammars: "typescript, tsx", copyright: ["Copyright (c) 2017 Max Brunsfeld"] },
  { repo: "tree-sitter-python", grammars: "python", copyright: ["Copyright (c) 2016 Max Brunsfeld"] },
  { repo: "tree-sitter-java", grammars: "java", copyright: ["Copyright (c) 2017 Ayman Nadeem"] },
  {
    repo: "tree-sitter-php",
    grammars: "php",
    copyright: ["Copyright (c) 2017 Josh Vera, GitHub", "Copyright (c) 2019 Max Brunsfeld, Amaan Qureshi, Christian Frøystad, Caleb White"]
  },
  { repo: "tree-sitter-c-sharp", grammars: "c_sharp", copyright: ["Copyright (c) 2014-2023 Max Brunsfeld, Damien Guard, Amaan Qureshi, and contributors."] }
];
const MIT_TERMS = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;
const grammarNotices = GRAMMAR_NOTICES.map(
  ({ repo, grammars, copyright }) => `### ${repo} (MIT), grammar: ${grammars}\n\n${copyright.join("\n")}`
).join("\n\n");

writeFileSync(
  join(outDir, "LICENSES.md"),
  `# Third-party licenses

This directory vendors build outputs of two npm packages so the audit runtime needs no \`node_modules\`.
It is regenerated by \`skills/audit/scripts/build-grammars.mjs\`; do not edit by hand.

## web-tree-sitter ${wts.version} (MIT)

Files: \`web-tree-sitter.mjs\`, \`tree-sitter.wasm\`.

\`\`\`
${licenseText(wts)}
\`\`\`

## tree-sitter-wasms ${wasms.version} (Unlicense)

Files: \`tree-sitter-<language>.wasm.gz\` (the package's prebuilt grammars, gzipped).

\`\`\`
${licenseText(wasms)}
\`\`\`

## Upstream grammars compiled into tree-sitter-wasms (MIT)

The grammar binaries are compiled from the upstream tree-sitter grammar repositories below, each licensed
under the MIT License with its own copyright holders. The permission text is identical in all of them
and is reproduced once after the notices.

${grammarNotices}

\`\`\`
${MIT_TERMS}
\`\`\`
`
);

console.log(`vendored ${files.length} files + MANIFEST.json + LICENSES.md into ${outDir}`);
console.log(`  web-tree-sitter ${wts.version}, tree-sitter-wasms ${wasms.version}`);
