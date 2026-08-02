import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifacts = [
  "benchmark/results/nodegoat-baseline.json",
  "benchmark/results/nodegoat-data-supplemental.json"
];

test("Windows checkout line-ending conversion cannot break NodeGoat artifact byte reproducibility", () => {
  const attributes = execFileSync("git", ["check-attr", "eol", "--", ...artifacts], {
    cwd: repositoryRoot,
    encoding: "utf8"
  }).trim().split(/\r?\n/);

  assert.deepEqual(attributes, [
    "benchmark/results/nodegoat-baseline.json: eol: lf",
    "benchmark/results/nodegoat-data-supplemental.json: eol: lf"
  ]);
});
