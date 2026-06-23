// Content-based, cross-run-stable fingerprints for findings and chains. The canonical OSWE-N id is
// POSITIONAL (aggregate-findings.mjs assigns it by sorted index), so it cannot identify a finding across
// runs. These fingerprints key on the vuln's CONTENT (class + source/sink location) and are what SARIF
// partialFingerprints and any baseline/diff must use. Zero deps beyond sha256Hex.
import { sha256Hex } from "./cache-wrap.mjs";

export function fingerprintFinding(f) {
  const key = `${f.vuln_class}|${f.source.file}:${f.source.line}|${f.sink.file}:${f.sink.line}`;
  return sha256Hex(key).slice(0, 16);
}

export function fingerprintChain(c, findings) {
  const byId = new Map((findings || []).map((f) => [f.finding_id, f]));
  const memberFps = (c.finding_ids || [])
    .map((id) => byId.get(id))
    .filter(Boolean)
    .map(fingerprintFinding)
    .sort();
  const key = `${c.entry_point.file}:${c.entry_point.line}|${c.final_impact}|${memberFps.join(",")}`;
  return sha256Hex(key).slice(0, 16);
}
