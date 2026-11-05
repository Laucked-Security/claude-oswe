// Sink-class table for the SP10 application graph: maps a normalized sink pattern (see
// surface.mjs normalizeToken) to a coarse vulnerability class. PURE and deterministic.
// First match wins, in the order of SINK_CLASS_RULES; nothing matching -> "other".
// Matching is on the LOWER-CASED token, so callers pass the normalized (not lower-cased) pattern.
// `stack` is only consulted for the bare `exec` token: Python's exec() evaluates code ("eval"),
// every other stack's exec runs a command ("cmd-exec"). An unknown stack behaves like non-python.

const matches = (re) => (lower) => re.test(lower);

export const SINK_CLASS_RULES = Object.freeze([
  {
    class: "cmd-exec",
    test: (lower, stack) =>
      /(child_process|execsync|spawn|execfile|system|popen|proc_open|passthru|shell_exec|processbuilder|runtime\.getruntime|process\.start|processstartinfo|useshellexecute|subprocess)/.test(lower) ||
      (stack !== "python" && /^exec$/.test(lower))
  },
  {
    class: "eval",
    test: (lower, stack) =>
      /(^eval$|newfunction|runinnewcontext|mvel|parseexpression|getvalue)/.test(lower) ||
      (stack === "python" && /^exec$/.test(lower))
  },
  { class: "deser", test: matches(/(unserialize|objectinputstream|readobject|xmldecoder|xstream|jsontypeinfo|yaml\.load|pickle|marshal|binaryformatter|netdatacontract|losformatter|objectstateformatter|typenamehandling|javascriptserializer)/) },
  { class: "nosql", test: matches(/^\$/) },
  { class: "template", test: matches(/(render_template_string|^template$|lodash\.template)/) },
  { class: "sql", test: matches(/(query|mysqli|db\.raw|db\.select|whereraw|statement\.execute|cursor\.execute|^raw$|^extra$|rawsql|sqlcommand|executereader|executenonquery|fromsqlraw|executesqlraw|sequelize)/) },
  { class: "include", test: matches(/(include|^require$)/) },
  { class: "file-write", test: matches(/(move_uploaded_file|file_put_contents|writefile)/) },
  { class: "file-read", test: matches(/(send_file|send_from_directory|sendfile|readfile|path\.combine)/) },
  { class: "ssrf", test: matches(/(axios|fetch|http\.request|^got$|requests\.)/) },
  { class: "xxe", test: matches(/(documentbuilder|saxparser|xmldocument|xmlreader|lxml)/) },
  { class: "trust-boundary", test: matches(/(setattribute|putvalue|addcookie)/) },
  { class: "redirect", test: matches(/redirect/) }
].map(Object.freeze));

export function sinkClassFor(normalizedPattern, stack) {
  const lower = String(normalizedPattern).toLowerCase();
  for (const r of SINK_CLASS_RULES) if (r.test(lower, stack)) return r.class;
  return "other";
}
