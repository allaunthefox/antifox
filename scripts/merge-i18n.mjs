#!/usr/bin/env node
// Merge the namespace JSON fragments returned by each page agent into the locale file.
// Fragment directory /tmp/i18n-frag/*.json, each shaped like { "<ns>": { "en-US": {...} }, ... }
// Each namespace is owned by exactly one agent, so a top-level assignment is enough — no conflicts. Keep the nav/common/status/login keys already in the locale.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const LOCALE_DIR = new URL("../web/src/i18n/locales/", import.meta.url);
const FRAG_DIR = "/tmp/i18n-frag";
const LANGS = ["en-US"];

// Safety net: decode HTML entities a sub-agent may have over-escaped (&lt;→< &gt;→> &amp;→& etc.).
// UI display text must always use literal characters; the <b> tags in settings also need their literal form for <Trans>.
function decodeEntities(v) {
  if (typeof v === "string") {
    return v
      .replaceAll("&lt;", "<")
      .replaceAll("&gt;", ">")
      .replaceAll("&quot;", '"')
      .replaceAll("&#39;", "'")
      .replaceAll("&amp;", "&");
  }
  if (Array.isArray(v)) return v.map(decodeEntities);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v)) out[k] = decodeEntities(v[k]);
    return out;
  }
  return v;
}

const locales = {};
for (const l of LANGS) {
  locales[l] = JSON.parse(readFileSync(new URL(`${l}.json`, LOCALE_DIR), "utf8"));
}

let nsCount = 0;
const seen = new Set();
for (const f of readdirSync(FRAG_DIR).filter((f) => f.endsWith(".json")).sort()) {
  const frag = JSON.parse(readFileSync(`${FRAG_DIR}/${f}`, "utf8"));
  for (const ns of Object.keys(frag)) {
    if (seen.has(ns)) {
      console.warn(`⚠️ Duplicate namespace: ${ns} (from ${f}) — the later one overwrites the earlier one`);
    }
    seen.add(ns);
    for (const l of LANGS) {
      const sub = frag[ns]?.[l];
      if (!sub) {
        console.warn(`⚠️ ${f}: ${ns} is missing ${l}`);
        continue;
      }
      locales[l][ns] = decodeEntities(sub);
    }
    nsCount++;
  }
}

for (const l of LANGS) {
  writeFileSync(new URL(`${l}.json`, LOCALE_DIR), JSON.stringify(locales[l], null, 2) + "\n");
}
console.log(`✓ Merged ${nsCount} namespaces into ${LANGS.length} locale file(s): ${[...seen].join(", ")}`);
