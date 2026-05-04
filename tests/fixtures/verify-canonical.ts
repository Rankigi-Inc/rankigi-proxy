import { createHash } from "crypto";

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("non-finite");
    if (Object.is(value, -0)) return "0";
    if (Number.isInteger(value)) return String(value);
    const s = String(value);
    if (!s.includes("e") && !s.includes("E")) return s;
    const fixed = value.toFixed(20).replace(/\.?0+$/, "");
    return fixed;
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value as object).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalJson((value as any)[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error("unsupported type");
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

const cases = [
  { name: "sort_keys", value: { b: 1, a: 2 } },
  { name: "unicode_and_null", value: { unicode: "café", empty: null } },
  { name: "numbers", value: { nums: [1, 1.5, 1.0, -0.0, 1000000, 0.1] } },
  { name: "escapes", value: { s: 'a"b\\c\nd\te' } },
  { name: "nested", value: { x: { b: 1, a: 2 }, y: [{ z: 1 }] } },
  { name: "control_chars", value: { c: "x\u0001y\u001fz" } },
  { name: "bool_array_null", value: { a: [true, false, null], b: null } },
  { name: "empty_obj_arr", value: { o: {}, a: [] } },
];

for (const c of cases) {
  const canon = canonicalJson(c.value);
  const hash = sha256(canon);
  console.log(`${c.name}`);
  console.log(`  canon: ${canon}`);
  console.log(`  hash:  ${hash}`);
}
