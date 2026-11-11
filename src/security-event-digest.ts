import { createHash } from "node:crypto";

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));

    return `{${entries.map(([key, entry]) =>
      `${JSON.stringify(key)}:${canonicalJson(entry)}`
    ).join(",")}}`;
  }

  return JSON.stringify(value) ?? "null";
}

export function securityEventDigest(event: unknown): string {
  return createHash("sha256").update(canonicalJson(event)).digest("hex");
}
