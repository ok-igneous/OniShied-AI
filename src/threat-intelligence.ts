import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export const INDICATOR_TYPES = [
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "file_hash_sha256",
  "email_address"
] as const;

export type IndicatorType = typeof INDICATOR_TYPES[number];
export type IndicatorStatus =
  | "pending" | "active" | "expired" | "revoked" | "rejected";
export type TrafficLightProtocol = "clear" | "green" | "amber" | "red";

export interface ThreatIndicator {
  id: string;
  version: number;
  type: IndicatorType;
  value_normalized: string;
  status: IndicatorStatus;
  valid_from: string;
  expires_at?: string | null;
  confidence: number;
  tlp: TrafficLightProtocol;
  source_id: string;
}

export interface IndicatorMatch {
  indicator_id: string;
  indicator_version: number;
  indicator_type: IndicatorType;
  matched_field_path: string;
  source_id: string;
  confidence: number;
  tlp: TrafficLightProtocol;
  matcher_version: string;
  matched_at: string;
}

export class IndicatorValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IndicatorValidationError";
  }
}

const MAX_VALUE_LENGTH = 2048;
const SHA256_PATTERN = /^[a-fA-F0-9]{64}$/;
const DOMAIN_LABEL_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function normalizeDomain(input: string): string {
  const withoutTerminalDot = input.endsWith(".") ? input.slice(0, -1) : input;
  if (!withoutTerminalDot || withoutTerminalDot.length > 253) {
    throw new IndicatorValidationError("Invalid domain length");
  }

  const ascii = domainToASCII(withoutTerminalDot).toLowerCase();
  if (!ascii || ascii.length > 253) {
    throw new IndicatorValidationError("Domain cannot be converted to IDNA ASCII");
  }

  const labels = ascii.split(".");
  if (labels.some((label) =>
    label.length > 63 || !DOMAIN_LABEL_PATTERN.test(label)
  )) {
    throw new IndicatorValidationError("Invalid domain label");
  }

  return ascii;
}

function normalizeIpv4(input: string): string {
  if (isIP(input) !== 4) {
    throw new IndicatorValidationError("Invalid IPv4 address");
  }
  return input.split(".").map((part) => String(Number(part))).join(".");
}

function normalizeIpv6(input: string): string {
  if (isIP(input) !== 6) {
    throw new IndicatorValidationError("Invalid IPv6 address");
  }

  // WHATWG URL parsing validates and canonicalizes IPv6 without network access.
  const hostname = new URL(`http://[${input}]/`).hostname;
  return hostname.slice(1, -1).toLowerCase();
}

function normalizeUrl(input: string): string {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new IndicatorValidationError("Invalid absolute URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new IndicatorValidationError("Only HTTP and HTTPS URLs are supported");
  }
  if (!parsed.hostname) {
    throw new IndicatorValidationError("URL hostname is required");
  }

  parsed.username = "";
  parsed.password = "";
  parsed.hostname = parsed.hostname.toLowerCase();
  return parsed.toString();
}

function normalizeEmail(input: string): string {
  const separator = input.lastIndexOf("@");
  if (separator < 1 || separator === input.length - 1) {
    throw new IndicatorValidationError("Invalid email address");
  }

  const local = input.slice(0, separator);
  if (
    local.length > 64 ||
    /[\s\u0000-\u001f\u007f]/.test(local) ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..")
  ) {
    throw new IndicatorValidationError("Invalid email local part");
  }

  return `${local}@${normalizeDomain(input.slice(separator + 1))}`;
}

export function normalizeIndicatorValue(
  type: IndicatorType,
  rawValue: string
): string {
  if (
    typeof rawValue !== "string" ||
    rawValue.length === 0 ||
    rawValue.length > MAX_VALUE_LENGTH ||
    /[\u0000-\u001f\u007f]/.test(rawValue) ||
    rawValue !== rawValue.trim()
  ) {
    throw new IndicatorValidationError("Indicator value is empty, oversized, or contains invalid whitespace");
  }

  switch (type) {
    case "ipv4":
      return normalizeIpv4(rawValue);
    case "ipv6":
      return normalizeIpv6(rawValue);
    case "domain":
      return normalizeDomain(rawValue);
    case "url":
      return normalizeUrl(rawValue);
    case "file_hash_sha256":
      if (!SHA256_PATTERN.test(rawValue)) {
        throw new IndicatorValidationError("Expected a 64-character SHA-256 hex digest");
      }
      return rawValue.toLowerCase();
    case "email_address":
      return normalizeEmail(rawValue);
    default: {
      const exhaustive: never = type;
      throw new IndicatorValidationError(`Unsupported indicator type: ${exhaustive}`);
    }
  }
}

type EventField = {
  type: IndicatorType;
  path: string;
  value: unknown;
};

function readOwnField(data: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : undefined;
}

function mappedEventFields(data: Record<string, unknown>): EventField[] {
  const definitions: Array<{ key: string; type: IndicatorType }> = [
    { key: "source_ip", type: "ipv4" },
    { key: "source_ip", type: "ipv6" },
    { key: "destination_ip", type: "ipv4" },
    { key: "destination_ip", type: "ipv6" },
    { key: "domain", type: "domain" },
    { key: "url", type: "url" },
    { key: "file_hash_sha256", type: "file_hash_sha256" },
    { key: "email_address", type: "email_address" }
  ];

  return definitions.flatMap(({ key, type }) => {
    const value = readOwnField(data, key);
    if (typeof value !== "string") return [];
    return [{ type, path: `data.${key}`, value }];
  });
}

export function matchThreatIndicators(input: {
  eventId: string;
  data: Record<string, unknown>;
  indicators: readonly ThreatIndicator[];
  now?: Date;
  matcherVersion?: string;
}): IndicatorMatch[] {
  const now = input.now ?? new Date();
  if (Number.isNaN(now.getTime())) {
    throw new IndicatorValidationError("Invalid matching timestamp");
  }
  const nowMs = now.getTime();
  const matcherVersion = input.matcherVersion ?? "exact-v1";
  const fields = mappedEventFields(input.data);
  const matches = new Map<string, IndicatorMatch>();

  for (const indicator of input.indicators) {
    if (indicator.status !== "active") continue;

    const validFrom = Date.parse(indicator.valid_from);
    const expiresAt = indicator.expires_at ? Date.parse(indicator.expires_at) : null;
    if (
      !Number.isFinite(validFrom) ||
      validFrom > nowMs ||
      (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= nowMs))
    ) {
      continue;
    }

    for (const field of fields) {
      if (field.type !== indicator.type) continue;

      let normalizedEventValue: string;
      try {
        normalizedEventValue = normalizeIndicatorValue(field.type, field.value as string);
      } catch {
        continue;
      }

      let normalizedIndicatorValue: string;
      try {
        normalizedIndicatorValue = normalizeIndicatorValue(
          indicator.type,
          indicator.value_normalized
        );
      } catch {
        continue;
      }

      if (normalizedEventValue !== normalizedIndicatorValue) continue;

      const dedupeKey = [
        indicator.id,
        indicator.version,
        field.path,
        matcherVersion
      ].join(":");

      matches.set(dedupeKey, {
        indicator_id: indicator.id,
        indicator_version: indicator.version,
        indicator_type: indicator.type,
        matched_field_path: field.path,
        source_id: indicator.source_id,
        confidence: indicator.confidence,
        tlp: indicator.tlp,
        matcher_version: matcherVersion,
        matched_at: now.toISOString()
      });
    }
  }

  return [...matches.values()];
}
