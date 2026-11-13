import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_MS = 30_000;
const DIGITS = 6;
const SECRET_BYTES = 20;

export function generateTotpSecret(): string {
  return encodeBase32(randomBytes(SECRET_BYTES));
}

export function encodeBase32(input: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

export function decodeBase32(secret: string): Buffer {
  if (!/^[A-Z2-7]{32,128}$/.test(secret)) {
    throw new Error("Invalid TOTP secret");
  }
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const character of secret) {
    const index = BASE32.indexOf(character);
    if (index < 0) throw new Error("Invalid TOTP secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

export function generateTotpAt(secret: string, timestampMs: number): string {
  if (!Number.isFinite(timestampMs) || timestampMs < 0) {
    throw new Error("Invalid TOTP timestamp");
  }
  const counter = Math.floor(timestampMs / STEP_MS);
  const digest = createHmac("sha1", decodeBase32(secret))
    .update(counterBuffer(counter))
    .digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24)
    | ((digest[offset + 1]! & 0xff) << 16)
    | ((digest[offset + 2]! & 0xff) << 8)
    | (digest[offset + 3]! & 0xff);
  return String(binary % (10 ** DIGITS)).padStart(DIGITS, "0");
}

/** Returns the matched time-step counter; persist it atomically to prevent replay. */
export function verifyTotp(
  secret: string,
  code: string,
  timestampMs: number,
  window = 1
): number | null {
  if (!/^\d{6}$/.test(code) || !Number.isSafeInteger(window) || window < 0 || window > 1) {
    return null;
  }
  const supplied = Buffer.from(code, "ascii");
  const current = Math.floor(timestampMs / STEP_MS);
  for (let delta = -window; delta <= window; delta += 1) {
    const counter = current + delta;
    if (counter < 0) continue;
    const expected = Buffer.from(generateTotpAt(secret, counter * STEP_MS), "ascii");
    if (timingSafeEqual(supplied, expected)) return counter;
  }
  return null;
}

function counterBuffer(counter: number): Buffer {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  return buffer;
}
