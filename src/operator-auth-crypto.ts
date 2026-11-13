import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const PASSWORD_KEY_LENGTH = 64;
const SALT_BYTES = 16;
const SESSION_TOKEN_BYTES = 32;
const SCRYPT_OPTIONS = { N: 16_384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashOperatorPassword(password: string): Promise<string> {
  if (password.length < 12 || password.length > 256) {
    throw new Error("Password must contain between 12 and 256 characters");
  }
  const salt = randomBytes(SALT_BYTES);
  const derived = await scrypt(password, salt, PASSWORD_KEY_LENGTH, SCRYPT_OPTIONS) as Buffer;
  return `scrypt$${SCRYPT_OPTIONS.N}$${SCRYPT_OPTIONS.r}$${SCRYPT_OPTIONS.p}$${salt.toString("hex")}$${derived.toString("hex")}`;
}

export async function verifyOperatorPassword(
  password: string,
  encoded: string
): Promise<boolean> {
  const parts = encoded.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, saltHex, keyHex] = parts;
  if (n !== String(SCRYPT_OPTIONS.N) || r !== String(SCRYPT_OPTIONS.r) ||
      p !== String(SCRYPT_OPTIONS.p) || !/^[a-f0-9]{32}$/.test(saltHex ?? "") ||
      !/^[a-f0-9]{128}$/.test(keyHex ?? "")) return false;

  try {
    const expected = Buffer.from(keyHex, "hex");
    const actual = await scrypt(
      password,
      Buffer.from(saltHex, "hex"),
      PASSWORD_KEY_LENGTH,
      SCRYPT_OPTIONS
    ) as Buffer;
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function createOperatorSessionToken(): string {
  return randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

export function hashOperatorSessionToken(token: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error("Invalid operator session token format");
  }
  return createHash("sha256").update(token, "utf8").digest("hex");
}
