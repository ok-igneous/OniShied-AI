import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const roots = ["src", "scripts", "database"];
const extensions = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".sql"]);
const limit = 500;
const violations = [];

async function walk(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }

  for (const entry of entries) {
    const filePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", "dist", "coverage", ".git"].includes(entry.name)) {
        await walk(filePath);
      }
      continue;
    }

    if (!entry.isFile() || !extensions.has(path.extname(entry.name))) continue;
    const content = await readFile(filePath, "utf8");
    const lines = content.split(/\r?\n/).length;
    if (lines > limit) violations.push({ filePath, lines });
  }
}

for (const root of roots) await walk(root);

if (violations.length > 0) {
  for (const item of violations) {
    console.error(`\u001b[31mFAIL\u001b[0m ${item.filePath}: ${item.lines} lines (maximum ${limit})`);
  }
  process.exitCode = 1;
} else {
  console.log(`Source-file size check passed: all scanned files are at or below ${limit} lines.`);
}
