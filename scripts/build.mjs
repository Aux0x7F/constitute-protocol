import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
await mkdir(join(root, "dist"), { recursive: true });
await copyFile(join(root, "src", "index.js"), join(root, "dist", "index.js"));
await copyFile(join(root, "src", "index.d.ts"), join(root, "dist", "index.d.ts"));
