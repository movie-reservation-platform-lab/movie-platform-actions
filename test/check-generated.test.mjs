import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../ci_automations/check-generated.mjs", import.meta.url));

for (const generated of ["actions/container-evidence/lib", "local-tools/container-security/lib"]) {
  for (const scenario of ["clean", "modified", "deleted", "new", "unrelated"]) {
    test(`generated-file check: ${generated}: ${scenario}`, (t) => {
      const cwd = mkdtempSync(join(tmpdir(), "check-generated-"));
      t.after(() => rmSync(cwd, { recursive: true, force: true }));
      const directory = join(cwd, generated);
      mkdirSync(directory, { recursive: true });
      const tracked = join(directory, "existing.mjs");
      writeFileSync(tracked, "export const value = 1;\n");
      execFileSync("git", ["init", "--quiet"], { cwd });
      execFileSync("git", ["add", "."], { cwd });

      if (scenario === "modified") writeFileSync(tracked, "export const value = 2;\n");
      if (scenario === "deleted") rmSync(tracked);
      if (scenario === "new") {
        mkdirSync(join(directory, "nested"));
        writeFileSync(join(directory, "nested/new.mjs"), "export {};\n");
      }
      if (scenario === "unrelated") writeFileSync(join(cwd, "notes.txt"), "notes\n");

      const result = spawnSync(process.execPath, [script], { cwd, encoding: "utf8" });
      const shouldPass = scenario === "clean" || scenario === "unrelated";
      assert.equal(result.status, shouldPass ? 0 : 1, result.stderr);
      if (!shouldPass) assert.match(result.stderr, /commit the updated lib/);
      if (scenario === "new") assert.match(result.stderr, /nested\/new\.mjs/);
    });
  }
}
