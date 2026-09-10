/**
 * ## Generated JavaScript check
 
 `check-generated.mjs` checks that the compiled JavaScript under
 `actions/container-evidence/lib/` matches the Git index and that no new,
 untracked generated files were left out. It fails on modified, deleted, or
 untracked files in that directory.
 
 Run it from the repository root through the package command, which compiles
 TypeScript before checking the output:
 
 ```sh
 npm run check:generated
 ```
 
 If it fails, run `npm run build` and include the generated `lib/` changes in
 your commit along with the TypeScript source.
 
 `npm run ci` runs this check followed by the offline test suite. The repository's
 GitHub Actions workflow runs that command for pull requests and pushes to `main`.
 */

import { execFileSync } from "node:child_process";

const directory = "actions/container-evidence/lib";

try {
  execFileSync("git", ["diff", "--exit-code", "--", directory], {
    stdio: "inherit",
  });
  const untracked = execFileSync(
    "git",
    ["ls-files", "--others", "--exclude-standard", "--", directory],
    { encoding: "utf8" },
  );
  if (untracked.length > 0) {
    console.error(`Untracked generated files:\n${untracked}`);
    process.exitCode = 1;
  }
} catch {
  process.exitCode = 1;
}

if (process.exitCode) {
  console.error("Run npm run build and commit the updated lib/ files.");
}
