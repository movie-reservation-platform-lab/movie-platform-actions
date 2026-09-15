/** Check canonical publication and current main before writing discovery outputs. */
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { publicationContext } from "./profile.mjs";
import { CanonicalMainError, resolveCanonicalMain } from "./canonical-main.mjs";
const failureMessages = {
    "invalid-publication-context": "Publication context is invalid; check the canonical repository, push/main guard, job and GitHub URLs.",
    "invalid-github-token": "GitHub token is missing or invalid; pass github.token through the required input.",
    "canonical-main-unavailable": "Canonical main lookup failed; check repository read access, main branch availability and GitHub connectivity/status.",
    "canonical-main-timeout": "GitHub lookup exceeded 30 seconds.",
    "canonical-main-response-too-large": "GitHub response exceeded 4096 bytes.",
    "canonical-main-invalid-response": "GitHub returned an invalid canonical main reference.",
    "stale-main-revision": "Run revision is no longer canonical main; use a run for the current main commit.",
    "prepare-output-failed": "Unable to write prepare outputs; check the runner output-file setup.",
    "prepare-failed": "Container candidate preparation failed; inspect the reviewed action implementation and runner setup.",
};
class PreparationError extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
    }
}
/** Importable orchestration for offline tests; only validated success writes outputs. */
export async function prepareCandidate(env) {
    let profile;
    try {
        profile = publicationContext(env);
        if (env.GITHUB_API_URL !== "https://api.github.com")
            throw new Error();
    }
    catch {
        throw new PreparationError("invalid-publication-context");
    }
    const outputPath = env.GITHUB_OUTPUT;
    if (!outputPath || /[\x00-\x1f\x7f]/.test(outputPath)) {
        throw new PreparationError("prepare-output-failed");
    }
    const canonicalSha = await resolveCanonicalMain(profile.component, env.GH_TOKEN);
    if (canonicalSha !== env.GITHUB_SHA)
        throw new PreparationError("stale-main-revision");
    try {
        appendFileSync(outputPath, `image_ref=${profile.image}\ntag=${profile.tag}\nartifact=${profile.artifact}\n`);
    }
    catch {
        throw new PreparationError("prepare-output-failed");
    }
}
/** Map known codes to controlled prose; never display arbitrary error text. */
export function preparationFailure(error) {
    const code = (error instanceof PreparationError || error instanceof CanonicalMainError) &&
        Object.hasOwn(failureMessages, error.code) ? error.code : "prepare-failed";
    return `[prepare-container-candidate] ${code}: ${failureMessages[code]}`;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    try {
        await prepareCandidate(process.env);
    }
    catch (error) {
        console.error(preparationFailure(error));
        process.exitCode = 1;
    }
}
