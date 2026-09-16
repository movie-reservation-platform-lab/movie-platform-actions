import { appendFileSync } from "node:fs";
import { publicationContext, requireDigest } from "./profile.mjs";
const profile = publicationContext(process.env);
requireDigest(process.env.CANDIDATE_DIGEST);
const version = process.env.EVIDENCE_VERSION ?? "v1alpha2";
if (version !== "v1alpha2" && version !== "v1alpha3")
    throw new Error("Unsupported evidence version");
if (profile.component === "reservation-service" && version !== "v1alpha3")
    throw new Error("Reservation-service requires explicit v1alpha3 evidence");
appendFileSync(process.env.GITHUB_OUTPUT, `image_ref=${profile.image}\nartifact=${profile.artifact}\ndocument=component-candidate-evidence-${version}.json\nversion=${version}\n`);
