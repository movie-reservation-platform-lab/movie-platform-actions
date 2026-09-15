/** Offline HTTPS lifecycle double, also usable as a child-process test preload. */
import https from "node:https";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { mock } from "node:test";

export const sourceSha = "b".repeat(40);
export const mainReference = (sha = sourceSha) => ({
  ref: "refs/heads/main", object: { type: "commit", sha },
});

/** Only test-owned scenarios control this fake; production has no test inputs. */
export function installGithubMock(mocks, scenario = {}) {
  const requests = [];
  mocks.method(https, "request", (options, onResponse) => {
    if (scenario.failure === "throw") throw new Error("TRANSPORT_SENTINEL");
    const request = new EventEmitter();
    const response = new EventEmitter();
    request.destroyed = false;
    response.destroyed = false;
    response.complete = false;
    response.headers = scenario.headers ?? {};
    response.statusCode = scenario.status ?? 200;
    requests.push({ options, request, response });
    request.destroy = () => {
      request.destroyed = true;
      queueMicrotask(() => request.emit("close"));
      return request;
    };
    response.destroy = () => {
      response.destroyed = true;
      queueMicrotask(() => response.emit("close"));
      return response;
    };
    request.end = () => queueMicrotask(() => {
      if (scenario.failure === "request") {
        request.emit("error", new Error("TRANSPORT_SENTINEL"));
        return;
      }
      if (scenario.failure === "no-headers") return;
      onResponse(response);
      if (response.destroyed) return;
      if (scenario.failure === "response") {
        response.emit("error", new Error("BODY_SENTINEL"));
        return;
      }
      const chunks = scenario.chunks ?? [scenario.body ?? JSON.stringify(mainReference())];
      for (const chunk of chunks) {
        response.emit("data", Buffer.from(chunk));
        if (response.destroyed) return;
      }
      if (scenario.failure === "stalled-body") return;
      if (scenario.failure === "incomplete") { response.emit("close"); return; }
      response.complete = true;
      response.emit("end");
      response.emit("close");
      request.emit("close");
    });
    return request;
  });
  syncBuiltinESMExports();
  return requests;
}

// --import installs the fake before the real prepare executable loads HTTPS.
if (process.env.PREPARE_HTTP_SCENARIO) {
  installGithubMock(mock, JSON.parse(process.env.PREPARE_HTTP_SCENARIO));
}
