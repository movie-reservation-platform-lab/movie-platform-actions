/** Test-only Node preload: exercise real child entrypoints without any network requests. */
import https from "node:https";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { policyFixture, baseline } from "./policy-fixture.mjs";

const RealDate = Date;
globalThis.Date = class extends RealDate {
  constructor(...args) { super(...(args.length ? args : [baseline.now])); }
  static now() { return RealDate.parse(baseline.now); }
};
https.request = (options, callback) => {
  const req = new EventEmitter();
  req.destroy = error => { queueMicrotask(() => { if (error) req.emit("error", error); req.emit("close"); }); return req; };
  req.end = () => queueMicrotask(() => {
    if (options.hostname !== "api.github.com" || !options.headers.Authorization) throw new Error("Unexpected test transport authority/credentials");
    const f = policyFixture(process.env.FAKE_POLICY_MODE === "empty" ? [] : baseline.records);
    const response = new EventEmitter();
    response.statusCode = process.env.FAKE_POLICY_MODE === "failed" ? 403 : f.responses.has(options.path) ? 200 : 404;
    callback(response);
    if (response.statusCode === 200) {
      response.emit("data", Buffer.from(JSON.stringify(f.responses.get(options.path))));
      response.emit("end");
      req.emit("close");
    }
  });
  return req;
};
syncBuiltinESMExports();
