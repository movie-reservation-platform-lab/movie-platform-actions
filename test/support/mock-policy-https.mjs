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
    const component = process.env.FAKE_POLICY_COMPONENT ?? "recommendation-mcp";
    const records = structuredClone(baseline.records);
    for (const record of records) {
      record.component = component;
      record.vex.statements[0].products[0]["@id"] = `https://github.com/movie-reservation-platform-lab/movie-${component}`;
    }
    const f = policyFixture(process.env.FAKE_POLICY_MODE === "empty" ? [] : records, component);
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
