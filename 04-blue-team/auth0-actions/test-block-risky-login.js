// Local test harness for block-risky-login.js with mocked Auth0 event/api objects.
// Run: node 04-blue-team/auth0-actions/test-block-risky-login.js
const action = require("./block-risky-login.js");

function makeApi() {
  const result = { denied: null, claims: {} };
  return {
    result,
    access: { deny: (reason) => { result.denied = reason; } },
    idToken: { setCustomClaim: (k, v) => { result.claims[k] = v; } },
    accessToken: { setCustomClaim: () => {} },
  };
}

const base = {
  user: { user_id: "auth0|alice", app_metadata: {} },
  request: { ip: "81.2.69.160", geoip: { countryCode: "GB" }, user_agent: "Mozilla/5.0 Chrome/131" },
  authentication: { riskAssessment: { confidence: "high", assessments: {} } },
  transaction: { requested_scopes: ["openid", "read:ai-data"] },
  secrets: {},
};
const merge = (patch) => JSON.parse(JSON.stringify({ ...base, ...patch }));

const cases = [
  ["Normal login from GB", merge({}), "ALLOW"],
  ["Login from US with curl user agent", merge({ request: { ip: "8.8.8.8", geoip: { countryCode: "US" }, user_agent: "curl/8.5" } }), "ALLOW"],
  ["Foreign country only (RU)", merge({ request: { ip: "5.8.18.1", geoip: { countryCode: "RU" }, user_agent: "Mozilla/5.0" } }), "ALLOW"],
  ["Foreign country + admin scope", merge({ request: { ip: "5.8.18.1", geoip: { countryCode: "RU" }, user_agent: "Mozilla/5.0" }, transaction: { requested_scopes: ["openid", "write:admin"] } }), "DENY"],
  ["Foreign country + low Auth0 confidence", merge({ request: { ip: "5.8.18.1", geoip: { countryCode: "KP" }, user_agent: "Mozilla/5.0" }, authentication: { riskAssessment: { confidence: "low", assessments: {} } } }), "DENY"],
  ["Blocklisted IP + bot UA + new device", merge({ request: { ip: "203.0.113.66", geoip: { countryCode: "GB" }, user_agent: "python-requests/2.32" }, secrets: { BLOCKED_IPS: "203.0.113.66" }, authentication: { riskAssessment: { confidence: "low", assessments: { NewDevice: { confidence: "low" } } } } }), "DENY"],
  ["Agent identity using interactive login", merge({ user: { user_id: "auth0|novaassist-01", app_metadata: { identity_type: "agent" } } }), "DENY"],
];

(async () => {
  let failures = 0;
  for (const [name, event, expected] of cases) {
    const api = makeApi();
    await action.onExecutePostLogin(event, api);
    const actual = api.result.denied ? "DENY" : "ALLOW";
    const ok = actual === expected;
    failures += ok ? 0 : 1;
    console.log(`${ok ? "PASS" : "FAIL"} | ${name.padEnd(40)} | expected=${expected} actual=${actual}` +
      (api.result.denied ? ` | ${api.result.denied}` : ""));
  }
  console.log(`\n${cases.length - failures}/${cases.length} risk-policy cases passed`);
  process.exit(failures ? 1 : 0);
})();
