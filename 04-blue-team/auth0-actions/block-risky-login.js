/**
 * Auth0 post-login Action: block risky logins (SecureNova custom risk condition).
 *
 * Deploy: Auth0 Dashboard > Actions > Library > Build Custom > "Login / Post Login",
 * paste this file, add the secrets below (optional), Deploy, then drag it into
 * Actions > Triggers > post-login.
 *
 * Risk score (deny when score >= RISK_THRESHOLD, default 70):
 *   +40  login from a country not in ALLOWED_COUNTRIES (default "GB,IE,US,IN")
 *   +40  Auth0 Adaptive MFA risk assessment confidence == "low"
 *   +30  IP on the internal blocklist (BLOCKED_IPS, comma separated)
 *   +30  any admin-scope request (write:admin) from a non-allowed country
 *   +20  impossible travel / new device flagged by Auth0 risk assessment
 *   +10  user agent looks like a script/bot (curl, python-requests, etc.)
 * Machine identities are never allowed through the interactive login flow:
 *   users with app_metadata.identity_type == "agent" are always denied.
 *
 * Optional secrets (Action > Settings > Secrets):
 *   ALLOWED_COUNTRIES, BLOCKED_IPS, RISK_THRESHOLD
 */

const DEFAULT_ALLOWED = "GB,IE,US,IN";
const BOT_UA = /(curl|wget|python-requests|httpie|go-http-client|okhttp|scrapy|headless)/i;

function list(value, fallback = "") {
  return String(value ?? fallback)
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
}

function assessRisk(event) {
  const secrets = event.secrets || {};
  const allowed = list(secrets.ALLOWED_COUNTRIES, DEFAULT_ALLOWED);
  const blockedIps = list(secrets.BLOCKED_IPS);
  const country = (event.request?.geoip?.countryCode || "").toUpperCase();
  const ip = event.request?.ip || "";
  const ua = event.request?.user_agent || "";
  const scope = String(event.transaction?.requested_scopes?.join?.(" ") ?? event.request?.query?.scope ?? "");
  const assessments = event.authentication?.riskAssessment?.assessments || {};
  const reasons = [];
  let score = 0;

  const foreign = country !== "" && !allowed.includes(country);
  if (foreign) { score += 40; reasons.push(`country ${country} not in allow-list`); }
  if (event.authentication?.riskAssessment?.confidence === "low") {
    score += 40; reasons.push("Auth0 risk assessment confidence=low");
  }
  if (blockedIps.includes(ip.toUpperCase())) { score += 30; reasons.push(`IP ${ip} on blocklist`); }
  if (foreign && scope.includes("write:admin")) { score += 30; reasons.push("admin scope from non-allowed country"); }
  if (assessments.ImpossibleTravel?.confidence === "low" || assessments.NewDevice?.confidence === "low") {
    score += 20; reasons.push("impossible travel / new device");
  }
  if (BOT_UA.test(ua)) { score += 10; reasons.push("scripted user agent"); }

  return { score, reasons, threshold: Number(secrets.RISK_THRESHOLD || 70) };
}

exports.onExecutePostLogin = async (event, api) => {
  if (event.user?.app_metadata?.identity_type === "agent") {
    console.log(`DENY user=${event.user.user_id} reason=agent identity used interactive login`);
    api.access.deny("AI agent identities must use the client-credentials flow, not interactive login.");
    return;
  }

  const { score, reasons, threshold } = assessRisk(event);
  api.idToken.setCustomClaim("https://securenova.ai/risk_score", score);
  api.accessToken.setCustomClaim("https://securenova.ai/risk_score", score);

  if (score >= threshold) {
    console.log(`DENY user=${event.user?.user_id} ip=${event.request?.ip} score=${score} reasons=${reasons.join("; ")}`);
    api.access.deny(`Login blocked by SecureNova risk policy (score ${score}). Contact security@securenova.ai.`);
    return;
  }
  console.log(`ALLOW user=${event.user?.user_id} score=${score} reasons=${reasons.join("; ") || "none"}`);
};

exports.assessRisk = assessRisk;
