import axios from "axios";
import { authStore } from "./auth";

const BASE = process.env.REACT_APP_BACKEND_URL;
export const API = `${BASE}/api`;

const http = axios.create({ baseURL: API, withCredentials: true });

// attach Bearer on every call
http.interceptors.request.use((cfg) => {
  const t = authStore.get();
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

// on 401, drop the token and force a re-login (SPA route guard picks it up)
http.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      authStore.clear();
      // avoid navigation loop while on /login
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.assign("/login");
      }
    }
    return Promise.reject(err);
  }
);

// attach ?token= for SSE URLs (EventSource can't send Authorization header)
const withToken = (url) => {
  const t = authStore.get();
  if (!t) return url;
  const sep = url.includes("?") ? "&" : "?";
  return `${url}${sep}token=${encodeURIComponent(t)}`;
};

export const api = {
  // stats + engagements
  stats: () => http.get("/stats").then((r) => r.data),
  engagements: (includeArchived = false) =>
    http.get("/engagements", { params: { include_archived: includeArchived ? 1 : 0 } }).then((r) => r.data.engagements),
  engagement: (id) => http.get(`/engagements/${id}`).then((r) => r.data),
  createEngagement: (body) => http.post("/engagements", body).then((r) => r.data),
  updateRoe: (id, body) => http.put(`/engagements/${id}/roe`, body).then((r) => r.data),
  signRoe: (id, signed_by) => http.post(`/engagements/${id}/roe/sign`, { signed_by }).then((r) => r.data),
  activate: (id) => http.post(`/engagements/${id}/activate`).then((r) => r.data),
  activateTest: (id) => http.post(`/engagements/${id}/activate-test`).then((r) => r.data),
  pause: (id) => http.post(`/engagements/${id}/pause`).then((r) => r.data),
  close: (id) => http.post(`/engagements/${id}/close`).then((r) => r.data),
  halt: (id, actor_id) => http.post(`/engagements/${id}/halt`, { actor_id }).then((r) => r.data),
  resume: (id) => http.post(`/engagements/${id}/resume`).then((r) => r.data),
  archiveEngagement: (id) => http.post(`/engagements/${id}/archive`).then((r) => r.data),
  unarchiveEngagement: (id) => http.post(`/engagements/${id}/unarchive`).then((r) => r.data),
  purgeEngagement: (id) => http.post(`/engagements/${id}/purge`).then((r) => r.data),
  deleteEngagement: (id) => http.delete(`/engagements/${id}`).then((r) => r.data),

  // sensing / assets / map  (sense + vulnScan now start a background job)
  sense: (id) => http.post(`/engagements/${id}/sense`).then((r) => r.data),
  // full autonomous kill chain (recon → web → identity → objective) as a job
  campaign: (id) => http.post(`/engagements/${id}/campaign`).then((r) => r.data),
  worldModel: (id) => http.get(`/engagements/${id}/world-model`).then((r) => r.data),
  campaignStatus: (id) => http.get(`/engagements/${id}/campaign-status`).then((r) => r.data),

  // authorization control room (RoE-driven)
  authorization: (id) => http.get(`/engagements/${id}/authorization`).then((r) => r.data),
  // execute a composed attack chain (starts the attack along it)
  executeChain: (id, chainId) => http.post(`/engagements/${id}/chains/${chainId}/execute`).then((r) => r.data),

  // offensive C2 / live footholds
  sessions: (id) => http.get(`/engagements/${id}/sessions`).then((r) => r.data),
  establishFoothold: (id, fid) => http.post(`/engagements/${id}/findings/${fid}/establish-foothold`).then((r) => r.data),
  sessionCommand: (id, sid, command) => http.post(`/engagements/${id}/sessions/${sid}/command`, { command }).then((r) => r.data),
  teardownSession: (id, sid) => http.post(`/engagements/${id}/sessions/${sid}/teardown`).then((r) => r.data),
  jobs: (id) => http.get(`/engagements/${id}/jobs`).then((r) => r.data.jobs),
  engagementEventsUrl: (id) => withToken(`${API}/engagements/${id}/events`),
  assets: (id) => http.get(`/engagements/${id}/assets`).then((r) => r.data.assets),
  threatMap: (id) => http.get(`/engagements/${id}/threat-map`).then((r) => r.data),
  attackTree: (id) => http.get(`/engagements/${id}/attack-tree`).then((r) => r.data),

  // vuln loop
  vulnScan: (id) => http.post(`/engagements/${id}/vuln-scan`).then((r) => r.data),
  findings: (id) => http.get(`/engagements/${id}/findings`).then((r) => r.data.findings),
  remediate: (fid) => http.post(`/findings/${fid}/remediate`).then((r) => r.data),
  retest: (fid) => http.post(`/findings/${fid}/retest`).then((r) => r.data),
  refreshCve: (id) => http.post(`/engagements/${id}/refresh-cve`).then((r) => r.data),
  cveCache: () => http.get(`/cve-cache`).then((r) => r.data.cves),

  // tools
  tools: () => http.get("/tools").then((r) => r.data.tools),
  toolAvailability: () => http.get("/tools/availability").then((r) => r.data),
  runTool: (toolId, body) => http.post(`/tools/${toolId}/run`, body).then((r) => r.data),
  invocations: (id) => http.get(`/engagements/${id}/invocations`).then((r) => r.data.invocations),
  invocationRaw: (invId) => http.get(`/invocations/${invId}/raw`).then((r) => r.data),

  // agents
  agents: () => http.get("/agents").then((r) => r.data.agents),
  createAgent: (body) => http.post("/agents", body).then((r) => r.data),
  promoteAgent: (id, to_state) => http.post(`/agents/${id}/promote`, { to_state }).then((r) => r.data),
  sandboxRun: (id) => http.post(`/agents/${id}/sandbox-run`).then((r) => r.data),
  sandboxTargets: () => http.get("/sandbox-targets").then((r) => r.data.targets),
  runAgent: (eid, aid) => http.post(`/engagements/${eid}/agents/${aid}/run`).then((r) => r.data),
  agentRuns: (id) => http.get(`/engagements/${id}/agent-runs`).then((r) => r.data.runs),
  agentRun: (rid) => http.get(`/agent-runs/${rid}`).then((r) => r.data),

  // approvals (role is now JWT-enforced server-side)
  approvals: (id, status) => http.get(`/engagements/${id}/approvals`, { params: { status } }).then((r) => r.data.approvals),
  approve: (aid) => http.post(`/approvals/${aid}/approve`, {}).then((r) => r.data),
  deny: (aid, reason) => http.post(`/approvals/${aid}/deny`, { reason }).then((r) => r.data),

  // audit
  audit: (id, params) => http.get(`/engagements/${id}/audit`, { params }).then((r) => r.data.events),
  auditVerify: (id) => http.get(`/engagements/${id}/audit/verify`).then((r) => r.data),

  // model gateway
  modelRoutes: () => http.get("/model/routes").then((r) => r.data.routes),
  modelInfer: (body) => http.post("/model/infer", body).then((r) => r.data),
  modelCalls: (engagement_id) => http.get("/model/calls", { params: { engagement_id } }).then((r) => r.data.calls),

  // red scope — incident hub + adversary copilot
  redScope: () => http.get("/red-scope").then((r) => r.data),
  redScopeChat: (body) => http.post("/red-scope/chat", body).then((r) => r.data),
  redScopeSaveAgent: (body) => http.post("/red-scope/agents", body).then((r) => r.data),

  // report
  report: (id) => http.get(`/engagements/${id}/report`).then((r) => r.data),
  reportHtmlUrl: (id) => withToken(`${API}/engagements/${id}/report.html`),
  reportPdfUrl: (id) => withToken(`${API}/engagements/${id}/report.pdf`),

  // attack path + surface
  attackPath: (id) => http.get(`/engagements/${id}/attack-path`).then((r) => r.data),
  attackPathStreamUrl: (id) => withToken(`${API}/engagements/${id}/attack-path/stream`),
  executeAttackPath: (id, target) =>
    http.post(`/engagements/${id}/attack-path/execute`, null, { params: target ? { target } : {} }).then((r) => r.data),
  assetDetail: (eid, aid) => http.get(`/engagements/${eid}/assets/${aid}`).then((r) => r.data),

  // auth admin (users mgmt)
  users: () => http.get("/auth/users").then((r) => r.data.users),
  createAuthUser: (body) => http.post("/auth/users", body).then((r) => r.data),
  deleteAuthUser: (uid) => http.delete(`/auth/users/${uid}`).then((r) => r.data),
};
