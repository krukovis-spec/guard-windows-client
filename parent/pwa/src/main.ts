import "./styles.css";
import { requestApprovalLocator } from "./approval-intent";
import { androidIntentLink } from "./domain";
import { copyFor } from "./i18n";
import { decodeAuthenticationOptions, decodeRegistrationOptions, passkeyDto } from "./passkey";
import { verifiedSnapshots } from "./security";
import { HttpParentTransport, stateForRelayError } from "./transport";
import type { DecisionKind, Language, ParentTransport, RequestSnapshot, SnapshotVerifier, ViewState } from "./types";

function requiredRoot(): HTMLDivElement {
  const found = document.querySelector<HTMLDivElement>("#app");
  if (!found) throw new Error("missing application root");
  return found;
}

const root = requiredRoot();

const transport = new HttpParentTransport();
let language: Language = "ru";
let state: ViewState = navigator.onLine ? "loading" : "offline";
let snapshots: readonly RequestSnapshot[] = [];

const unavailableVerifier: SnapshotVerifier = { decryptAndVerify: async () => ({ verified: false }) };

declare global {
  interface Window {
    /** Installed only by the audited verification adapter; absent means fail closed. */
    guardParentSnapshotVerifier?: SnapshotVerifier;
  }
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

function labelState(t: ReturnType<typeof copyFor>): string {
  if (state === "offline") return t.offline;
  if (state === "expired") return t.expired;
  if (state === "already-resolved") return t.resolved;
  if (state === "error") return t.error;
  return t.loading;
}

function render(): void {
  const t = copyFor(language);
  document.documentElement.lang = language;
  document.title = t.product;
  root.replaceChildren();
  const shell = element("main", "shell");
  const header = element("header", "masthead");
  const mark = element("span", "mark"); mark.setAttribute("aria-hidden", "true"); mark.textContent = "G";
  const heading = element("div"); const h1 = element("h1"); h1.textContent = t.product; const eyebrow = element("p", "eyebrow"); eyebrow.textContent = t.inbox; heading.append(h1, eyebrow);
  const toggle = element("button", "language"); toggle.type = "button"; toggle.textContent = t.language; toggle.addEventListener("click", () => { language = language === "ru" ? "en" : "ru"; render(); });
  header.append(mark, heading, toggle); shell.append(header);

  const notice = element("aside", "trust-note"); notice.setAttribute("aria-live", "polite");
  const title = element("strong"); title.textContent = state === "ready" ? t.verified : labelState(t);
  const detail = element("span"); detail.textContent = state === "ready" ? t.outage : `${labelState(t)} ${t.outage}`;
  notice.append(title, detail); shell.append(notice);

  if (state === "loading") shell.append(loadingView(t.loading));
  else if (state === "ready") shell.append(inboxView(t));
  else shell.append(accountView(t));
  root.append(shell);
}

function loadingView(text: string): HTMLElement {
  const section = element("section", "loading"); section.setAttribute("aria-busy", "true");
  const p = element("p"); p.textContent = text; section.append(p);
  for (let index = 0; index < 3; index += 1) section.append(element("div", "skeleton"));
  return section;
}

function accountView(t: ReturnType<typeof copyFor>): HTMLElement {
  const section = element("section", "account"); const h2 = element("h2"); h2.textContent = t.account;
  const login = element("button", "primary"); login.textContent = t.signIn; login.addEventListener("click", () => void passkey("login", transport));
  const register = element("button", "secondary"); register.textContent = t.register; register.addEventListener("click", () => void passkey("register", transport));
  section.append(h2, login, register); return section;
}

function inboxView(t: ReturnType<typeof copyFor>): HTMLElement {
  const section = element("section", "inbox"); const h2 = element("h2"); h2.textContent = t.inbox; section.append(h2);
  const pending = snapshots.filter((snapshot) => snapshot.status === "pending");
  if (!pending.length) { const p = element("p", "empty"); p.textContent = t.noRequests; section.append(p); return section; }
  for (const snapshot of pending) section.append(requestView(snapshot, t));
  return section;
}

function requestView(snapshot: RequestSnapshot, t: ReturnType<typeof copyFor>): HTMLElement {
  const article = element("article", "request");
  const meta = element("p", "meta"); meta.textContent = `${snapshot.childLabel} · ${snapshot.deviceLabel} · ${t.pending}`;
  const h3 = element("h3"); h3.textContent = snapshot.subject;
  const evidenceLabel = element("h4"); evidenceLabel.textContent = t.evidence;
  const evidence = element("p", "evidence"); evidence.textContent = snapshot.evidence;
  const time = element("p", "time"); time.textContent = `${t.requested}: ${new Date(snapshot.requestedAt).toLocaleString(language)}`;
  const form = element("form", "decisions"); form.addEventListener("submit", (event) => { event.preventDefault(); const data = new FormData(form); const kind = data.get("decision") as DecisionKind; const minutes = Number(data.get("minutes")); void beginIntent(snapshot.requestId, kind, minutes); });
  const choices: readonly [DecisionKind, string][] = [["AllowAlways", t.allowAlways], ["AllowTemporary", t.allowTemporary], ["AllowDailyQuota", t.allowQuota], ["Deny", t.deny]];
  for (const [value, label] of choices) { const radio = element("label", "decision"); const input = element("input"); input.type = "radio"; input.name = "decision"; input.value = value; input.required = true; radio.append(input, document.createTextNode(label)); form.append(radio); }
  const minutes = element("input"); minutes.type = "number"; minutes.name = "minutes"; minutes.min = "5"; minutes.max = "480"; minutes.value = "30"; minutes.setAttribute("aria-label", t.minutes);
  const submit = element("button", "primary"); submit.type = "submit"; submit.textContent = t.continuePhone;
  form.append(minutes, submit); article.append(meta, h3, evidenceLabel, evidence, time, form); return article;
}

async function beginIntent(requestId: string, kind: DecisionKind, minutes: number): Promise<void> {
  try {
    const locator = await requestApprovalLocator(transport, requestId, kind, minutes);
    const link = androidIntentLink(locator.locator);
    await navigator.clipboard?.writeText(link);
    window.location.assign(link);
  } catch (error) {
    state = stateForRelayError(error); render();
  }
}

async function passkey(mode: "login" | "register", api: ParentTransport): Promise<void> {
  try {
    const options = mode === "login" ? await api.createLoginOptions() : await api.createRegistrationOptions();
    const credential = mode === "login"
      ? await navigator.credentials.get({ publicKey: decodeAuthenticationOptions(options) })
      : await navigator.credentials.create({ publicKey: decodeRegistrationOptions(options) });
    if (!(credential instanceof PublicKeyCredential)) throw new Error("passkey cancelled");
    if (mode === "login") await api.completeLogin(passkeyDto(credential)); else await api.completeRegistration(passkeyDto(credential));
    await refresh();
  } catch (error) { state = stateForRelayError(error); render(); }
}

async function refresh(): Promise<void> {
  state = "loading"; render();
  try {
    snapshots = await verifiedSnapshots(await transport.listSnapshots(), window.guardParentSnapshotVerifier ?? unavailableVerifier);
    state = "ready";
  } catch (error) { state = stateForRelayError(error); }
  render();
}

window.addEventListener("online", () => void refresh());
window.addEventListener("offline", () => { state = "offline"; render(); });
if ("serviceWorker" in navigator) void navigator.serviceWorker.register("/sw.js");
render();
