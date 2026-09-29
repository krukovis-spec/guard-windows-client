import type { ApprovalIntent, DecisionKind } from "./types";

export const MINUTES = { temporary: { min: 5, max: 240 }, quota: { min: 15, max: 480 } } as const;

export function boundedMinutes(kind: DecisionKind, value: number): number | undefined {
  if (kind === "AllowAlways" || kind === "Deny") return undefined;
  const range = kind === "AllowTemporary" ? MINUTES.temporary : MINUTES.quota;
  return Math.max(range.min, Math.min(range.max, Math.round(value)));
}

export function makeIntent(requestId: string, kind: DecisionKind, minutes: number): ApprovalIntent {
  return { requestId, kind, minutes: boundedMinutes(kind, minutes) };
}

export function androidIntentLink(locator: string): string {
  if (!/^[A-Za-z0-9._~-]{16,256}$/u.test(locator)) throw new Error("invalid approval locator");
  return `guard-parent://request?locator=${encodeURIComponent(locator)}`;
}
