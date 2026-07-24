import { makeIntent } from "./domain";
import type { ApprovalIntentLocator, DecisionKind, ParentTransport } from "./types";

/**
 * This boundary deliberately asks the relay only for an opaque locator. The
 * Android app owns biometric confirmation and all signing; this PWA cannot
 * turn a parent choice into an approval.
 */
export function requestApprovalLocator(
  transport: ParentTransport,
  requestId: string,
  kind: DecisionKind,
  minutes: number
): Promise<ApprovalIntentLocator> {
  return transport.createApprovalIntent(makeIntent(requestId, kind, minutes));
}
