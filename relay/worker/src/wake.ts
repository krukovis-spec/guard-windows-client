/** Wake delivery is deliberately non-authoritative: poll remains mandatory. */
export interface WakeHint { mailboxId: string; collapseToken: string; }
export interface WakeAdapter { notify(hint: WakeHint): Promise<void>; }
/** Default for the free relay: no FCM credentials, no content-bearing push payload. */
export class NoopWakeAdapter implements WakeAdapter { async notify(_hint: WakeHint): Promise<void> {} }
