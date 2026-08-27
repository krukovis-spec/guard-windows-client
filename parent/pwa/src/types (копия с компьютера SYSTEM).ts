export type Language = "ru" | "en";
export type ViewState = "loading" | "ready" | "offline" | "expired" | "already-resolved" | "error";
export type DecisionKind = "AllowAlways" | "AllowTemporary" | "AllowDailyQuota" | "Deny";

export interface RequestSnapshot {
  readonly requestId: string;
  readonly childLabel: string;
  readonly deviceLabel: string;
  readonly kind: "application" | "website";
  readonly subject: string;
  readonly evidence: string;
  readonly requestedAt: string;
  readonly status: "pending" | "resolved" | "expired";
}

export interface EncryptedRelayFrame {
  readonly frameId: string;
  readonly encodedFrame: ArrayBuffer;
  readonly receivedAt: string;
}

export interface VerificationResult {
  readonly verified: boolean;
  readonly snapshot?: RequestSnapshot;
}

export interface SnapshotVerifier {
  decryptAndVerify(input: EncryptedRelayFrame): Promise<VerificationResult>;
}

export interface ApprovalIntent {
  readonly requestId: string;
  readonly kind: DecisionKind;
  readonly minutes?: number;
}

export interface ApprovalIntentLocator {
  readonly locator: string;
  readonly expiresAt: string;
}

export interface PasskeyOptions {
  /** JSON returned by the BFF. Binary WebAuthn fields are decoded and validated before browser use. */
  readonly publicKey: unknown;
}

export interface PasskeyCredentialDto {
  readonly id: string;
  readonly rawId: string;
  readonly type: "public-key";
  readonly response: {
    readonly clientDataJSON: string;
    readonly attestationObject?: string;
    readonly authenticatorData?: string;
    readonly signature?: string;
    readonly userHandle?: string | null;
  };
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

export interface ParentTransport {
  createRegistrationOptions(): Promise<PasskeyOptions>;
  completeRegistration(credential: PasskeyCredentialDto): Promise<void>;
  createLoginOptions(): Promise<PasskeyOptions>;
  completeLogin(credential: PasskeyCredentialDto): Promise<void>;
  listSnapshots(): Promise<readonly EncryptedRelayFrame[]>;
  createApprovalIntent(input: ApprovalIntent): Promise<ApprovalIntentLocator>;
}
