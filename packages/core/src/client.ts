import {
  getOwnAuthEndpoint,
  type AuthSessionPayload,
  type DeliveryPayload,
  type OwnAuthEndpointId,
  type OwnAuthEndpointInputMap,
  type OwnAuthEndpointOutputMap,
  type PublicAuthUser,
  type SignInPayload
} from "./http/contract.js";
import {
  clientErrorFromUnknown,
  OwnAuthClientError
} from "./client-error.js";
import { requestJsonWithCloudChallenge } from "./cloud-challenge-client.js";
import { isCloudClientManifest } from "./cloud-plugin.js";
import type { CloudClientOptions } from "./cloud-types.js";
import {
  getBrowserOrigin,
  navigateBrowser,
  runOAuthPopup,
  type OAuthPopupResult
} from "./client-oauth-popup.js";
import {
  callOwnAuthPluginMethod,
  type OwnAuthPluginClient
} from "./client-plugin.js";
import { resolveFetchImplementation } from "./fetch-implementation.js";
import type { OwnAuthPluginClientManifest } from "./plugin-types.js";

export { OwnAuthClientError } from "./client-error.js";
export { cloudClient, cloudNativeClient } from "./cloud-plugin.js";
export {
  CloudChallengeTimeoutError,
  solveCloudChallenge
} from "./cloud-challenge-client.js";
export type { OAuthPopupResult } from "./client-oauth-popup.js";
export type { OwnAuthPluginClient } from "./client-plugin.js";

export type OAuthSignInInput = Omit<
  OwnAuthEndpointInputMap["oauthStart"],
  "openerOrigin"
> & { popupTimeoutMs?: number };

export type SamlSignInInput = Omit<
  OwnAuthEndpointInputMap["samlStart"],
  "intent"
>;

export interface OwnAuthClientOptions {
  baseURL?: string;
  fetch?: typeof globalThis.fetch;
  headers?: OwnAuthClientHeaders | (() => OwnAuthClientHeaders | Promise<OwnAuthClientHeaders>);
  plugins?: readonly OwnAuthPluginClientManifest[];
  pluginFingerprint?: string;
}

export type OwnAuthClientHeaders =
  | Headers
  | Record<string, string>
  | [string, string][];

export interface OwnAuthSessionSnapshot {
  data: AuthSessionPayload | null;
  isPending: boolean;
  error: OwnAuthClientError | null;
}

export type OwnAuthSessionListener = () => void;

export class OwnAuthClient {
  private readonly baseURL: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly configuredHeaders?: OwnAuthClientOptions["headers"];
  private readonly pluginManifests: ReadonlyMap<string, OwnAuthPluginClientManifest>;
  private readonly pluginFingerprint?: string;
  private readonly cloudOptions: Required<CloudClientOptions> | null;
  private readonly listeners = new Set<OwnAuthSessionListener>();
  private sessionLoaded = false;
  private sessionRevision = 0;
  private sessionRequest: Promise<AuthSessionPayload | null> | null = null;
  private snapshot: OwnAuthSessionSnapshot = {
    data: null,
    isPending: true,
    error: null
  };

  constructor(options: OwnAuthClientOptions = {}) {
    this.baseURL = (options.baseURL ?? "/api/auth").replace(/\/+$/, "");
    const fetchImpl = resolveFetchImplementation(options.fetch);
    if (!fetchImpl) {
      throw new Error("Own Auth client requires a Fetch API implementation");
    }
    this.fetchImpl = fetchImpl;
    this.configuredHeaders = options.headers;
    this.pluginManifests = new Map((options.plugins ?? []).map((plugin) => [plugin.id, plugin]));
    this.pluginFingerprint = options.pluginFingerprint;
    const cloudManifest = (options.plugins ?? []).find(isCloudClientManifest);
    this.cloudOptions = cloudManifest?.__ownAuthCloudClient ?? null;
    if (this.pluginManifests.size !== (options.plugins ?? []).length) {
      throw new Error("Own Auth client plugin IDs must be unique");
    }
  }

  getSessionSnapshot = (): OwnAuthSessionSnapshot => this.snapshot;

  subscribe = (listener: OwnAuthSessionListener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  async ensureSession(): Promise<AuthSessionPayload | null> {
    if (this.sessionLoaded) {
      return this.snapshot.data;
    }
    if (this.sessionRequest) {
      return this.sessionRequest;
    }

    const request = this.getSession();
    this.sessionRequest = request;
    try {
      return await request;
    } finally {
      if (this.sessionRequest === request) {
        this.sessionRequest = null;
      }
    }
  }

  async getSession(): Promise<AuthSessionPayload | null> {
    const revision = ++this.sessionRevision;
    this.updateSnapshot({ ...this.snapshot, isPending: true, error: null });
    try {
      const result = await this.request("getSession", undefined);
      if (this.sessionRevision !== revision) {
        return this.snapshot.data;
      }
      this.sessionLoaded = true;
      this.updateSnapshot({ data: result.session, isPending: false, error: null });
      return result.session;
    } catch (error) {
      const clientError = clientErrorFromUnknown(error);
      if (this.sessionRevision !== revision) {
        return this.snapshot.data;
      }
      this.updateSnapshot({ data: null, isPending: false, error: clientError });
      throw clientError;
    }
  }

  async signUpEmailPassword(
    input: OwnAuthEndpointInputMap["signUpEmailPassword"]
  ): Promise<AuthSessionPayload> {
    return this.setCreatedSession(await this.request("signUpEmailPassword", input));
  }

  async signInEmailPassword(
    input: OwnAuthEndpointInputMap["signInEmailPassword"]
  ): Promise<SignInPayload> {
    return this.acceptSignInResult(await this.request("signInEmailPassword", input));
  }

  async signOut(): Promise<void> {
    await this.request("signOut", undefined);
    this.clearSession();
  }

  async changePassword(
    input: OwnAuthEndpointInputMap["changePassword"]
  ): Promise<PublicAuthUser> {
    const result = await this.request("changePassword", input);
    this.updateUser(result.user);
    return result.user;
  }

  requestMagicLink(
    input: OwnAuthEndpointInputMap["requestMagicLink"]
  ): Promise<DeliveryPayload> {
    return this.request("requestMagicLink", input);
  }

  async verifyMagicLink(
    input: OwnAuthEndpointInputMap["verifyMagicLink"]
  ): Promise<SignInPayload> {
    return this.acceptSignInResult(await this.request("verifyMagicLink", input));
  }

  requestEmailVerification(
    input: OwnAuthEndpointInputMap["requestEmailVerification"]
  ): Promise<DeliveryPayload> {
    return this.request("requestEmailVerification", input);
  }

  async verifyEmail(
    input: OwnAuthEndpointInputMap["verifyEmail"]
  ): Promise<PublicAuthUser> {
    const result = await this.request("verifyEmail", input);
    this.updateUser(result.user);
    return result.user;
  }

  requestPasswordReset(
    input: OwnAuthEndpointInputMap["requestPasswordReset"]
  ): Promise<DeliveryPayload> {
    return this.request("requestPasswordReset", input);
  }

  async resetPassword(
    input: OwnAuthEndpointInputMap["resetPassword"]
  ): Promise<PublicAuthUser> {
    const result = await this.request("resetPassword", input);
    this.clearSession();
    return result.user;
  }

  requestSmsOtp(
    input: OwnAuthEndpointInputMap["requestSmsOtp"]
  ): Promise<DeliveryPayload> {
    return this.request("requestSmsOtp", input);
  }

  async verifySmsOtp(
    input: OwnAuthEndpointInputMap["verifySmsOtp"]
  ): Promise<OwnAuthEndpointOutputMap["verifySmsOtp"]> {
    const result = await this.request("verifySmsOtp", input);
    if (result.status === "complete") {
      this.setCreatedSession(result);
    } else if (result.status === "verified") {
      this.updateUser(result.user);
    }
    return result;
  }

  acceptInvite(
    input: OwnAuthEndpointInputMap["acceptInvite"]
  ): Promise<OwnAuthEndpointOutputMap["acceptInvite"]> {
    return this.request("acceptInvite", input);
  }

  plugin(pluginId: string): OwnAuthPluginClient {
    return {
      call: <Output>(method: string, input?: unknown) =>
        this.callPluginMethod<Output>(pluginId, method, input)
    };
  }

  async callPluginMethod<Output = unknown>(
    pluginId: string,
    methodName: string,
    input?: unknown
  ): Promise<Output> {
    const manifest = this.pluginManifests.get(pluginId);
    return callOwnAuthPluginMethod<Output>({
      baseURL: this.baseURL,
      fetch: this.fetchImpl,
      fingerprint: this.pluginFingerprint,
      headers: new Headers(await this.resolveHeaders()),
      input,
      manifest,
      methodName,
      pluginId
    });
  }

  signInWithOAuth(
    input: OAuthSignInInput & { mode: "popup" }
  ): Promise<OAuthPopupResult>;
  signInWithOAuth(
    input: OAuthSignInInput & { mode?: "redirect" }
  ): Promise<void>;
  async signInWithOAuth(input: OAuthSignInInput): Promise<OAuthPopupResult | void> {
    const { popupTimeoutMs, ...requestInput } = input;
    if (input.mode === "popup") {
      return runOAuthPopup(
        () => this.request("oauthStart", {
          ...requestInput,
          mode: "popup",
          openerOrigin: getBrowserOrigin()
        }),
        () => this.getSession(),
        new URL(this.baseURL, getBrowserOrigin()).origin,
        popupTimeoutMs
      );
    }
    const result = await this.request("oauthStart", {
      ...requestInput,
      mode: "redirect"
    });
    navigateBrowser(result.url);
  }

  unlinkOAuthProvider(
    input: OwnAuthEndpointInputMap["unlinkOAuthProvider"]
  ): Promise<OwnAuthEndpointOutputMap["unlinkOAuthProvider"]> {
    return this.request("unlinkOAuthProvider", input);
  }

  async signInWithSaml(input: SamlSignInInput): Promise<void> {
    const result = await this.request("samlStart", { ...input, intent: "sign_in" });
    navigateBrowser(result.url);
  }

  async linkSaml(input: SamlSignInInput): Promise<void> {
    const result = await this.request("samlStart", { ...input, intent: "link" });
    navigateBrowser(result.url);
  }

  prepareGoogleOneTap(): Promise<OwnAuthEndpointOutputMap["prepareGoogleOneTap"]> {
    return this.request("prepareGoogleOneTap", undefined);
  }

  async signInWithGoogleOneTap(
    input: OwnAuthEndpointInputMap["signInGoogleOneTap"]
  ): Promise<SignInPayload> {
    return this.acceptSignInResult(await this.request("signInGoogleOneTap", input));
  }

  async completeMfaWithTotp(
    input: OwnAuthEndpointInputMap["completeMfaTotp"]
  ): Promise<AuthSessionPayload> {
    return this.setCreatedSession(await this.request("completeMfaTotp", input));
  }

  async completeMfaWithRecoveryCode(
    input: OwnAuthEndpointInputMap["completeMfaRecovery"]
  ): Promise<AuthSessionPayload> {
    return this.setCreatedSession(await this.request("completeMfaRecovery", input));
  }

  beginTotpEnrollment(): Promise<OwnAuthEndpointOutputMap["beginTotpEnrollment"]> {
    return this.request("beginTotpEnrollment", undefined);
  }

  confirmTotpEnrollment(
    input: OwnAuthEndpointInputMap["confirmTotpEnrollment"]
  ): Promise<OwnAuthEndpointOutputMap["confirmTotpEnrollment"]> {
    return this.request("confirmTotpEnrollment", input);
  }

  async disableTotp(
    input: OwnAuthEndpointInputMap["disableTotp"]
  ): Promise<void> {
    await this.request("disableTotp", input);
  }

  regenerateRecoveryCodes(
    input: OwnAuthEndpointInputMap["regenerateRecoveryCodes"]
  ): Promise<OwnAuthEndpointOutputMap["regenerateRecoveryCodes"]> {
    return this.request("regenerateRecoveryCodes", input);
  }

  beginPasskeyRegistration(): Promise<OwnAuthEndpointOutputMap["beginPasskeyRegistration"]> {
    return this.request("beginPasskeyRegistration", undefined);
  }

  completePasskeyRegistration(
    input: OwnAuthEndpointInputMap["completePasskeyRegistration"]
  ): Promise<OwnAuthEndpointOutputMap["completePasskeyRegistration"]> {
    return this.request("completePasskeyRegistration", input);
  }

  beginPasskeyAuthentication(
    input: OwnAuthEndpointInputMap["beginPasskeyAuthentication"] = {}
  ): Promise<OwnAuthEndpointOutputMap["beginPasskeyAuthentication"]> {
    return this.request("beginPasskeyAuthentication", input);
  }

  async completePasskeyAuthentication(
    input: OwnAuthEndpointInputMap["completePasskeyAuthentication"]
  ): Promise<AuthSessionPayload> {
    return this.setCreatedSession(await this.request("completePasskeyAuthentication", input));
  }

  listPasskeys(): Promise<OwnAuthEndpointOutputMap["listPasskeys"]> {
    return this.request("listPasskeys", undefined);
  }

  renamePasskey(
    input: OwnAuthEndpointInputMap["renamePasskey"]
  ): Promise<OwnAuthEndpointOutputMap["renamePasskey"]> {
    return this.request("renamePasskey", input);
  }

  async revokePasskey(
    input: OwnAuthEndpointInputMap["revokePasskey"]
  ): Promise<void> {
    await this.request("revokePasskey", input);
  }

  private async request<Id extends OwnAuthEndpointId>(
    id: Id,
    input: OwnAuthEndpointInputMap[Id]
  ): Promise<OwnAuthEndpointOutputMap[Id]> {
    const endpoint = getOwnAuthEndpoint(id);
    const headers = new Headers(await this.resolveHeaders());
    const init: RequestInit = {
      method: endpoint.method,
      credentials: "include",
      headers
    };

    if (endpoint.request) {
      headers.set("content-type", "application/json");
      init.body = JSON.stringify(input);
    }

    const { body } = await requestJsonWithCloudChallenge(
      this.fetchImpl,
      `${this.baseURL}${endpoint.path}`,
      init,
      this.cloudOptions
    );
    return body as OwnAuthEndpointOutputMap[Id];
  }

  private async resolveHeaders(): Promise<OwnAuthClientHeaders> {
    if (typeof this.configuredHeaders === "function") {
      return this.configuredHeaders();
    }
    return this.configuredHeaders ?? {};
  }

  private setCreatedSession(session: AuthSessionPayload): AuthSessionPayload {
    this.sessionRevision += 1;
    this.sessionLoaded = true;
    this.updateSnapshot({ data: session, isPending: false, error: null });
    return session;
  }

  private clearSession(): void {
    this.sessionRevision += 1;
    this.sessionLoaded = true;
    this.updateSnapshot({ data: null, isPending: false, error: null });
  }

  private acceptSignInResult(result: SignInPayload): SignInPayload {
    if (result.status === "complete") this.setCreatedSession(result);
    return result;
  }

  private updateUser(user: PublicAuthUser): void {
    if (!this.snapshot.data || this.snapshot.data.user.id !== user.id) {
      return;
    }
    this.sessionRevision += 1;
    this.updateSnapshot({
      ...this.snapshot,
      data: { ...this.snapshot.data, user },
      error: null
    });
  }

  private updateSnapshot(snapshot: OwnAuthSessionSnapshot): void {
    this.snapshot = snapshot;
    for (const listener of this.listeners) {
      listener();
    }
  }
}

export function createOwnAuthClient(options?: OwnAuthClientOptions): OwnAuthClient {
  return new OwnAuthClient(options);
}
