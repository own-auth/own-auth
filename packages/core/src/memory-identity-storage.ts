import type {
  MfaChallenge,
  OAuthCredential,
  OAuthTransaction,
  PasskeyCredential,
  RecoveryCode,
  TotpFactor,
  WebAuthnChallenge
} from "./identity-types.js";
import {
  cloneStored,
  findStored,
  someStored,
  updateStoredEntity
} from "./memory-storage-helpers.js";
import { createIdentityConflictError } from "./errors.js";
import type { Account } from "./types.js";

export class MemoryIdentityStorage {
  protected hasUnprovedCredentials(userId: string, verifiedAccountId?: string): boolean {
    return someStored(this.accounts, (account) => account.userId === userId &&
      account.provider !== "password" && account.provider !== "magic_link" && account.id !== verifiedAccountId) ||
      [this.passkeys, this.totpFactors, this.recoveryCodes, this.mfaChallenges, this.webAuthnChallenges]
        .some((records) => someStored<{ userId: string | null }>(records, (record) => record.userId === userId));
  }
  protected readonly accounts = new Map<string, Account>();
  private readonly oauthTransactions = new Map<string, OAuthTransaction>();
  private readonly oauthCredentials = new Map<string, OAuthCredential>();
  private readonly totpFactors = new Map<string, TotpFactor>();
  private readonly recoveryCodes = new Map<string, RecoveryCode>();
  private readonly mfaChallenges = new Map<string, MfaChallenge>();
  protected readonly passkeys = new Map<string, PasskeyCredential>();
  private readonly webAuthnChallenges = new Map<string, WebAuthnChallenge>();

  async createAccount(account: Account): Promise<Account> {
    if (this.hasProviderAccount(account.provider, account.providerAccountId)) {
      throw createIdentityConflictError("providerAccount");
    }
    this.accounts.set(account.id, cloneStored(account));
    return cloneStored(account);
  }

  async getAccountByProvider(
    provider: string,
    providerAccountId: string
  ): Promise<Account | null> {
    return findStored(
      this.accounts,
      (account) =>
        account.provider === provider && account.providerAccountId === providerAccountId
    );
  }

  async listAccountsByUserId(userId: string): Promise<Account[]> {
    return [...this.accounts.values()]
      .filter((account) => account.userId === userId)
      .map(cloneStored);
  }

  async deleteAccount(id: string): Promise<boolean> {
    return this.deleteStoredAccount(id);
  }

  protected deleteStoredAccount(id: string): boolean {
    if (!this.accounts.delete(id)) {
      return false;
    }
    for (const [credentialId, credential] of this.oauthCredentials) {
      if (credential.accountId === id) {
        this.oauthCredentials.delete(credentialId);
      }
    }
    return true;
  }

  protected hasProviderAccount(provider: string, providerAccountId: string): boolean {
    return [...this.accounts.values()].some(
      (account) =>
        account.provider === provider &&
        account.providerAccountId === providerAccountId
    );
  }

  async createOAuthTransaction(transaction: OAuthTransaction): Promise<OAuthTransaction> {
    this.oauthTransactions.set(transaction.id, cloneStored(transaction));
    return cloneStored(transaction);
  }

  async consumeOAuthTransaction(
    stateHash: string,
    flowKind: OAuthTransaction["flowKind"],
    consumedAt: Date
  ): Promise<OAuthTransaction | null> {
    const match = [...this.oauthTransactions.values()].find(
      (transaction) =>
        transaction.stateHash === stateHash &&
        transaction.flowKind === flowKind &&
        !transaction.consumedAt &&
        transaction.expiresAt > consumedAt
    );
    return match
      ? updateStoredEntity(this.oauthTransactions, match.id, { consumedAt })
      : null;
  }

  async getOAuthCredentialByAccountId(accountId: string): Promise<OAuthCredential | null> {
    return findStored(
      this.oauthCredentials,
      (credential) => credential.accountId === accountId
    );
  }

  async upsertOAuthCredential(credential: OAuthCredential): Promise<OAuthCredential> {
    const existing = await this.getOAuthCredentialByAccountId(credential.accountId);
    if (existing) {
      const updated = { ...credential, id: existing.id, createdAt: existing.createdAt };
      this.oauthCredentials.set(existing.id, cloneStored(updated));
      return cloneStored(updated);
    }
    this.oauthCredentials.set(credential.id, cloneStored(credential));
    return cloneStored(credential);
  }

  async rotateOAuthCredential(
    id: string,
    expectedCiphertext: string,
    patch: Partial<OAuthCredential>
  ): Promise<OAuthCredential | null> {
    const existing = this.oauthCredentials.get(id);
    if (!existing || existing.ciphertext !== expectedCiphertext) {
      return null;
    }
    return updateStoredEntity(this.oauthCredentials, id, patch);
  }

  async deleteOAuthCredentialByAccountId(accountId: string): Promise<boolean> {
    const credential = await this.getOAuthCredentialByAccountId(accountId);
    return credential ? this.oauthCredentials.delete(credential.id) : false;
  }

  async createTotpFactor(factor: TotpFactor): Promise<TotpFactor> {
    this.totpFactors.set(factor.id, cloneStored(factor));
    return cloneStored(factor);
  }

  async getTotpFactorById(id: string): Promise<TotpFactor | null> {
    const factor = this.totpFactors.get(id);
    return factor ? cloneStored(factor) : null;
  }

  async getActiveTotpFactorByUserId(userId: string): Promise<TotpFactor | null> {
    return findStored(
      this.totpFactors,
      (factor) => factor.userId === userId && factor.status === "active"
    );
  }

  async updateTotpFactor(id: string, patch: Partial<TotpFactor>): Promise<TotpFactor | null> {
    return updateStoredEntity(this.totpFactors, id, patch);
  }

  async activateTotpFactor(
    id: string,
    timestep: number,
    activatedAt: Date
  ): Promise<TotpFactor | null> {
    const factor = this.totpFactors.get(id);
    if (!factor || factor.status !== "pending") {
      return null;
    }
    const activeFactor = [...this.totpFactors.values()].some(
      (candidate) =>
        candidate.userId === factor.userId &&
        candidate.status === "active"
    );
    if (activeFactor) {
      return null;
    }
    return updateStoredEntity(this.totpFactors, id, {
      status: "active",
      lastUsedTimestep: timestep,
      updatedAt: activatedAt
    });
  }

  async useTotpTimestep(
    id: string,
    timestep: number,
    usedAt: Date
  ): Promise<TotpFactor | null> {
    const factor = this.totpFactors.get(id);
    if (
      !factor ||
      factor.status !== "active" ||
      (factor.lastUsedTimestep !== null && factor.lastUsedTimestep >= timestep)
    ) {
      return null;
    }
    return updateStoredEntity(this.totpFactors, id, {
      lastUsedTimestep: timestep,
      updatedAt: usedAt
    });
  }

  async replaceRecoveryCodes(userId: string, codes: RecoveryCode[]): Promise<void> {
    for (const [id, code] of this.recoveryCodes) {
      if (code.userId === userId) {
        this.recoveryCodes.delete(id);
      }
    }
    for (const code of codes) {
      this.recoveryCodes.set(code.id, cloneStored(code));
    }
  }

  async consumeRecoveryCode(
    userId: string,
    codeHash: string,
    consumedAt: Date
  ): Promise<RecoveryCode | null> {
    const code = [...this.recoveryCodes.values()].find(
      (candidate) =>
        candidate.userId === userId && candidate.codeHash === codeHash && !candidate.consumedAt
    );
    return code
      ? updateStoredEntity(this.recoveryCodes, code.id, { consumedAt })
      : null;
  }

  async createMfaChallenge(challenge: MfaChallenge): Promise<MfaChallenge> {
    this.mfaChallenges.set(challenge.id, cloneStored(challenge));
    return cloneStored(challenge);
  }

  async getMfaChallengeById(id: string): Promise<MfaChallenge | null> {
    const challenge = this.mfaChallenges.get(id);
    return challenge ? cloneStored(challenge) : null;
  }

  async getMfaChallengeByTokenHash(tokenHash: string): Promise<MfaChallenge | null> {
    return findStored(
      this.mfaChallenges,
      (challenge) => challenge.tokenHash === tokenHash
    );
  }

  async incrementMfaChallengeAttempts(
    id: string,
    attemptedAt: Date
  ): Promise<MfaChallenge | null> {
    const challenge = this.mfaChallenges.get(id);
    if (!isUsableMfaChallenge(challenge, attemptedAt)) {
      return null;
    }
    return updateStoredEntity(this.mfaChallenges, id, {
      attempts: challenge.attempts + 1
    });
  }

  async consumeMfaChallenge(id: string, consumedAt: Date): Promise<MfaChallenge | null> {
    const challenge = this.mfaChallenges.get(id);
    return isUsableMfaChallenge(challenge, consumedAt)
      ? updateStoredEntity(this.mfaChallenges, id, { consumedAt })
      : null;
  }

  async createPasskeyCredential(credential: PasskeyCredential): Promise<PasskeyCredential> {
    if (
      [...this.passkeys.values()].some(
        (candidate) => candidate.credentialId === credential.credentialId
      )
    ) {
      throw new Error("Passkey credential already exists");
    }
    this.passkeys.set(credential.id, cloneStored(credential));
    return cloneStored(credential);
  }

  async getPasskeyCredentialById(id: string): Promise<PasskeyCredential | null> {
    const credential = this.passkeys.get(id);
    return credential ? cloneStored(credential) : null;
  }

  async getPasskeyCredentialByCredentialId(
    credentialId: string
  ): Promise<PasskeyCredential | null> {
    return findStored(
      this.passkeys,
      (credential) => credential.credentialId === credentialId
    );
  }

  async listPasskeyCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    return [...this.passkeys.values()]
      .filter((credential) => credential.userId === userId)
      .map(cloneStored);
  }

  async updatePasskeyCredential(
    id: string,
    patch: Partial<PasskeyCredential>
  ): Promise<PasskeyCredential | null> {
    return updateStoredEntity(this.passkeys, id, patch);
  }

  async updatePasskeyCounter(
    id: string,
    expectedCounter: number,
    nextCounter: number,
    usedAt: Date
  ): Promise<PasskeyCredential | null> {
    const credential = this.passkeys.get(id);
    if (!credential || credential.counter !== expectedCounter) {
      return null;
    }
    return updateStoredEntity(this.passkeys, id, {
      counter: nextCounter,
      lastUsedAt: usedAt,
      updatedAt: usedAt
    });
  }

  async deletePasskeyCredential(id: string): Promise<boolean> {
    return this.deleteStoredPasskey(id);
  }

  protected deleteStoredPasskey(id: string): boolean {
    return this.passkeys.delete(id);
  }

  async createWebAuthnChallenge(challenge: WebAuthnChallenge): Promise<WebAuthnChallenge> {
    this.webAuthnChallenges.set(challenge.id, cloneStored(challenge));
    return cloneStored(challenge);
  }

  async consumeWebAuthnChallenge(
    challengeHash: string,
    purpose: WebAuthnChallenge["purpose"],
    consumedAt: Date
  ): Promise<WebAuthnChallenge | null> {
    const challenge = [...this.webAuthnChallenges.values()].find(
      (candidate) =>
        candidate.challengeHash === challengeHash &&
        candidate.purpose === purpose &&
        !candidate.consumedAt &&
        candidate.expiresAt > consumedAt
    );
    return challenge
      ? updateStoredEntity(this.webAuthnChallenges, challenge.id, { consumedAt })
      : null;
  }
}

function isUsableMfaChallenge(
  challenge: MfaChallenge | undefined,
  at: Date
): challenge is MfaChallenge {
  return Boolean(
    challenge &&
    !challenge.consumedAt &&
    challenge.expiresAt > at &&
    challenge.attempts < challenge.maxAttempts
  );
}
