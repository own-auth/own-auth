import type {
  MfaChallenge,
  OAuthCredential,
  OAuthTransaction,
  PasskeyCredential,
  RecoveryCode,
  TotpFactor,
  WebAuthnChallenge
} from "../identity-types.js";
import {
  mapMfaChallenge,
  mapOAuthCredential,
  mapOAuthTransaction,
  mapPasskey,
  mapRecoveryCode,
  mapTotpFactor,
  mapWebAuthnChallenge
} from "../database-identity-mappers.js";
import {
  mfaChallengeColumns,
  mfaChallengeReturning,
  oauthCredentialReturning,
  oauthTransactionColumns,
  oauthTransactionReturning,
  passkeyColumns,
  passkeyReturning,
  recoveryCodeColumns,
  recoveryCodeReturning,
  totpFactorColumns,
  totpFactorReturning,
  webAuthnChallengeColumns,
  webAuthnChallengeReturning
} from "../database-identity-schema.js";
import { expectDatabaseValue } from "../database-row.js";
import type { DatabaseRow } from "../database-types.js";
import { D1StorageBase, placeholders } from "./d1-storage-base.js";

export class D1IdentityStorage extends D1StorageBase {
  async createOAuthTransaction(transaction: OAuthTransaction): Promise<OAuthTransaction> {
    return mapOAuthTransaction(await this.insertOne(
      "own_auth_oauth_transactions",
      oauthTransactionColumns,
      transaction,
      oauthTransactionReturning
    ));
  }

  async consumeOAuthTransaction(
    stateHash: string,
    flowKind: OAuthTransaction["flowKind"],
    consumedAt: Date
  ): Promise<OAuthTransaction | null> {
    const row = await this.prepare(
      `update own_auth_oauth_transactions set consumed_at = ?3
       where state_hash = ?1 and flow_kind = ?2 and consumed_at is null and expires_at > ?3
       returning ${oauthTransactionReturning}`,
      [stateHash, flowKind, consumedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapOAuthTransaction(row) : null;
  }

  async getOAuthCredentialByAccountId(accountId: string): Promise<OAuthCredential | null> {
    const row = await this.selectOne(
      `${oauthCredentialReturning} from own_auth_oauth_credentials where account_id = ?1`,
      [accountId]
    );
    return row ? mapOAuthCredential(row) : null;
  }

  async upsertOAuthCredential(credential: OAuthCredential): Promise<OAuthCredential> {
    const row = await this.prepare(
      `insert into own_auth_oauth_credentials
        (id, account_id, provider, ciphertext, nonce, encryption_key_id, scopes, created_at, updated_at, rotated_at)
       values (${placeholders(10)})
       on conflict (account_id) do update set
         provider = excluded.provider,
         ciphertext = excluded.ciphertext,
         nonce = excluded.nonce,
         encryption_key_id = excluded.encryption_key_id,
         scopes = excluded.scopes,
         updated_at = excluded.updated_at,
         rotated_at = excluded.rotated_at
       returning ${oauthCredentialReturning}`,
      [
        credential.id,
        credential.accountId,
        credential.provider,
        credential.ciphertext,
        credential.nonce,
        credential.encryptionKeyId,
        credential.scopes,
        credential.createdAt,
        credential.updatedAt,
        credential.rotatedAt
      ]
    ).first<DatabaseRow>();
    return mapOAuthCredential(expectDatabaseValue(row, "D1 OAuth credential upsert"));
  }

  async rotateOAuthCredential(
    id: string,
    expectedCiphertext: string,
    patch: Partial<OAuthCredential>
  ): Promise<OAuthCredential | null> {
    const entries = Object.entries({
      ciphertext: patch.ciphertext,
      nonce: patch.nonce,
      encryption_key_id: patch.encryptionKeyId,
      scopes: patch.scopes,
      updated_at: patch.updatedAt,
      rotated_at: patch.rotatedAt
    }).filter(([, value]) => value !== undefined);
    if (entries.length === 0) {
      const row = await this.selectOne(
        `${oauthCredentialReturning} from own_auth_oauth_credentials ` +
        "where id = ?1 and ciphertext = ?2",
        [id, expectedCiphertext]
      );
      return row ? mapOAuthCredential(row) : null;
    }
    const params: unknown[] = entries.map(([, value]) => value);
    params.push(id, expectedCiphertext);
    const assignments = entries.map(([column], index) => `${column} = ?${index + 1}`);
    const row = await this.prepare(
      `update own_auth_oauth_credentials set ${assignments.join(", ")}
       where id = ?${params.length - 1} and ciphertext = ?${params.length}
       returning ${oauthCredentialReturning}`,
      params
    ).first<DatabaseRow>();
    return row ? mapOAuthCredential(row) : null;
  }

  async deleteOAuthCredentialByAccountId(accountId: string): Promise<boolean> {
    return Boolean(await this.prepare(
      "delete from own_auth_oauth_credentials where account_id = ?1 returning id",
      [accountId]
    ).first<DatabaseRow>());
  }

  async createTotpFactor(factor: TotpFactor): Promise<TotpFactor> {
    return mapTotpFactor(await this.insertOne(
      "own_auth_mfa_factors",
      totpFactorColumns,
      factor,
      totpFactorReturning
    ));
  }

  async getTotpFactorById(id: string): Promise<TotpFactor | null> {
    const row = await this.selectOne(
      `${totpFactorReturning} from own_auth_mfa_factors where id = ?1`,
      [id]
    );
    return row ? mapTotpFactor(row) : null;
  }

  async getActiveTotpFactorByUserId(userId: string): Promise<TotpFactor | null> {
    const row = await this.selectOne(
      `${totpFactorReturning} from own_auth_mfa_factors ` +
      "where user_id = ?1 and status = 'active' order by created_at desc limit 1",
      [userId]
    );
    return row ? mapTotpFactor(row) : null;
  }

  async updateTotpFactor(id: string, patch: Partial<TotpFactor>): Promise<TotpFactor | null> {
    const row = await this.updateOne(
      "own_auth_mfa_factors",
      totpFactorColumns,
      id,
      patch,
      totpFactorReturning
    );
    return row ? mapTotpFactor(row) : null;
  }

  async activateTotpFactor(
    id: string,
    timestep: number,
    activatedAt: Date
  ): Promise<TotpFactor | null> {
    const row = await this.prepare(
      `update own_auth_mfa_factors
       set status = 'active', last_used_timestep = ?2, updated_at = ?3
       where id = ?1 and status = 'pending'
         and not exists (
           select 1
           from own_auth_mfa_factors active
           where active.user_id = own_auth_mfa_factors.user_id
             and active.status = 'active'
         )
       returning ${totpFactorReturning}`,
      [id, timestep, activatedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapTotpFactor(row) : null;
  }

  async useTotpTimestep(
    id: string,
    timestep: number,
    usedAt: Date
  ): Promise<TotpFactor | null> {
    const row = await this.prepare(
      `update own_auth_mfa_factors
       set last_used_timestep = ?2, updated_at = ?3
       where id = ?1 and status = 'active'
         and (last_used_timestep is null or last_used_timestep < ?2)
       returning ${totpFactorReturning}`,
      [id, timestep, usedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapTotpFactor(row) : null;
  }

  async replaceRecoveryCodes(userId: string, codes: RecoveryCode[]): Promise<void> {
    const statements = [
      this.prepare("delete from own_auth_recovery_codes where user_id = ?1", [userId]),
      ...codes.map((code) => this.insertStatement(
        "own_auth_recovery_codes",
        recoveryCodeColumns,
        code,
        recoveryCodeReturning
      ))
    ];
    await this.db.batch(statements);
  }

  async consumeRecoveryCode(
    userId: string,
    codeHash: string,
    consumedAt: Date
  ): Promise<RecoveryCode | null> {
    const row = await this.prepare(
      `update own_auth_recovery_codes set consumed_at = ?3
       where user_id = ?1 and code_hash = ?2 and consumed_at is null
       returning ${recoveryCodeReturning}`,
      [userId, codeHash, consumedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapRecoveryCode(row) : null;
  }

  async createMfaChallenge(challenge: MfaChallenge, authorityExpiresAt?: Date): Promise<MfaChallenge> {
    return mapMfaChallenge(await this.insertOne(
      "own_auth_mfa_challenges",
      mfaChallengeColumns,
      challenge,
      mfaChallengeReturning,
      authorityExpiresAt
    ));
  }

  async getMfaChallengeById(id: string): Promise<MfaChallenge | null> {
    const row = await this.selectOne(
      `${mfaChallengeReturning} from own_auth_mfa_challenges where id = ?1`,
      [id]
    );
    return row ? mapMfaChallenge(row) : null;
  }

  async getMfaChallengeByTokenHash(tokenHash: string): Promise<MfaChallenge | null> {
    const row = await this.selectOne(
      `${mfaChallengeReturning} from own_auth_mfa_challenges where token_hash = ?1`,
      [tokenHash]
    );
    return row ? mapMfaChallenge(row) : null;
  }

  async incrementMfaChallengeAttempts(
    id: string,
    attemptedAt: Date
  ): Promise<MfaChallenge | null> {
    const row = await this.prepare(
      `update own_auth_mfa_challenges set attempts = attempts + 1
       where id = ?1 and consumed_at is null and expires_at > ?2 and attempts < max_attempts
       returning ${mfaChallengeReturning}`,
      [id, attemptedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapMfaChallenge(row) : null;
  }

  async consumeMfaChallenge(id: string, consumedAt: Date): Promise<MfaChallenge | null> {
    const row = await this.prepare(
      `update own_auth_mfa_challenges set consumed_at = ?2
       where id = ?1 and consumed_at is null and expires_at > ?2 and attempts < max_attempts
       returning ${mfaChallengeReturning}`,
      [id, consumedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapMfaChallenge(row) : null;
  }

  async createPasskeyCredential(credential: PasskeyCredential): Promise<PasskeyCredential> {
    return mapPasskey(await this.insertOne(
      "own_auth_passkeys",
      passkeyColumns,
      credential,
      passkeyReturning
    ));
  }

  async getPasskeyCredentialById(id: string): Promise<PasskeyCredential | null> {
    const row = await this.selectOne(`${passkeyReturning} from own_auth_passkeys where id = ?1`, [id]);
    return row ? mapPasskey(row) : null;
  }

  async getPasskeyCredentialByCredentialId(credentialId: string): Promise<PasskeyCredential | null> {
    const row = await this.selectOne(
      `${passkeyReturning} from own_auth_passkeys where credential_id = ?1`,
      [credentialId]
    );
    return row ? mapPasskey(row) : null;
  }

  async listPasskeyCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    const rows = await this.selectMany(
      `${passkeyReturning} from own_auth_passkeys where user_id = ?1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapPasskey);
  }

  async updatePasskeyCredential(
    id: string,
    patch: Partial<PasskeyCredential>
  ): Promise<PasskeyCredential | null> {
    const row = await this.updateOne(
      "own_auth_passkeys",
      passkeyColumns,
      id,
      patch,
      passkeyReturning
    );
    return row ? mapPasskey(row) : null;
  }

  async updatePasskeyCounter(
    id: string,
    expectedCounter: number,
    nextCounter: number,
    usedAt: Date
  ): Promise<PasskeyCredential | null> {
    const row = await this.prepare(
      `update own_auth_passkeys
       set counter = ?3, last_used_at = ?4, updated_at = ?4
       where id = ?1 and counter = ?2
       returning ${passkeyReturning}`,
      [id, expectedCounter, nextCounter, usedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapPasskey(row) : null;
  }

  async deletePasskeyCredential(id: string): Promise<boolean> {
    return Boolean(await this.prepare(
      "delete from own_auth_passkeys where id = ?1 returning id",
      [id]
    ).first<DatabaseRow>());
  }

  async createWebAuthnChallenge(challenge: WebAuthnChallenge): Promise<WebAuthnChallenge> {
    return mapWebAuthnChallenge(await this.insertOne(
      "own_auth_webauthn_challenges",
      webAuthnChallengeColumns,
      challenge,
      webAuthnChallengeReturning
    ));
  }

  async consumeWebAuthnChallenge(
    challengeHash: string,
    purpose: WebAuthnChallenge["purpose"],
    consumedAt: Date
  ): Promise<WebAuthnChallenge | null> {
    const row = await this.prepare(
      `update own_auth_webauthn_challenges set consumed_at = ?3
       where challenge_hash = ?1 and purpose = ?2 and consumed_at is null and expires_at > ?3
       returning ${webAuthnChallengeReturning}`,
      [challengeHash, purpose, consumedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapWebAuthnChallenge(row) : null;
  }
}
