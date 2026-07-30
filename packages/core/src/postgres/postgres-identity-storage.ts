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
  recoveryCodeReturning,
  totpFactorColumns,
  totpFactorReturning,
  webAuthnChallengeColumns,
  webAuthnChallengeReturning
} from "../database-identity-schema.js";
import { PostgresStorageBase } from "./postgres-storage-base.js";
import { isPostgresUniqueConstraint } from "./postgres-errors.js";
import { expectOne } from "./postgres-row.js";
import type { Row } from "./postgres-types.js";

export class PostgresIdentityStorage extends PostgresStorageBase {
  async createOAuthTransaction(transaction: OAuthTransaction): Promise<OAuthTransaction> {
    return mapOAuthTransaction(
      await this.insertOne(
        "own_auth_oauth_transactions",
        oauthTransactionColumns,
        transaction,
        oauthTransactionReturning
      )
    );
  }

  async consumeOAuthTransaction(
    stateHash: string,
    flowKind: OAuthTransaction["flowKind"],
    consumedAt: Date
  ): Promise<OAuthTransaction | null> {
    const result = await this.db.query<Row>(
      `update own_auth_oauth_transactions
       set consumed_at = $3
       where state_hash = $1 and flow_kind = $2 and consumed_at is null and expires_at > $3
       returning ${oauthTransactionReturning}`,
      [stateHash, flowKind, consumedAt]
    );
    return result.rows[0] ? mapOAuthTransaction(result.rows[0]) : null;
  }

  async getOAuthCredentialByAccountId(accountId: string): Promise<OAuthCredential | null> {
    const row = await this.selectOne(
      `${oauthCredentialReturning} from own_auth_oauth_credentials where account_id = $1`,
      [accountId]
    );
    return row ? mapOAuthCredential(row) : null;
  }

  async upsertOAuthCredential(credential: OAuthCredential): Promise<OAuthCredential> {
    const result = await this.db.query<Row>(
      `insert into own_auth_oauth_credentials
        (id, account_id, provider, ciphertext, nonce, encryption_key_id, scopes, created_at, updated_at, rotated_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
    );
    return mapOAuthCredential(expectOne(result.rows));
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
        "where id = $1 and ciphertext = $2",
        [id, expectedCiphertext]
      );
      return row ? mapOAuthCredential(row) : null;
    }
    const params = entries.map(([, value]) => value);
    params.push(id, expectedCiphertext);
    const assignments = entries.map(([column], index) => `${column} = $${index + 1}`);
    const result = await this.db.query<Row>(
      `update own_auth_oauth_credentials set ${assignments.join(", ")}
       where id = $${params.length - 1} and ciphertext = $${params.length}
       returning ${oauthCredentialReturning}`,
      params
    );
    return result.rows[0] ? mapOAuthCredential(result.rows[0]) : null;
  }

  async deleteOAuthCredentialByAccountId(accountId: string): Promise<boolean> {
    const result = await this.db.query<Row>(
      "delete from own_auth_oauth_credentials where account_id = $1 returning id",
      [accountId]
    );
    return result.rows.length > 0;
  }

  async createTotpFactor(factor: TotpFactor): Promise<TotpFactor> {
    return mapTotpFactor(
      await this.insertOne("own_auth_mfa_factors", totpFactorColumns, factor, totpFactorReturning)
    );
  }

  async getTotpFactorById(id: string): Promise<TotpFactor | null> {
    const row = await this.selectOne(
      `${totpFactorReturning} from own_auth_mfa_factors where id = $1`,
      [id]
    );
    return row ? mapTotpFactor(row) : null;
  }

  async getActiveTotpFactorByUserId(userId: string): Promise<TotpFactor | null> {
    const row = await this.selectOne(
      `${totpFactorReturning} from own_auth_mfa_factors where user_id = $1 and status = 'active' order by created_at desc limit 1`,
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
    try {
      const result = await this.db.query<Row>(
        `update own_auth_mfa_factors
         set status = 'active', last_used_timestep = $2, updated_at = $3
         where id = $1 and status = 'pending'
           and not exists (
             select 1
             from own_auth_mfa_factors active
             where active.user_id = own_auth_mfa_factors.user_id
               and active.status = 'active'
           )
         returning ${totpFactorReturning}`,
        [id, timestep, activatedAt]
      );
      return result.rows[0] ? mapTotpFactor(result.rows[0]) : null;
    } catch (error) {
      if (
        isPostgresUniqueConstraint(
          error,
          "own_auth_mfa_factors_one_active_totp_idx"
        )
      ) {
        return null;
      }
      throw error;
    }
  }

  async useTotpTimestep(
    id: string,
    timestep: number,
    usedAt: Date
  ): Promise<TotpFactor | null> {
    const result = await this.db.query<Row>(
      `update own_auth_mfa_factors
       set last_used_timestep = $2, updated_at = $3
       where id = $1 and status = 'active'
         and (last_used_timestep is null or last_used_timestep < $2)
       returning ${totpFactorReturning}`,
      [id, timestep, usedAt]
    );
    return result.rows[0] ? mapTotpFactor(result.rows[0]) : null;
  }

  async replaceRecoveryCodes(userId: string, codes: RecoveryCode[]): Promise<void> {
    await this.db.query(
      `with deleted as (
         delete from own_auth_recovery_codes where user_id = $1
       )
       insert into own_auth_recovery_codes (id, user_id, code_hash, consumed_at, created_at)
       select value->>'id', value->>'userId', value->>'codeHash', null,
              (value->>'createdAt')::timestamptz
       from jsonb_array_elements($2::jsonb) as value`,
      [userId, JSON.stringify(codes)]
    );
  }

  async consumeRecoveryCode(
    userId: string,
    codeHash: string,
    consumedAt: Date
  ): Promise<RecoveryCode | null> {
    const result = await this.db.query<Row>(
      `update own_auth_recovery_codes set consumed_at = $3
       where user_id = $1 and code_hash = $2 and consumed_at is null
       returning ${recoveryCodeReturning}`,
      [userId, codeHash, consumedAt]
    );
    return result.rows[0] ? mapRecoveryCode(result.rows[0]) : null;
  }

  async createMfaChallenge(challenge: MfaChallenge): Promise<MfaChallenge> {
    return mapMfaChallenge(
      await this.insertOne(
        "own_auth_mfa_challenges",
        mfaChallengeColumns,
        challenge,
        mfaChallengeReturning
      )
    );
  }

  async getMfaChallengeById(id: string): Promise<MfaChallenge | null> {
    const row = await this.selectOne(
      `${mfaChallengeReturning} from own_auth_mfa_challenges where id = $1`,
      [id]
    );
    return row ? mapMfaChallenge(row) : null;
  }

  async getMfaChallengeByTokenHash(tokenHash: string): Promise<MfaChallenge | null> {
    const row = await this.selectOne(
      `${mfaChallengeReturning} from own_auth_mfa_challenges where token_hash = $1`,
      [tokenHash]
    );
    return row ? mapMfaChallenge(row) : null;
  }

  async incrementMfaChallengeAttempts(
    id: string,
    attemptedAt: Date
  ): Promise<MfaChallenge | null> {
    const result = await this.db.query<Row>(
      `update own_auth_mfa_challenges set attempts = attempts + 1
       where id = $1 and consumed_at is null and expires_at > $2 and attempts < max_attempts
       returning ${mfaChallengeReturning}`,
      [id, attemptedAt]
    );
    return result.rows[0] ? mapMfaChallenge(result.rows[0]) : null;
  }

  async consumeMfaChallenge(id: string, consumedAt: Date): Promise<MfaChallenge | null> {
    const result = await this.db.query<Row>(
      `update own_auth_mfa_challenges set consumed_at = $2
       where id = $1 and consumed_at is null and expires_at > $2 and attempts < max_attempts
       returning ${mfaChallengeReturning}`,
      [id, consumedAt]
    );
    return result.rows[0] ? mapMfaChallenge(result.rows[0]) : null;
  }

  async createPasskeyCredential(credential: PasskeyCredential): Promise<PasskeyCredential> {
    return mapPasskey(
      await this.insertOne("own_auth_passkeys", passkeyColumns, credential, passkeyReturning)
    );
  }

  async getPasskeyCredentialById(id: string): Promise<PasskeyCredential | null> {
    const row = await this.selectOne(`${passkeyReturning} from own_auth_passkeys where id = $1`, [id]);
    return row ? mapPasskey(row) : null;
  }

  async getPasskeyCredentialByCredentialId(
    credentialId: string
  ): Promise<PasskeyCredential | null> {
    const row = await this.selectOne(
      `${passkeyReturning} from own_auth_passkeys where credential_id = $1`,
      [credentialId]
    );
    return row ? mapPasskey(row) : null;
  }

  async listPasskeyCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    const rows = await this.selectMany(
      `${passkeyReturning} from own_auth_passkeys where user_id = $1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapPasskey);
  }

  async updatePasskeyCredential(
    id: string,
    patch: Partial<PasskeyCredential>
  ): Promise<PasskeyCredential | null> {
    const row = await this.updateOne("own_auth_passkeys", passkeyColumns, id, patch, passkeyReturning);
    return row ? mapPasskey(row) : null;
  }

  async updatePasskeyCounter(
    id: string,
    expectedCounter: number,
    nextCounter: number,
    usedAt: Date
  ): Promise<PasskeyCredential | null> {
    const result = await this.db.query<Row>(
      `update own_auth_passkeys
       set counter = $3, last_used_at = $4, updated_at = $4
       where id = $1 and counter = $2
       returning ${passkeyReturning}`,
      [id, expectedCounter, nextCounter, usedAt]
    );
    return result.rows[0] ? mapPasskey(result.rows[0]) : null;
  }

  async deletePasskeyCredential(id: string): Promise<boolean> {
    const result = await this.db.query<Row>(
      "delete from own_auth_passkeys where id = $1 returning id",
      [id]
    );
    return result.rows.length > 0;
  }

  async createWebAuthnChallenge(challenge: WebAuthnChallenge): Promise<WebAuthnChallenge> {
    return mapWebAuthnChallenge(
      await this.insertOne(
        "own_auth_webauthn_challenges",
        webAuthnChallengeColumns,
        challenge,
        webAuthnChallengeReturning
      )
    );
  }

  async consumeWebAuthnChallenge(
    challengeHash: string,
    purpose: WebAuthnChallenge["purpose"],
    consumedAt: Date
  ): Promise<WebAuthnChallenge | null> {
    const result = await this.db.query<Row>(
      `update own_auth_webauthn_challenges set consumed_at = $3
       where challenge_hash = $1 and purpose = $2 and consumed_at is null and expires_at > $3
       returning ${webAuthnChallengeReturning}`,
      [challengeHash, purpose, consumedAt]
    );
    return result.rows[0] ? mapWebAuthnChallenge(result.rows[0]) : null;
  }
}
