import type { createOwnAuth } from "../../src/index.js";
import type { AuthStorage } from "../../src/storage.js";
import {
  assertConformance,
  assertConformanceEqual,
  assertSingleSettledWinner,
  requireCompleteResult,
  requireConformanceValue
} from "./conformance-assertions.js";
import {
  uniqueConformanceEmail as uniqueEmail,
  uniqueConformancePhone as uniquePhone
} from "./conformance-values.js";

type Auth = ReturnType<typeof createOwnAuth>;

export type StorageBarrierMethod =
  | "acceptInvitationAtomically"
  | "claimEmailOwnershipAtomically"
  | "createUser"
  | "consumeToken"
  | "consumeSmsOtp"
  | "incrementSmsOtpAttempts"
  | "removeAuthenticationMethodAtomically";

export interface AuthConcurrencyHarness {
  auth: readonly [Auth, Auth];
  storage: readonly [AuthStorage, AuthStorage];
}

export interface AuthConcurrencyCase {
  name: string;
  barrierMethod: StorageBarrierMethod;
  sms?: { maxAttempts: number };
  run(harness: AuthConcurrencyHarness): Promise<void>;
}

export const authConcurrencyCases: readonly AuthConcurrencyCase[] = [
  {
    name: "maps one concurrent email collision to a typed auth error",
    barrierMethod: "createUser",
    async run({ auth, storage }) {
      const email = uniqueEmail("collision");
      const input = { email, password: "correct-horse" };

      assertSingleSettledWinner(await Promise.allSettled([
        auth[0].signUpEmailPassword(input),
        auth[1].signUpEmailPassword(input)
      ]), "email_already_exists", "email signup collision");

      const user = requireConformanceValue(
        await storage[0].getUserByEmail(email),
        "Signup winner was not persisted"
      );
      assertConformanceEqual(
        (await storage[0].listAccountsByUserId(user.id)).length,
        1,
        "signup account count"
      );
      assertConformanceEqual(
        (await storage[0].listSessionsByUserId(user.id)).length,
        1,
        "signup session count"
      );
    }
  },
  {
    name: "allows only one concurrent magic-link verification",
    barrierMethod: "claimEmailOwnershipAtomically",
    async run({ auth, storage }) {
      const email = uniqueEmail("magic");
      const delivery = await auth[0].requestMagicLink({ email });
      const token = requireConformanceValue(delivery.token, "Magic-link token was not exposed");

      assertSingleSettledWinner(await Promise.allSettled([
        auth[0].verifyMagicLink({ token }),
        auth[1].verifyMagicLink({ token })
      ]), "token_already_used", "magic-link verification");

      const user = requireConformanceValue(
        await storage[0].getUserByEmail(email),
        "Magic-link user was not persisted"
      );
      assertConformanceEqual(
        (await storage[0].listSessionsByUserId(user.id)).length,
        1,
        "magic-link session count"
      );
    }
  },
  {
    name: "allows only one concurrent email verification",
    barrierMethod: "claimEmailOwnershipAtomically",
    async run({ auth, storage }) {
      const email = uniqueEmail("verify");
      await auth[0].signUpEmailPassword({ email, password: "correct-horse" });
      const delivery = await auth[0].requestEmailVerification({ email });
      const token = requireConformanceValue(
        delivery.token,
        "Email-verification token was not exposed"
      );

      assertSingleSettledWinner(await Promise.allSettled([
        auth[0].verifyEmail({ token }),
        auth[1].verifyEmail({ token })
      ]), "token_already_used", "email verification");

      assertConformance(
        (await storage[0].getUserByEmail(email))?.emailVerifiedAt instanceof Date,
        "Email verification was not persisted"
      );
    }
  },
  {
    name: "allows only one concurrent password reset",
    barrierMethod: "claimEmailOwnershipAtomically",
    async run({ auth }) {
      const email = uniqueEmail("reset");
      await auth[0].signUpEmailPassword({ email, password: "correct-horse" });
      const delivery = await auth[0].requestPasswordReset({ email });
      const token = requireConformanceValue(delivery.token, "Password-reset token was not exposed");
      const passwords = ["new-password-one", "new-password-two"] as const;

      const winner = assertSingleSettledWinner(await Promise.allSettled([
        auth[0].resetPassword({ token, newPassword: passwords[0] }),
        auth[1].resetPassword({ token, newPassword: passwords[1] })
      ]), "token_already_used", "password reset");

      const signIn = requireCompleteResult(await auth[0].signInEmailPassword({
        email,
        password: passwords[winner]!
      }), "password-reset sign-in");
      assertConformanceEqual(signIn.user.email, email, "password-reset sign-in email");
    }
  },
  {
    name: "allows only one concurrent invitation acceptance",
    barrierMethod: "acceptInvitationAtomically",
    async run({ auth, storage }) {
      const owner = await auth[0].signUpEmailPassword({
        email: uniqueEmail("owner"),
        password: "correct-horse"
      });
      const invited = await auth[0].signUpEmailPassword({
        email: uniqueEmail("invited"),
        password: "correct-horse"
      });
      const { organisation } = await auth[0].createOrganisation({
        name: `Concurrent organisation ${crypto.randomUUID()}`,
        ownerUserId: owner.user.id
      });
      const invite = await auth[0].inviteMember({
        organisationId: organisation.id,
        email: requireConformanceValue(invited.user.email, "Invited user has no email"),
        invitedByUserId: owner.user.id
      });
      const input = {
        token: requireConformanceValue(invite.token, "Invitation token was not exposed"),
        userId: invited.user.id
      };

      assertSingleSettledWinner(await Promise.allSettled([
        auth[0].acceptInvite(input),
        auth[1].acceptInvite(input)
      ]), "token_already_used", "invitation acceptance");

      assertConformanceEqual(
        (await storage[0].listOrganisationMembers(organisation.id))
          .filter((member) => member.userId === invited.user.id).length,
        1,
        "invited organisation-member count"
      );
    }
  },
  {
    name: "preserves one login method during concurrent provider unlinking",
    barrierMethod: "removeAuthenticationMethodAtomically",
    async run({ auth, storage }) {
      const now = new Date();
      const userId = `usr_${crypto.randomUUID()}`;
      await storage[0].createUser({
        id: userId,
        email: null,
        emailVerifiedAt: null,
        phone: null,
        phoneVerifiedAt: null,
        passwordHash: null,
        name: null,
        imageUrl: null,
        disabledAt: null,
        metadata: {},
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null
      });
      const providers = ["google", "github"] as const;
      const providerAccountIds = providers.map(() => crypto.randomUUID());
      await Promise.all(providers.map((provider, index) =>
        storage[0].createAccount({
          id: `acct_${crypto.randomUUID()}`,
          userId,
          provider,
          providerAccountId: providerAccountIds[index]!,
          providerEmail: null,
          providerPhone: null,
          createdAt: now,
          updatedAt: now
        })
      ));

      assertSingleSettledWinner(await Promise.allSettled(
        providers.map((provider, index) =>
          auth[index as 0 | 1].unlinkOAuthProvider({
            actorUserId: userId,
            provider,
            providerAccountId: providerAccountIds[index]!
          })
        )
      ), "authentication_method_required", "provider unlinking");
      assertConformanceEqual(
        (await storage[0].listAccountsByUserId(userId)).length,
        1,
        "remaining provider account count"
      );
    }
  },
  {
    name: "allows only one concurrent SMS OTP verification",
    barrierMethod: "consumeSmsOtp",
    async run({ auth, storage }) {
      const phone = uniquePhone();
      const delivery = await auth[0].requestSmsOtp({ phone });
      const code = requireConformanceValue(delivery.code, "SMS code was not exposed");

      assertSingleSettledWinner(await Promise.allSettled([
        auth[0].verifySmsOtp({ phone, code }),
        auth[1].verifySmsOtp({ phone, code })
      ]), "invalid_otp", "SMS OTP verification");

      const user = requireConformanceValue(
        await storage[0].getUserByPhone(phone),
        "SMS user was not persisted"
      );
      assertConformanceEqual(
        (await storage[0].listSessionsByUserId(user.id)).length,
        1,
        "SMS session count"
      );
    }
  },
  {
    name: "counts concurrent wrong SMS OTP attempts",
    barrierMethod: "incrementSmsOtpAttempts",
    sms: { maxAttempts: 2 },
    async run({ auth, storage }) {
      const phone = uniquePhone();
      const delivery = await auth[0].requestSmsOtp({ phone });
      const validCode = requireConformanceValue(delivery.code, "SMS code was not exposed");
      const wrongCode = validCode === "000000" ? "111111" : "000000";

      const results = await Promise.allSettled([
        auth[0].verifySmsOtp({ phone, code: wrongCode }),
        auth[1].verifySmsOtp({ phone, code: wrongCode })
      ]);
      assertConformanceEqual(
        results.filter((result) => result.status === "rejected").length,
        2,
        "wrong SMS rejection count"
      );
      assertConformanceEqual(
        (await storage[0].getLatestSmsOtp(phone, "phone_login"))?.attempts,
        2,
        "persisted SMS attempt count"
      );
    }
  }
];
