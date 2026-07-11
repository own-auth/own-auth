import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");
const repositoryFileUrl = "https://github.com/tina-li-xx/own-auth/blob/main";

const files = [
  {
    source: "README.md",
    target: "packages/core/README.md",
    transform: packageReadme
  },
  {
    source: "docs/installation.md",
    target: "packages/core/docs/installation.md"
  },
  {
    source: "docs/configuration.md",
    target: "packages/core/docs/configuration.md"
  },
  {
    source: "docs/introduction.md",
    target: "packages/core/docs/introduction.md"
  },
  {
    source: "docs/security-model.md",
    target: "packages/core/docs/security-model.md"
  },
  {
    source: "docs/security/rate-limiting.md",
    target: "packages/core/docs/security/rate-limiting.md"
  },
  {
    source: "docs/security/audit-logs.md",
    target: "packages/core/docs/security/audit-logs.md"
  },
  {
    source: "docs/passwords.md",
    target: "packages/core/docs/passwords.md"
  },
  {
    source: "docs/magic-links.md",
    target: "packages/core/docs/magic-links.md"
  },
  {
    source: "docs/phone-login.md",
    target: "packages/core/docs/phone-login.md"
  },
  {
    source: "docs/email-verification.md",
    target: "packages/core/docs/email-verification.md"
  },
  {
    source: "docs/password-reset.md",
    target: "packages/core/docs/password-reset.md"
  },
  {
    source: "docs/sessions/management.md",
    target: "packages/core/docs/sessions/management.md"
  },
  {
    source: "docs/organisations/overview.md",
    target: "packages/core/docs/organisations/overview.md"
  },
  {
    source: "docs/organisations/members.md",
    target: "packages/core/docs/organisations/members.md"
  },
  {
    source: "docs/organisations/roles.md",
    target: "packages/core/docs/organisations/roles.md"
  },
  {
    source: "docs/organisations/invites.md",
    target: "packages/core/docs/organisations/invites.md"
  },
  {
    source: "docs/api-keys/overview.md",
    target: "packages/core/docs/api-keys/overview.md"
  },
  {
    source: "docs/site-manifest.json",
    target: "packages/core/docs/site-manifest.json"
  },
  {
    source: "docs/frameworks/nextjs.md",
    target: "packages/core/docs/frameworks/nextjs.md"
  },
  {
    source: "docs/frameworks/express.md",
    target: "packages/core/docs/frameworks/express.md"
  },
  {
    source: "docs/frameworks/hono.md",
    target: "packages/core/docs/frameworks/hono.md"
  },
  {
    source: "docs/frameworks/fastify.md",
    target: "packages/core/docs/frameworks/fastify.md"
  },
  {
    content: `${JSON.stringify(publicApiSnapshot(), null, 2)}\n`,
    target: "etc/own-auth.api.json"
  }
];

const staleFiles = [];

for (const file of files) {
  const source = file.content ?? readFileSync(resolve(rootDir, file.source), "utf8");
  const expected = file.transform ? file.transform(source) : source;
  const targetPath = resolve(rootDir, file.target);
  const current = readOptionalFile(targetPath);

  if (current === expected) {
    continue;
  }

  if (checkOnly) {
    staleFiles.push(file.target);
    continue;
  }

  mkdirSync(dirname(targetPath), { recursive: true });
  writeFileSync(targetPath, expected);
  console.log(`Synced ${file.target}`);
}

function publicApiSnapshot() {
  const index = sourceFile("packages/core/src/index.ts");
  const authEngine = sourceFile("packages/core/src/auth-engine.ts");
  const options = sourceFile("packages/core/src/auth-engine-options.ts");
  const errors = sourceFile("packages/core/src/errors.ts");
  const exportedValues = [];
  const exportedTypes = [];
  const methods = [];
  const optionNames = [];
  const errorCodes = [];

  for (const statement of index.statements) {
    if (!ts.isExportDeclaration(statement) || !statement.exportClause) {
      continue;
    }
    if (!ts.isNamedExports(statement.exportClause)) {
      continue;
    }

    for (const element of statement.exportClause.elements) {
      const target = statement.isTypeOnly || element.isTypeOnly
        ? exportedTypes
        : exportedValues;
      target.push(element.name.text);
    }
  }

  for (const statement of authEngine.statements) {
    if (!ts.isClassDeclaration(statement) || statement.name?.text !== "OwnAuth") {
      continue;
    }
    for (const member of statement.members) {
      if (ts.isMethodDeclaration(member) && member.name && ts.isIdentifier(member.name)) {
        methods.push(member.name.text);
      }
    }
  }

  for (const statement of options.statements) {
    if (!ts.isInterfaceDeclaration(statement) || statement.name.text !== "OwnAuthOptions") {
      continue;
    }
    for (const member of statement.members) {
      if (ts.isPropertySignature(member) && member.name && ts.isIdentifier(member.name)) {
        optionNames.push(member.name.text);
      }
    }
  }

  for (const statement of errors.statements) {
    if (!ts.isTypeAliasDeclaration(statement) || statement.name.text !== "AuthErrorCode") {
      continue;
    }
    if (!ts.isUnionTypeNode(statement.type)) {
      continue;
    }
    for (const type of statement.type.types) {
      if (ts.isLiteralTypeNode(type) && ts.isStringLiteral(type.literal)) {
        errorCodes.push(type.literal.text);
      }
    }
  }

  return {
    errorCodes: errorCodes.sort(),
    exports: exportedValues.sort(),
    methods: methods.sort(),
    options: optionNames.sort(),
    typeExports: exportedTypes.sort()
  };
}

function sourceFile(path) {
  const source = readFileSync(resolve(rootDir, path), "utf8");
  return ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
}

if (staleFiles.length) {
  console.error("Generated package documentation is stale:");
  for (const file of staleFiles) {
    console.error(`- ${file}`);
  }
  console.error("Run: pnpm docs:sync");
  process.exit(1);
}

function packageReadme(source) {
  return source.replace(
    /\]\(\.\/(docs\/[^)]+|SECURITY\.md|CONTRIBUTING\.md)\)/g,
    (_match, path) => `](${repositoryFileUrl}/${path})`
  );
}

function readOptionalFile(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}
