import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");
const repositoryFileUrl = "https://github.com/tina-li-xx/own-auth/blob/main";
const packageDocumentationFiles = listFiles("docs")
  .filter(isPackageDocumentation)
  .map((source) => ({ source, target: `packages/core/${source}` }));
const packageDocumentationTargets = new Set(
  packageDocumentationFiles.map(({ target }) => target)
);

const files = [
  {
    source: "CHANGELOG.md",
    target: "packages/core/CHANGELOG.md"
  },
  {
    source: "README.md",
    target: "packages/core/README.md",
    transform: packageReadme
  },
  ...packageDocumentationFiles,
  {
    content: `${JSON.stringify(publicApiSnapshot(), null, 2)}\n`,
    target: "etc/own-auth.api.json"
  }
];

function listFiles(directory) {
  return readdirSync(resolve(rootDir, directory), { withFileTypes: true })
    .flatMap((entry) => {
      const path = `${directory}/${entry.name}`;
      return entry.isDirectory() ? listFiles(path) : [path];
    })
    .sort();
}

function isPackageDocumentation(path) {
  return !path.startsWith("docs/architecture/") &&
    path !== "docs/product-roadmap-review.md";
}

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

for (const target of listFiles("packages/core/docs")) {
  if (packageDocumentationTargets.has(target)) continue;
  if (checkOnly) {
    staleFiles.push(target);
  } else {
    rmSync(resolve(rootDir, target));
    console.log(`Removed ${target}`);
  }
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
      const isPrivate = member.modifiers?.some(
        (modifier) => modifier.kind === ts.SyntaxKind.PrivateKeyword
      );
      if (
        ts.isMethodDeclaration(member) &&
        !isPrivate &&
        !hasInternalTag(member) &&
        member.name &&
        ts.isIdentifier(member.name)
      ) {
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

function hasInternalTag(node) {
  return ts.getJSDocTags(node).some((tag) => tag.tagName.text === "internal");
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
    /\]\(\.\/(docs\/[^)#]+|SECURITY\.md|CONTRIBUTING\.md)(#[^)]+)?\)/g,
    (_match, path, hash = "") => `](${repositoryFileUrl}/${path}${hash})`
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
