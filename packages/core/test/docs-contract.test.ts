import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import ts from "typescript";

import * as ownAuthExports from "../src/index.js";
import { OwnAuth } from "../src/index.js";

const repositoryRoot = new URL("../../../", import.meta.url);
const manifest = JSON.parse(
  readFileSync(new URL("docs/site-manifest.json", repositoryRoot), "utf8")
) as {
  groups?: Array<{
    pages?: Array<{ source: string }>;
  }>;
};
const publicDocSources = new Set(
  manifest.groups?.flatMap((group) =>
    group.pages?.map((page) => page.source) ?? []
  ) ?? []
);
const publicDocs = [...publicDocSources].map((source) =>
  readFileSync(new URL(source, repositoryRoot), "utf8")
);
const examples = publicDocs.flatMap((document) =>
  [...document.matchAll(/```(?:ts|typescript)(?:[ \t]+[^\n]+)?\n([\s\S]*?)```/g)]
    .map((match) => match[1] ?? "")
);

describe("README contract", () => {
  it("uses valid TypeScript and public Own Auth APIs", () => {
    const runtimeMethods = new Set(Object.getOwnPropertyNames(OwnAuth.prototype));

    for (const example of examples) {
      const syntax = ts.transpileModule(example, {
        compilerOptions: {
          module: ts.ModuleKind.ESNext,
          target: ts.ScriptTarget.ESNext
        },
        reportDiagnostics: true
      });
      const syntaxErrors = (syntax.diagnostics ?? [])
        .filter((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error)
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));

      expect(syntaxErrors, `Invalid README TypeScript example:\n${example}`).toEqual([]);

      for (const importedName of ownAuthValueImports(example)) {
        expect(
          importedName in ownAuthExports,
          `README imports missing Own Auth export: ${importedName}`
        ).toBe(true);
      }

      for (const methodName of ownAuthMethodCalls(example)) {
        expect(
          runtimeMethods.has(methodName),
          `README calls missing Own Auth method: auth.${methodName}()`
        ).toBe(true);
      }
    }
  });

  it("documents every public Own Auth method", () => {
    const documented = publicDocs.join("\n");
    const methods = Object.getOwnPropertyNames(OwnAuth.prototype)
      .filter((method) => method !== "constructor");

    for (const method of methods) {
      expect(
        documented.includes(method),
        `Public Own Auth method is missing from the documentation: ${method}`
      ).toBe(true);
    }
  });
});

function ownAuthValueImports(code: string) {
  const names: string[] = [];
  const pattern = /import\s+(type\s+)?\{([^}]+)\}\s+from\s+["']own-auth["']/g;

  for (const match of code.matchAll(pattern)) {
    if (match[1]) {
      continue;
    }

    for (const imported of (match[2] ?? "").split(",")) {
      const name = imported.trim();
      if (!name || name.startsWith("type ")) {
        continue;
      }
      names.push(name.split(/\s+as\s+/)[0] ?? name);
    }
  }

  return names;
}

function ownAuthMethodCalls(code: string) {
  return [...code.matchAll(/\bauth\.([A-Za-z][A-Za-z0-9]*)\s*\(/g)]
    .map((match) => match[1] ?? "")
    .filter(Boolean);
}
