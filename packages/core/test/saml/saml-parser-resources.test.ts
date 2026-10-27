import { createRequire } from "node:module";
import { Worker } from "node:worker_threads";
import { describe, expect, it } from "vitest";

const parserModule = createRequire(import.meta.url).resolve("@node-saml/node-saml/lib/xml.js");
const byteLimit = 64 * 1024;
const deadlineMs = 5_000;
const heapLimitMb = 96;

const cases = [
  { name: "long whitespace before an end tag closes", accepted: true,
    xml: `<root></root${" ".repeat(48_000)}>` },
  { name: "many distinct attributes", accepted: true,
    xml: `<root ${Array.from({ length: 3_000 }, (_, i) => `a${i}="x"`).join(" ")}/>` },
  { name: "many duplicate attributes", accepted: false,
    xml: `<root ${'a="x" '.repeat(8_000)}/>` },
  { name: "repeated malformed tag recovery", accepted: false,
    xml: `<root>${"<a<".repeat(15_000)}</root>` },
  { name: "nested namespace declarations", accepted: true,
    xml: Array.from({ length: 500 }, (_, i) => `<n xmlns:p${i}="urn:${i}">`).join("") + "</n>".repeat(500) }
];

describe("SAML parser resource bounds", () => {
  for (const input of cases) {
    it(`handles ${input.name} within the isolated worker budget`, async () => {
      expect(Buffer.byteLength(input.xml, "utf8")).toBeLessThanOrEqual(byteLimit);
      const result = await parseInWorker(input.xml);
      expect(result.accepted).toBe(input.accepted);
      expect(result.heapBytes).toBeLessThan(heapLimitMb * 1024 * 1024);
    }, deadlineMs + 5_000);
  }
});

async function parseInWorker(xml: string): Promise<{ accepted: boolean; heapBytes: number }> {
  // A separate worker lets the parent interrupt a synchronous parser loop.
  const worker = new Worker(`
      const { parentPort, workerData } = require("node:worker_threads");
      const { parseDomFromString } = require(workerData.parserModule);
      (async () => {
        let accepted = false;
        try { await parseDomFromString(workerData.xml); accepted = true; } catch {}
        parentPort.postMessage({ accepted, heapBytes: process.memoryUsage().heapUsed });
      })();
    `, { eval: true, workerData: { parserModule, xml }, resourceLimits: { maxOldGenerationSizeMb: heapLimitMb } });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error("SAML parser exceeded the five second worker deadline")), deadlineMs);
      worker.once("message", resolve);
      worker.once("error", reject);
      worker.once("exit", (code) => reject(new Error(`SAML parser worker exited before returning a result (${code})`)));
    });
  } finally {
    clearTimeout(timer);
    await worker.terminate();
  }
}
