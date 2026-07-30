export function resolveFetchImplementation(
  fetchImpl?: typeof globalThis.fetch
): typeof globalThis.fetch | undefined {
  const resolved = fetchImpl ?? globalThis.fetch;
  if (typeof resolved !== "function") return undefined;

  // Some browser-native fetch implementations require the global receiver.
  return fetchImpl === undefined || resolved === globalThis.fetch
    ? resolved.bind(globalThis)
    : resolved;
}
