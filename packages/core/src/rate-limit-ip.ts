/** A stable budget for one IPv4 address or one IPv6 /64 network. */
export function rateLimitIpIdentifier(value: string): string {
  const address = value.trim();
  const octets = address.split(".");
  if (octets.length === 4 && octets.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) {
    return octets.join(".");
  }

  try {
    const host = address.startsWith("[") ? address : `[${address}]`;
    if (!/^\[[\da-f:.]+\]$/i.test(host)) return "invalid-ip";
    const parsed = new URL(`http://${host}/`);
    const canonical = parsed.hostname.slice(1, -1);
    const halves = canonical.split("::");
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const groups = halves.length === 2
      ? [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right]
      : left;
    if (groups.length !== 8 || !groups.every((part) => /^[a-f0-9]{1,4}$/.test(part))) return "invalid-ip";
    const numbers = groups.map((part) => Number.parseInt(part, 16));
    if (numbers.slice(0, 5).every((part) => part === 0) && numbers[5] === 0xffff) {
      return [numbers[6]! >> 8, numbers[6]! & 255, numbers[7]! >> 8, numbers[7]! & 255].join(".");
    }
    return `ipv6:${numbers.slice(0, 4).map((part) => part.toString(16)).join(":")}/64`;
  } catch {
    // Invalid supplied values share a budget instead of creating unlimited buckets.
    return "invalid-ip";
  }
}
