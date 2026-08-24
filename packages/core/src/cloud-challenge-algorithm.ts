export function hasLeadingZeroBits(digest: Uint8Array | string, required: number): boolean {
  let remaining = required;
  const width = typeof digest === "string" ? 4 : 8;
  for (const unit of digest) {
    const value = typeof unit === "string" ? Number.parseInt(unit, 16) : unit;
    if (!Number.isInteger(value) || value < 0 || value >= 2 ** width) return false;
    const zeros = value === 0 ? width : Math.clz32(value) - (32 - width);
    if (zeros >= remaining) return true;
    if (zeros < width) return false;
    remaining -= width;
  }
  return remaining <= 0;
}
