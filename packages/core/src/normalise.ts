export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isValidEmailAddress(email: string): boolean {
  const parts = email.split("@");
  if (
    email.length > 254 ||
    /[\u0000-\u0020\u007f]/u.test(email) ||
    parts.length !== 2
  ) {
    return false;
  }
  const [local = "", domain = ""] = parts;
  if (!local || local.length > 64 || !domain || domain.length > 253) {
    return false;
  }

  return [local, domain].every(
    (part) =>
      !part.startsWith(".") &&
      !part.endsWith(".") &&
      !part.includes("..")
  );
}

export function normalizePhone(phone: string): string {
  return phone.trim().replace(/[\s().-]/g, "");
}

export function isValidE164Phone(phone: string): boolean {
  return /^\+[1-9]\d{1,14}$/u.test(phone);
}

export function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return slug || "organisation";
}

export function isExpired(date: Date, now = new Date()): boolean {
  return date.getTime() <= now.getTime();
}
