const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

const ROUTES: ReadonlyArray<{ method: string; pattern: RegExp }> = [
  {
    method: "GET",
    pattern:
      /^\/(health|status|session\/check|sources|search|memory-proposals|memories|today|projects|tags)$/,
  },
  {
    method: "POST",
    pattern:
      /^\/(auth\/exchange|session\/check|captures\/(text|upload|url)|answers|projects|tags)$/,
  },
  { method: "GET", pattern: new RegExp(`^/(sources|jobs|memories|purges)/${UUID}$`, "i") },
  { method: "GET", pattern: new RegExp(`^/sources/${UUID}/content$`, "i") },
  { method: "GET", pattern: new RegExp(`^/sources/${UUID}/context/${UUID}$`, "i") },
  { method: "POST", pattern: new RegExp(`^/sources/${UUID}/purge$`, "i") },
  { method: "PUT", pattern: new RegExp(`^/sources/${UUID}/organization$`, "i") },
  {
    method: "POST",
    pattern: new RegExp(`^/memory-proposals/${UUID}/(approve|reject|edit-and-approve)$`, "i"),
  },
  {
    method: "POST",
    pattern: new RegExp(`^/memories/${UUID}/(revise|supersede|archive|purge)$`, "i"),
  },
  { method: "POST", pattern: new RegExp(`^/memories/${UUID}/resurface$`, "i") },
  { method: "PATCH", pattern: new RegExp(`^/(projects|tags)/${UUID}$`, "i") },
  { method: "DELETE", pattern: new RegExp(`^/(projects|tags)/${UUID}$`, "i") },
];

const FORWARDED_REQUEST_HEADERS = [
  "accept",
  "content-type",
  "idempotency-key",
  "x-csrf-token",
  "x-request-id",
] as const;

const SESSION_COOKIE = "second_brain_session";
const UUID_PATTERN = new RegExp(`^${UUID}$`, "i");
const SESSION_COOKIE_VALUE = /^[A-Za-z0-9_-]{16,512}$/;
const HTTP_DATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (?:0[1-9]|[12]\d|3[01]) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} (?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d GMT$/;
const MIN_SESSION_MAX_AGE = 300;
const MAX_SESSION_MAX_AGE = 604_800;

export interface ServerPrincipal {
  ownerId: string;
  workspaceId: string;
}

export function resolveUpstreamPath(method: string, segments: readonly string[]): string | null {
  if (segments.length === 0 || segments.some((segment) => !segment || /[/.\\%]/.test(segment))) {
    return null;
  }
  const relativePath = `/${segments.join("/")}`;
  const allowed = ROUTES.some(
    (route) => route.method === method.toUpperCase() && route.pattern.test(relativePath),
  );
  return allowed ? `/api/v1${relativePath}` : null;
}

function getSessionCookie(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === SESSION_COOKIE && valueParts.length > 0) {
      const value = valueParts.join("=");
      if (SESSION_COOKIE_VALUE.test(value)) return `${SESSION_COOKIE}=${value}`;
    }
  }
  return null;
}

export function safeSessionSetCookie(value: string | null): string | null {
  if (!value) return null;
  const parts = value.split(";").map((part) => part.trim());
  const [cookie, ...attributes] = parts;
  if (!cookie) return null;
  const [name, ...valueParts] = cookie.split("=");
  const cookieValue = valueParts.join("=");
  if (name !== SESSION_COOKIE || !SESSION_COOKIE_VALUE.test(cookieValue)) return null;

  const seen = new Set<string>();
  let expires: string | null = null;
  let maxAge: number | null = null;
  for (const attribute of attributes) {
    const [rawName, ...rawValueParts] = attribute.split("=");
    const attributeName = rawName?.toLowerCase();
    if (!attributeName || seen.has(attributeName)) return null;
    const attributeValue = rawValueParts.join("=");
    if (attributeName === "secure" && rawValueParts.length === 0) {
      seen.add(attributeName);
    } else if (attributeName === "httponly" && rawValueParts.length === 0) {
      seen.add(attributeName);
    } else if (attributeName === "path" && attributeValue === "/") {
      seen.add(attributeName);
    } else if (attributeName === "samesite" && attributeValue.toLowerCase() === "lax") {
      seen.add(attributeName);
    } else if (attributeName === "max-age" && /^(?:0|[1-9]\d*)$/.test(attributeValue)) {
      const parsed = Number(attributeValue);
      if (parsed < MIN_SESSION_MAX_AGE || parsed > MAX_SESSION_MAX_AGE) return null;
      maxAge = parsed;
      seen.add(attributeName);
    } else if (
      attributeName === "expires" &&
      HTTP_DATE.test(attributeValue) &&
      new Date(attributeValue).toUTCString() === attributeValue
    ) {
      expires = attributeValue;
      seen.add(attributeName);
    } else {
      return null;
    }
  }

  if (
    seen.size !== 6 ||
    !seen.has("secure") ||
    !seen.has("httponly") ||
    !seen.has("path") ||
    !seen.has("samesite") ||
    expires === null ||
    maxAge === null
  ) {
    return null;
  }
  return `${SESSION_COOKIE}=${cookieValue}; expires=${expires}; HttpOnly; Max-Age=${maxAge}; Path=/; SameSite=lax; Secure`;
}

export function buildUpstreamHeaders(incoming: Headers, publicOrigin: string): Headers {
  const forwarded = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = incoming.get(name);
    if (value) forwarded.set(name, value);
  }

  const sessionCookie = getSessionCookie(incoming.get("cookie"));
  if (sessionCookie) forwarded.set("cookie", sessionCookie);

  const trustedOrigin = new URL(publicOrigin);
  forwarded.set("origin", trustedOrigin.origin);
  forwarded.set("host", trustedOrigin.host);
  return forwarded;
}

export function validateBrowserOrigin(headers: Headers, publicOrigin: string): boolean {
  const trustedOrigin = new URL(publicOrigin);
  return (
    headers.get("origin") === trustedOrigin.origin && headers.get("host") === trustedOrigin.host
  );
}

export function withServerPrincipal(headers: Headers, principal: ServerPrincipal): Headers {
  if (!UUID_PATTERN.test(principal.ownerId) || !UUID_PATTERN.test(principal.workspaceId)) {
    throw new TypeError("Development principal IDs must be UUIDs");
  }
  const scoped = new Headers(headers);
  scoped.set("x-second-brain-owner-id", principal.ownerId);
  scoped.set("x-second-brain-workspace-id", principal.workspaceId);
  return scoped;
}
