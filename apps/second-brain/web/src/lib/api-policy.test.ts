import { describe, expect, it } from "vitest";

import {
  buildUpstreamHeaders,
  resolveUpstreamPath,
  safeSessionSetCookie,
  validateBrowserOrigin,
  withServerPrincipal,
} from "./api-policy";

describe("API proxy policy", () => {
  const productionCookie =
    "second_brain_session=replaced-session-token; expires=Fri, 28 Aug 2026 19:54:45 GMT; HttpOnly; Max-Age=86400; Path=/; SameSite=lax; Secure";

  it("allows only documented path and method combinations", () => {
    expect(resolveUpstreamPath("GET", ["status"])).toBe("/api/v1/status");
    expect(resolveUpstreamPath("POST", ["captures", "text"])).toBe("/api/v1/captures/text");
    expect(resolveUpstreamPath("POST", ["captures", "upload"])).toBe("/api/v1/captures/upload");
    expect(resolveUpstreamPath("POST", ["captures", "url"])).toBe("/api/v1/captures/url");
    expect(resolveUpstreamPath("GET", ["sources", crypto.randomUUID()])).toMatch(
      /^\/api\/v1\/sources\//,
    );
    const sourceId = crypto.randomUUID();
    const memoryId = crypto.randomUUID();
    const projectId = crypto.randomUUID();
    expect(resolveUpstreamPath("GET", ["sources", sourceId, "content"])).toBe(
      `/api/v1/sources/${sourceId}/content`,
    );
    expect(resolveUpstreamPath("PUT", ["sources", sourceId, "organization"])).toBe(
      `/api/v1/sources/${sourceId}/organization`,
    );
    expect(resolveUpstreamPath("POST", ["memories", memoryId, "resurface"])).toBe(
      `/api/v1/memories/${memoryId}/resurface`,
    );
    expect(resolveUpstreamPath("PATCH", ["projects", projectId])).toBe(
      `/api/v1/projects/${projectId}`,
    );
    expect(resolveUpstreamPath("DELETE", ["projects", projectId])).toBe(
      `/api/v1/projects/${projectId}`,
    );
    expect(resolveUpstreamPath("GET", ["purges", crypto.randomUUID()])).toMatch(
      /^\/api\/v1\/purges\//,
    );
    expect(resolveUpstreamPath("POST", ["sources", "notes"])).toBeNull();
    expect(resolveUpstreamPath("DELETE", ["sources"])).toBeNull();
    expect(resolveUpstreamPath("GET", ["..", "status"])).toBeNull();
  });

  it("never forwards browser-supplied identity or arbitrary cookies", () => {
    const incoming = new Headers({
      accept: "application/json",
      authorization: "Bearer browser-controlled",
      cookie: "other=private; second_brain_session=opaque-token-with-entropy",
      "x-owner-id": crypto.randomUUID(),
      "x-principal-id": crypto.randomUUID(),
      "x-second-brain-owner-id": crypto.randomUUID(),
      "x-second-brain-workspace-id": crypto.randomUUID(),
      "x-workspace-id": crypto.randomUUID(),
    });

    const forwarded = buildUpstreamHeaders(incoming, "https://brain.example.test");

    expect(forwarded.get("accept")).toBe("application/json");
    expect(forwarded.get("cookie")).toBe("second_brain_session=opaque-token-with-entropy");
    expect(forwarded.get("origin")).toBe("https://brain.example.test");
    expect(forwarded.get("host")).toBe("brain.example.test");
    expect(forwarded.has("authorization")).toBe(false);
    expect(forwarded.has("x-owner-id")).toBe(false);
    expect(forwarded.has("x-principal-id")).toBe(false);
    expect(forwarded.has("x-second-brain-owner-id")).toBe(false);
    expect(forwarded.has("x-second-brain-workspace-id")).toBe(false);
    expect(forwarded.has("x-workspace-id")).toBe(false);
    expect(forwarded.get("cookie")).not.toContain("other=private");
  });

  it("can add only an explicit server-controlled development principal", () => {
    const ownerId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const headers = withServerPrincipal(new Headers(), { ownerId, workspaceId });

    expect(headers.get("x-second-brain-owner-id")).toBe(ownerId);
    expect(headers.get("x-second-brain-workspace-id")).toBe(workspaceId);
    expect(() =>
      withServerPrincipal(new Headers(), { ownerId: "not-a-uuid", workspaceId }),
    ).toThrow("Development principal IDs must be UUIDs");
  });

  it("requires the configured browser origin for mutations", () => {
    expect(
      validateBrowserOrigin(
        new Headers({ host: "brain.example.test", origin: "https://brain.example.test" }),
        "https://brain.example.test",
      ),
    ).toBe(true);
    expect(
      validateBrowserOrigin(
        new Headers({ host: "brain.example.test", origin: "https://hostile.example" }),
        "https://brain.example.test",
      ),
    ).toBe(false);
    expect(
      validateBrowserOrigin(
        new Headers({ host: "brain.example.test" }),
        "https://brain.example.test",
      ),
    ).toBe(false);
  });

  it("forwards only a tightly scoped secure session response cookie", () => {
    expect(safeSessionSetCookie(productionCookie)).toBe(productionCookie);
    expect(
      safeSessionSetCookie(productionCookie.replace("second_brain_session", "other")),
    ).toBeNull();
    expect(safeSessionSetCookie(productionCookie.replace("; Secure", ""))).toBeNull();
    expect(safeSessionSetCookie(productionCookie.replace("lax", "none"))).toBeNull();
    expect(safeSessionSetCookie(`${productionCookie}; Domain=example.test`)).toBeNull();
  });

  it("rejects malicious or malformed Max-Age and Expires attributes", () => {
    for (const maxAge of ["299", "604801", "086400", "+86400", "86400.0", "1e5"]) {
      expect(safeSessionSetCookie(productionCookie.replace("86400", maxAge))).toBeNull();
    }
    expect(safeSessionSetCookie(`${productionCookie}; Max-Age=86400`)).toBeNull();
    expect(
      safeSessionSetCookie(
        productionCookie.replace("Fri, 28 Aug 2026 19:54:45 GMT", "Thu, 28 Aug 2026 19:54:45 GMT"),
      ),
    ).toBeNull();
    expect(
      safeSessionSetCookie(
        productionCookie.replace("Fri, 28 Aug 2026 19:54:45 GMT", "Fri, 31 Feb 2026 19:54:45 GMT"),
      ),
    ).toBeNull();
    expect(
      safeSessionSetCookie(`${productionCookie}; expires=Fri, 28 Aug 2026 19:54:45 GMT`),
    ).toBeNull();
  });
});
