import { describe, expect, it } from "vitest";

import { resolveWebRuntimeConfig } from "./runtime-config";

const ownerId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";

function developmentEnvironment(
  overrides: Readonly<Record<string, string | undefined>> = {},
): Record<string, string | undefined> {
  return {
    SECOND_BRAIN_API_URL: "http://127.0.0.1:3310",
    SECOND_BRAIN_PUBLIC_ORIGIN: "http://127.0.0.1:3301",
    SECOND_BRAIN_WEB_APP_ENV: "test",
    SECOND_BRAIN_WEB_AUTH_MODE: "development_headers",
    SECOND_BRAIN_WEB_BIND_HOST: "127.0.0.1",
    SECOND_BRAIN_WEB_DEV_OWNER_ID: ownerId,
    SECOND_BRAIN_WEB_DEV_WORKSPACE_ID: workspaceId,
    SECOND_BRAIN_WEB_PORT: "3301",
    ...overrides,
  };
}

describe("web runtime configuration", () => {
  it("accepts development identity only on an explicit loopback listener", () => {
    const result = resolveWebRuntimeConfig(developmentEnvironment(), "start");

    expect(result).toEqual({
      ok: true,
      value: expect.objectContaining({
        bindHost: "127.0.0.1",
        developmentPrincipal: { ownerId, workspaceId },
      }),
    });
  });

  it("rejects development identity in production", () => {
    const result = resolveWebRuntimeConfig(
      developmentEnvironment({
        SECOND_BRAIN_PUBLIC_ORIGIN: "https://brain.example.test",
        SECOND_BRAIN_WEB_APP_ENV: "production",
      }),
      "start",
    );

    expect(result).toEqual({ ok: false, code: "development_identity_forbidden" });
  });

  it("rejects development identity when the actual Next listener is not loopback", () => {
    const result = resolveWebRuntimeConfig(
      developmentEnvironment({ SECOND_BRAIN_WEB_BIND_HOST: "0.0.0.0" }),
      "start",
    );

    expect(result).toEqual({ ok: false, code: "development_identity_requires_loopback" });
  });

  it("rejects hostname-based upstreams and malformed development principals", () => {
    expect(
      resolveWebRuntimeConfig(
        developmentEnvironment({ SECOND_BRAIN_API_URL: "http://localhost:3310" }),
        "start",
      ),
    ).toEqual({ ok: false, code: "development_identity_requires_loopback" });
    expect(
      resolveWebRuntimeConfig(
        developmentEnvironment({ SECOND_BRAIN_WEB_DEV_OWNER_ID: "not-a-uuid" }),
        "start",
      ),
    ).toEqual({ ok: false, code: "development_identity_invalid" });
  });

  it("requires an explicit bind host for production start", () => {
    const environment = developmentEnvironment({
      SECOND_BRAIN_PUBLIC_ORIGIN: "https://brain.example.test",
      SECOND_BRAIN_WEB_APP_ENV: "production",
      SECOND_BRAIN_WEB_AUTH_MODE: "session",
    });
    delete environment.SECOND_BRAIN_WEB_BIND_HOST;
    delete environment.SECOND_BRAIN_WEB_DEV_OWNER_ID;
    delete environment.SECOND_BRAIN_WEB_DEV_WORKSPACE_ID;

    expect(resolveWebRuntimeConfig(environment, "start")).toEqual({
      ok: false,
      code: "bind_host_required",
    });
  });
});
