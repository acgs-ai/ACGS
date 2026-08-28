import { isIP } from "node:net";

import type { ServerPrincipal } from "./api-policy";

type AppEnvironment = "development" | "test" | "production";
type AuthMode = "session" | "development_headers";
type RuntimeCommand = "dev" | "start" | "probe";
type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface WebRuntimeConfig {
  apiUrl: URL;
  appEnvironment: AppEnvironment;
  authMode: AuthMode;
  bindHost: string;
  developmentPrincipal: ServerPrincipal | null;
  port: number;
  publicOrigin: URL;
}

export type RuntimeConfigResult =
  | { ok: true; value: WebRuntimeConfig }
  | { ok: false; code: string };

function parseOrigin(value: string | undefined): URL | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") return null;
    return url;
  } catch {
    return null;
  }
}

function isLoopback(value: string): boolean {
  if (isIP(value) === 4) return value.split(".")[0] === "127";
  return isIP(value) === 6 && value === "::1";
}

function isLoopbackUrl(url: URL): boolean {
  return isLoopback(url.hostname.replace(/^\[|\]$/g, ""));
}

export function resolveWebRuntimeConfig(
  environment: RuntimeEnvironment,
  command: RuntimeCommand,
): RuntimeConfigResult {
  const appEnvironment = environment.SECOND_BRAIN_WEB_APP_ENV;
  if (!appEnvironment || !["development", "test", "production"].includes(appEnvironment)) {
    return { ok: false, code: "app_environment_invalid" };
  }
  const authMode = environment.SECOND_BRAIN_WEB_AUTH_MODE;
  if (!authMode || !["session", "development_headers"].includes(authMode)) {
    return { ok: false, code: "auth_mode_invalid" };
  }

  const bindHost = environment.SECOND_BRAIN_WEB_BIND_HOST;
  if (!bindHost && command !== "dev") return { ok: false, code: "bind_host_required" };
  const resolvedBindHost = bindHost ?? "127.0.0.1";
  if (isIP(resolvedBindHost) === 0) return { ok: false, code: "bind_host_invalid" };

  const apiUrl = parseOrigin(environment.SECOND_BRAIN_API_URL);
  const publicOrigin = parseOrigin(environment.SECOND_BRAIN_PUBLIC_ORIGIN);
  if (!apiUrl) return { ok: false, code: "api_url_invalid" };
  if (!publicOrigin) return { ok: false, code: "public_origin_invalid" };
  if (appEnvironment === "production" && publicOrigin.protocol !== "https:") {
    return { ok: false, code: "production_https_required" };
  }

  const port = Number(environment.SECOND_BRAIN_WEB_PORT ?? "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, code: "port_invalid" };
  }

  let developmentPrincipal: ServerPrincipal | null = null;
  if (authMode === "development_headers") {
    if (appEnvironment === "production") {
      return { ok: false, code: "development_identity_forbidden" };
    }
    if (!isLoopback(resolvedBindHost) || !isLoopbackUrl(apiUrl) || !isLoopbackUrl(publicOrigin)) {
      return { ok: false, code: "development_identity_requires_loopback" };
    }
    const ownerId = environment.SECOND_BRAIN_WEB_DEV_OWNER_ID;
    const workspaceId = environment.SECOND_BRAIN_WEB_DEV_WORKSPACE_ID;
    if (!ownerId || !workspaceId) return { ok: false, code: "development_identity_incomplete" };
    if (!UUID.test(ownerId) || !UUID.test(workspaceId)) {
      return { ok: false, code: "development_identity_invalid" };
    }
    developmentPrincipal = { ownerId, workspaceId };
  } else if (
    environment.SECOND_BRAIN_WEB_DEV_OWNER_ID ||
    environment.SECOND_BRAIN_WEB_DEV_WORKSPACE_ID
  ) {
    return { ok: false, code: "unused_development_identity_forbidden" };
  }

  return {
    ok: true,
    value: {
      apiUrl,
      appEnvironment: appEnvironment as AppEnvironment,
      authMode: authMode as AuthMode,
      bindHost: resolvedBindHost,
      developmentPrincipal,
      port,
      publicOrigin,
    },
  };
}
