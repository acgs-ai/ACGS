import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";

import type { SpooledBody } from "./bounded-body";

interface UpstreamRequestOptions {
  body?: SpooledBody | null | undefined;
  headers: Headers;
  method: string;
  timeoutMs: number;
}

export async function requestUpstream(
  target: URL,
  options: UpstreamRequestOptions,
): Promise<Response> {
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new TypeError("Unsupported upstream protocol");
  }
  const requestHeaders = Object.fromEntries(options.headers.entries());
  const request = target.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    let responseStarted = false;
    const outgoing = request(
      target,
      { headers: requestHeaders, method: options.method },
      (incoming) => {
        responseStarted = true;
        const responseHeaders = new Headers();
        for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
          const name = incoming.rawHeaders[index];
          const value = incoming.rawHeaders[index + 1];
          if (name && value) responseHeaders.append(name, value);
        }
        const status = incoming.statusCode ?? 502;
        const body =
          options.method === "HEAD" || [204, 205, 304].includes(status)
            ? null
            : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>);
        resolve(new Response(body, { headers: responseHeaders, status }));
      },
    );
    const timeout = setTimeout(
      () => outgoing.destroy(new Error("Upstream request timed out")),
      options.timeoutMs,
    );
    outgoing.once("close", () => clearTimeout(timeout));
    outgoing.once("error", (error) => {
      if (!responseStarted) reject(error);
    });
    if (options.body) {
      const requestBody = options.body.openStream();
      requestBody.once("error", (error) => outgoing.destroy(error));
      requestBody.pipe(outgoing);
    } else {
      outgoing.end();
    }
  });
}
