import { createReadStream, statSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const publicDirectory = join(moduleDirectory, "public");
const staticFiles = new Map([
  ["/", ["index.html", "text/html; charset=utf-8", "no-store"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml", "public, max-age=86400"]],
  ["/assets/styles.css", ["styles.css", "text/css; charset=utf-8", "no-cache"]],
  ["/assets/app.js", ["app.js", "text/javascript; charset=utf-8", "no-cache"]],
]);
const repositoryPagePath = /^\/repositories\/[^/]+\/[^/]+(?:\/(overview|runs|secrets|variables|settings))?\/?$/;
const legacyWorkspacePath = "/ui/github/installations";
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const hopByHopHeaders = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"]);
const clientErrorBytes = 2048;

function sendStatic(request, response, definition) {
  const [filename, contentType, cacheControl] = definition;
  const path = join(publicDirectory, filename);
  const size = statSync(path).size;
  response.writeHead(200, {
    "cache-control": cacheControl,
    "content-length": size,
    "content-security-policy": contentSecurityPolicy,
    "content-type": contentType,
    "referrer-policy": "same-origin",
    "x-content-type-options": "nosniff",
  });
  if (request.method === "HEAD") return response.end();
  createReadStream(path).pipe(response);
}

function proxyRequest(request, response, backendOrigin) {
  const target = new URL(request.url, backendOrigin);
  const headers = { ...request.headers };
  headers.host = request.headers.host || target.host;
  headers["x-forwarded-host"] = request.headers.host || target.host;
  headers["x-forwarded-proto"] ||= "http";
  delete headers.connection;

  const transport = target.protocol === "https:" ? httpsRequest : httpRequest;
  const upstream = transport({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: request.method,
    path: `${target.pathname}${target.search}`,
    headers,
  }, (upstreamResponse) => {
    if (target.pathname === "/auth/callback" || target.pathname === "/api/v1/ui/github") {
      const setCookieCount = Array.isArray(upstreamResponse.headers["set-cookie"])
        ? upstreamResponse.headers["set-cookie"].length
        : Number(Boolean(upstreamResponse.headers["set-cookie"]));
      process.stdout.write(`${request.method} ${target.pathname} -> ${upstreamResponse.statusCode || 502} set-cookie=${setCookieCount}\n`);
    }
    const responseHeaders = {};
    for (const [name, value] of Object.entries(upstreamResponse.headers)) {
      if (!hopByHopHeaders.has(name) && value !== undefined) responseHeaders[name] = value;
    }
    response.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
    upstreamResponse.pipe(response);
  });
  upstream.on("error", () => {
    if (response.headersSent) return response.destroy();
    response.writeHead(502, { "content-type": "application/problem+json", "cache-control": "no-store" });
    response.end(JSON.stringify({ title: "Backend unavailable", status: 502 }));
  });
  request.pipe(upstream);
}

export function createRuntrueServer({ backendOrigin = process.env.BACKEND_ORIGIN || "http://127.0.0.1:8080" } = {}) {
  return createServer((request, response) => {
    const url = new URL(request.url, "http://runtrue.local");
    if (url.pathname === "/frontend-healthz") {
      response.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      return response.end('{"status":"ok"}');
    }
    if (request.method === "POST" && url.pathname === "/frontend-client-error") {
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk) => {
        if (body.length <= clientErrorBytes) body += chunk;
      });
      request.on("end", () => {
        let detail = "unknown client error";
        try {
          const parsed = JSON.parse(body.slice(0, clientErrorBytes));
          if (typeof parsed.detail === "string") detail = parsed.detail;
        } catch {}
        detail = detail.replaceAll(/[\r\n\t\x00-\x1f\x7f]/g, " ").slice(0, 500);
        process.stdout.write(`frontend client error: ${detail}\n`);
        response.writeHead(204, { "cache-control": "no-store" });
        return response.end();
      });
      return;
    }
    if ((request.method === "GET" || request.method === "HEAD") && (url.pathname === legacyWorkspacePath || url.pathname.startsWith(`${legacyWorkspacePath}/repositories/`))) {
      const pathname = url.pathname === legacyWorkspacePath
        ? "/"
        : url.pathname.slice(legacyWorkspacePath.length);
      response.writeHead(308, { location: `${pathname}${url.search}`, "cache-control": "no-store" });
      return response.end();
    }
    const staticDefinition = staticFiles.get(url.pathname)
      || (repositoryPagePath.test(url.pathname) ? staticFiles.get("/") : null);
    if ((request.method === "GET" || request.method === "HEAD") && staticDefinition) {
      return sendStatic(request, response, staticDefinition);
    }
    return proxyRequest(request, response, backendOrigin);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number.parseInt(process.env.PORT || "3000", 10);
  const server = createRuntrueServer();
  server.listen(port, "0.0.0.0", () => process.stdout.write(`Runtrue frontend listening on ${port}\n`));
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
