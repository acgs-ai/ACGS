// acgs-governance-proxy — marketing apex worker (Workers Static Assets).
//
// The script layer exists for exactly one job _redirects cannot do:
// host-based canonicalization (Workers Assets rejects absolute-URL sources,
// error 100324). Everything else — /console 308 privilege boundary, SPA
// deep-link rewrites, security headers — stays declarative in _redirects and
// _headers next to this file.
//
// run_worker_first is enabled in wrangler.toml so this fetch handler sees
// every request (otherwise asset-matching paths bypass the script and
// www.acgs.ai/ would serve duplicate 200 content straight from assets).
export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    if (url.hostname === 'www.acgs.ai') {
      url.hostname = 'acgs.ai'
      return Response.redirect(url.toString(), 301)
    }
    return env.ASSETS.fetch(request)
  },
}
