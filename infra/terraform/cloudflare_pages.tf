# Cloudflare Pages project for the public marketing site.
# Name + production branch pinned by .github/workflows/marketing-cloudflare.yml:11-12
# (`wrangler pages deploy --branch=master` against project `acgs-marketing`).
# Deploys stay in CI behind the human-approved `production` environment; this
# resource only makes the project's existence reproducible.

resource "cloudflare_pages_project" "marketing" {
  account_id        = var.cloudflare_account_id
  name              = "acgs-marketing"
  production_branch = "master"
}
