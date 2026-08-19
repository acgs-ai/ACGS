Review this pull request for correctness, security regressions, CI risk, and claim-boundary issues.

Repository-specific instructions:
- Follow AGENTS.md.
- Treat constitutional hashes and governance claim boundaries as high-risk.
- Do not edit files; this workflow is review-only.
- Keep feedback concise and actionable.

Use the checked-out merge ref plus the base/head refs prepared by the workflow to inspect the
PR diff. `HEAD^1` is the base commit and `HEAD^2` is the head commit; the same two commits are
also reachable as `refs/remotes/origin/<base branch>` and `refs/pull/<number>/head`.
