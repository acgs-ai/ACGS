# External References

These are **optional third-party research references**. They are **not
dependencies of the ACGS build or test suite** — nothing in this tree imports
them (see `MONOREPO.md`). They were previously embedded as git submodules, which
made `git clone --recursive` pull megabytes of unrelated upstream code and could
fail when an upstream remote was unavailable. They are now recorded here as a
pinned reference list instead, so a normal `git clone` (with or without
`--recursive`) succeeds for any reviewer.

| Project | Purpose (why referenced) | Upstream | Pinned commit | Required for build/test? |
|---|---|---|---|---|
| UI-TARS-desktop | GUI-agent reference implementation | https://github.com/bytedance/UI-TARS-desktop | `7986f5a` | No |
| OpenSwarm | Multi-agent swarm framework reference | https://github.com/VRSEN/OpenSwarm | `5da250e` | No |
| everything-claude-code | Claude Code patterns reference | https://github.com/affaan-m/everything-claude-code | `841beea` | No |
| natural_language_autoencoders | NL-autoencoder research reference | https://github.com/kitft/natural_language_autoencoders | `047eb8e` | No |

## Licensing

Each project is licensed by its own upstream repository. **Confirm the current
license at the upstream URL before reusing or redistributing any of this code.**
ACGS does not vendor or redistribute these projects; it only references them.

## To inspect a reference at its pinned commit

```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo> && git checkout <pinned-commit>
```
