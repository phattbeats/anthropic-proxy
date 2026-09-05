# Authorship policy

Every commit on `phattbeats/anthropic-proxy` must have the author identity `phattbeats <obiwouldjablowme@protonmail.com>` and must contain **no** `Co-authored-by` trailer of any name. The authorship check runs in two places:

1. **Local pre-commit hook** — `.githooks/commit-msg`. The hook refuses any commit whose `GIT_AUTHOR_IDENT` is not `phattbeats <obiwouldjablowme@protonmail.com>` and refuses any commit message containing a `Co-authored-by:` line.
2. **CI range check** — `.github/workflows/authorship-check.yml`. On every pull request and every push to `main`, the workflow walks the full commit range (`base..head` for PRs, `before..sha` for pushes) and fails if any commit's author or trailer violates the policy.

This is **not** a denylist of names — it is a positive allowlist of exactly one identity, with **zero** `Co-authored-by` trailers permitted.

## Configure a clone

Set the Git identity before committing:

```sh
git config user.name phattbeats
git config user.email obiwouldjablowme@protonmail.com
```

This repo has no `package.json` and no `prepare` script, so the hook is installed by pointing `core.hooksPath` at the in-repo `.githooks/` directory:

```sh
./scripts/install-git-hooks.sh
# or, equivalently:
git config core.hooksPath .githooks
chmod +x .githooks/commit-msg
```

In Claude Code, set `includeCoAuthoredBy` to `false` in user or project `settings.json`. OpenClaw/Paperclip commit paths follow the same rule.
