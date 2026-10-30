# Contributing

Thanks for taking a look. Issues and PRs are welcome. For anything bigger than a small fix, open an issue first so we can agree on the approach before you write code.

## Workflow

1. Branch from `main` (fork first if you don't have write access).
2. Make the change and run the local checks below. They're the same ones CI runs.
3. Open a PR using the template. **The PR title must be a [Conventional Commit](https://www.conventionalcommits.org/)** (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `feat!:` for breaking changes). PRs are squash-merged, so the title becomes the commit, and [release-please](https://github.com/googleapis/release-please) uses it to pick the next version and write the changelog.
4. CI must be green and the PR reviewed before merge.

## Local checks

Requires Python 3.10+ and the [Claude Code](https://claude.com/claude-code) CLI.

```bash
pip install pytest ruff==0.17.3
ruff check .                                        # lint (config in pyproject.toml)
python -m pytest tests                              # analyzer unit tests
claude plugin validate --strict .                   # marketplace manifest
claude plugin validate --strict plugins/sre-toolkit # plugin + skills
```

## Skill conventions

- **Read-only by default.** A skill can inspect, validate, and plan. Anything that changes infrastructure must stop and ask for explicit approval first.
- **Never print secrets.** Skills must not echo tokens, keys, or credential files into the transcript, and must redact them from tool output they summarise.
- **Be honest about verification.** A skill must never report that something was tested or validated unless the command actually ran and passed.
- Helper scripts ship with unit tests in `tests/`. New skills get a row in the README's skills table.

## Ground rules

- **No secrets in the repo, ever.** That includes tokens, keys, account/subscription/tenant IDs, and internal hostnames in examples or test fixtures. Use obvious placeholders.
- **Pin third-party GitHub Actions to a full commit SHA** with the version as a trailing comment (`uses: org/action@<sha> # v1.2.3`) so Dependabot can bump them.
- Keep changes focused: one concern per PR makes review and rollback easy.

## Security issues

Don't open a public issue. See [SECURITY.md](SECURITY.md).
