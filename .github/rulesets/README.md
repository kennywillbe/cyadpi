# Repository rules

The branch protection on `main` and the tag rule are set on GitHub. These files
are an export of them, so a change shows up in a diff. GitHub is the source of
truth.

`main-branch-protection.json`

- Changes land through pull requests with green checks, on an up to date base.
- Squash merges only, linear history: the PR title becomes the commit subject
  on `main`, which is why the title has to be a conventional commit.
- No force pushes, no deleting `main`. This applies to the owner too.
- Zero approvals required. GitHub does not let you approve your own PR, so with
  one maintainer the checks are the gate.

`release-tags.json`

- Only an admin creates, moves or deletes a `v*` tag. Pushing one is what
  builds and publishes the binaries.
