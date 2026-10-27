# Releasing

Pushing a version tag runs the whole pipeline (see Release Flow in `CLAUDE.md`):
`release.yml` creates the GitHub release, `build.yml` builds binaries, `.deb` and `.rpm`
packages, and the Homebrew cask, and `packages.yml` publishes the apt and dnf
repositories to GitHub Pages.

## One-time setup

### Homebrew tap

The cask is pushed to [iamvirul/homebrew-sarc](https://github.com/iamvirul/homebrew-sarc)
over SSH with a deploy key, which can write to that repository and nothing else.
`build.yml` fails before building if the `HOMEBREW_TAP_DEPLOY_KEY` secret is missing.
To create or replace the key:

```bash
dir=$(mktemp -d)
ssh-keygen -q -t ed25519 -N '' -C "sarc release cask push" -f "$dir/tap"
gh repo deploy-key add "$dir/tap.pub" --repo iamvirul/homebrew-sarc --allow-write \
  --title "sarc release (goreleaser cask push)"
gh secret set HOMEBREW_TAP_DEPLOY_KEY --repo iamvirul/sarc < "$dir/tap"
rm -r "$dir"
```

No backup is needed: a lost key is replaced by running this again and deleting the old
deploy key in the tap's settings.

### Package signing key

The apt `InRelease`/`Release.gpg` files and the dnf `repomd.xml.asc` are signed with a
dedicated ed25519 GPG key, `sarc packages <89099391+iamvirul@users.noreply.github.com>`:

```
C288 2C4E 61C3 846A 5302  3BD8 8455 419A 7567 D512
```

It is stored in the `PACKAGE_SIGNING_KEY` secret, without a passphrase because CI uses it
unattended. Users import its public half from `https://iamvirul.github.io/sarc/sarc.gpg`,
and the README lists the fingerprint so they can check it. Keep the offline backup of the
private key (for example in a password manager): rotating the key makes every user import
the new one. To rotate, generate a new key in a throwaway keyring, update the secret and
the fingerprint in this file and the README, and rerun `packages.yml`:

```bash
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key "sarc packages <89099391+iamvirul@users.noreply.github.com>" ed25519 sign never
gpg --armor --export-secret-keys | gh secret set PACKAGE_SIGNING_KEY --repo iamvirul/sarc
gpg --armor --export-secret-keys > sarc-packages-signing-key.asc   # store offline
gpg --fingerprint
rm -rf "$GNUPGHOME"; unset GNUPGHOME
```

### GitHub Pages

Pages deploys from GitHub Actions (Settings -> Pages -> Source: GitHub Actions); this is
already set.

## Republishing

`packages.yml` rebuilds the repositories from release assets every run, so running it by
hand (Actions -> Package repositories -> Run workflow) republishes them, for example after
rotating the signing key. The repositories keep the newest 3 releases that carry packages.
