# Releasing

Pushing a version tag runs the whole pipeline (see Release Flow in `CLAUDE.md`):
`release.yml` creates the GitHub release, `build.yml` builds binaries, `.deb` and `.rpm`
packages, and the Homebrew cask, and `packages.yml` publishes the apt and dnf
repositories to GitHub Pages.

## One-time setup

### Homebrew tap

The cask is pushed to [iamvirul/homebrew-sarc](https://github.com/iamvirul/homebrew-sarc).
`GITHUB_TOKEN` cannot push to another repository, so `build.yml` needs a token that can:

1. Create a fine-grained personal access token with access to `iamvirul/homebrew-sarc`
   only and the **Contents: Read and write** permission.
2. Store it as the `HOMEBREW_TAP_GITHUB_TOKEN` secret:

   ```bash
   gh secret set HOMEBREW_TAP_GITHUB_TOKEN --repo iamvirul/sarc
   ```

### Package signing key

The apt `InRelease`/`Release.gpg` files and the dnf `repomd.xml.asc` are signed with a
dedicated GPG key. Users import its public half from `https://iamvirul.github.io/sarc/sarc.gpg`.
Generate it in a throwaway keyring so it never mixes with personal keys:

```bash
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key "sarc packages <89099391+iamvirul@users.noreply.github.com>" ed25519 sign never
gpg --armor --export-secret-keys | gh secret set PACKAGE_SIGNING_KEY --repo iamvirul/sarc
gpg --armor --export > sarc-packages.pub.asc   # keep a copy of the public key
gpg --armor --export-secret-keys > sarc-packages.key.asc   # store offline, e.g. in a password manager
rm -rf "$GNUPGHOME"; unset GNUPGHOME
```

The key has no passphrase because CI uses it unattended; the secret store protects it.
Rotating it means users must import the new public key, so keep the offline copy.

### GitHub Pages

Pages must deploy from GitHub Actions (Settings -> Pages -> Source: GitHub Actions), or:

```bash
gh api -X POST repos/iamvirul/sarc/pages -f build_type=workflow
```

## Republishing

`packages.yml` rebuilds the repositories from release assets every run, so running it by
hand (Actions -> Package repositories -> Run workflow) republishes them, for example after
rotating the signing key. The repositories keep the newest 3 releases that carry packages.
