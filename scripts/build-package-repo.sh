#!/usr/bin/env bash
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Builds signed apt and dnf repositories from .deb and .rpm packages, for GitHub Pages.
#
#   build-package-repo.sh PACKAGE_DIR SITE_DIR BASE_URL
#
# The signing key must already be in the gpg keyring; the first secret key is used, or
# the one named by SIGNING_KEY. Layout of SITE_DIR:
#
#   sarc.gpg                   armored public key
#   apt/dists/stable/...       Release, InRelease, Release.gpg, Packages per architecture
#   apt/pool/main/s/sarc/      .deb files
#   rpm/                       .rpm files, repodata/ with a signed repomd.xml
#   rpm/sarc.repo              dnf repository definition
#   index.html                 install instructions
#
# Requires apt-ftparchive (apt-utils), createrepo_c, and gpg.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 PACKAGE_DIR SITE_DIR BASE_URL" >&2
  exit 2
fi
packages=$1
site=$2
base_url=${3%/}

for tool in apt-ftparchive createrepo_c gpg; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done

key=${SIGNING_KEY:-$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')}
if [ -z "$key" ]; then
  echo "error: no secret key in the gpg keyring to sign the repositories with" >&2
  exit 1
fi

shopt -s nullglob
debs=("$packages"/*.deb)
rpms=("$packages"/*.rpm)
if [ ${#debs[@]} -eq 0 ] || [ ${#rpms[@]} -eq 0 ]; then
  echo "error: $packages needs both .deb and .rpm packages" >&2
  exit 1
fi

sign() { gpg --batch --yes --local-user "$key" "$@"; }

rm -rf "$site"
mkdir -p "$site"
gpg --batch --armor --export "$key" > "$site/sarc.gpg"

# apt: one "stable" suite with a "main" component.
apt_root=$site/apt
pool=pool/main/s/sarc
mkdir -p "$apt_root/$pool"
cp "${debs[@]}" "$apt_root/$pool/"
architectures=$(for d in "${debs[@]}"; do dpkg-deb --field "$d" Architecture; done | sort -u | tr '\n' ' ')
(
  cd "$apt_root"
  for arch in $architectures; do
    dir=dists/stable/main/binary-$arch
    mkdir -p "$dir"
    apt-ftparchive --arch "$arch" packages "$pool" > "$dir/Packages"
    gzip -9 --keep --force "$dir/Packages"
  done
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=sarc \
    -o APT::FTPArchive::Release::Label=sarc \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Components=main \
    -o "APT::FTPArchive::Release::Architectures=${architectures% }" \
    release dists/stable > dists/stable/Release.tmp
  mv dists/stable/Release.tmp dists/stable/Release
  sign --clearsign --output dists/stable/InRelease dists/stable/Release
  sign --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
)

# dnf: repomd.xml is signed; it pins every package's SHA-256, so the signature covers
# the packages too (repo_gpgcheck).
rpm_root=$site/rpm
mkdir -p "$rpm_root"
cp "${rpms[@]}" "$rpm_root/"
createrepo_c --quiet "$rpm_root"
sign --armor --detach-sign --output "$rpm_root/repodata/repomd.xml.asc" "$rpm_root/repodata/repomd.xml"
cat > "$rpm_root/sarc.repo" <<EOF
[sarc]
name=sarc
baseurl=$base_url/rpm
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=$base_url/sarc.gpg
EOF

cat > "$site/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>sarc packages</title>
<h1>sarc packages</h1>
<p>Debian and Ubuntu:</p>
<pre>sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL $base_url/sarc.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/sarc.gpg
echo "deb [signed-by=/etc/apt/keyrings/sarc.gpg] $base_url/apt stable main" | sudo tee /etc/apt/sources.list.d/sarc.list
sudo apt update && sudo apt install sarc</pre>
<p>Fedora, RHEL, and other dnf systems:</p>
<pre>sudo curl -fsSL -o /etc/yum.repos.d/sarc.repo $base_url/rpm/sarc.repo
sudo dnf install sarc</pre>
<p>Source and releases: <a href="https://github.com/iamvirul/sarc">github.com/iamvirul/sarc</a></p>
EOF

echo "built apt (${architectures% }) and rpm repositories with $((${#debs[@]})) .deb and ${#rpms[@]} .rpm package(s), signed by $key"
