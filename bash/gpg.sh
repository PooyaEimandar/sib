#!/usr/bin/env bash
set -euo pipefail

echo "== Git GPG Setup (headless-safe) =="

read -rp "Git user name: " GIT_NAME
read -rp "Git email (same as GitHub/GitLab): " GIT_EMAIL
read -rsp "GPG passphrase (won't show): " GPG_PASSPHRASE
echo

mkdir -p ~/.gnupg
chmod 700 ~/.gnupg

if ! grep -q '^allow-loopback-pinentry$' ~/.gnupg/gpg-agent.conf 2>/dev/null; then
  echo 'allow-loopback-pinentry' >> ~/.gnupg/gpg-agent.conf
fi

gpgconf --kill gpg-agent >/dev/null 2>&1 || true
gpgconf --launch gpg-agent >/dev/null 2>&1 || true

gpg --batch --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $GIT_NAME
Name-Email: $GIT_EMAIL
Expire-Date: 0
%commit
EOF

KEY_ID=$(gpg --list-secret-keys --keyid-format=long "$GIT_EMAIL" \
  | awk '/sec/{print $2}' | cut -d'/' -f2)

echo "GPG Key ID: $KEY_ID"

git config --global user.name "$GIT_NAME"
git config --global user.email "$GIT_EMAIL"
git config --global user.signingkey "$KEY_ID"
git config --global commit.gpgsign true
git config --global gpg.program gpg

echo
echo "== Public key (copy/paste into GitHub/GitLab) =="
gpg --armor --export "$KEY_ID"
