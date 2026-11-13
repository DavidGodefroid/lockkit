#!/bin/sh
# Regenerates the key-mode fixtures of update's tests: a test cosign key pair
# (the private key encrypted with an empty password), an artifact, a bundle
# signed with the key and uploaded to Rekor, and one signed without the tlog
# upload. Needs cosign and network access to Rekor. Run it from this
# directory.
set -eu
cd "$(dirname "$0")"
rm -f cosign.key cosign.pub other.key other.pub artifact artifact.sigstore.json artifact.notlog.sigstore.json
COSIGN_PASSWORD= cosign generate-key-pair
COSIGN_PASSWORD= cosign generate-key-pair --output-key-prefix other
rm other.key
printf 'abc123  tool_1.0_linux_amd64.tar.gz\n' > artifact
COSIGN_PASSWORD= cosign sign-blob --yes --new-bundle-format --key cosign.key \
	--bundle artifact.sigstore.json artifact
COSIGN_PASSWORD= cosign sign-blob --yes --new-bundle-format --key cosign.key \
	--tlog-upload=false --bundle artifact.notlog.sigstore.json artifact
