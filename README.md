# Simple Artifact Publisher

A minimal authenticated ZIP publisher for static artifacts. `POST /v1/artifacts` creates an opaque URL and `PUT /v1/artifacts/<id>` replaces it when the quoted `If-Match` revision matches. The process needs a SHA-256 digest of one or more bearer tokens in `API_TOKEN_SHA256`; it never stores plaintext tokens.

## Run

```sh
API_TOKEN_SHA256="$(printf token | sha256sum | cut -d' ' -f1)" \
ARTIFACT_ROOT=./artifacts \
PUBLIC_BASE_URL=https://assets.example \
node server.mjs
```

The server accepts ZIP archives up to 15 MiB compressed, 40 MiB expanded, and 200 files. A root `index.html` is required. ZIP entry paths, sizes, type, local-directory consistency and CRC-32 are verified before publication.

## CI/CD

Pushes to `main` test and publish a content-addressed image. CI then commits its immutable image digest to `deploy/docker-compose.yml`; the deploy workflow obtains a GitHub Actions OIDC token and sends it to a configured deployment receiver. The receiver must validate issuer, audience and exact subject before invoking a server-held Portainer stack webhook. No Portainer credential or webhook URL belongs in this repository or GitHub secrets.
