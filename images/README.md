# Images

Example Dockerfiles for building utility images used with Anchore Enterprise.

---

## Dockerfile.anchorectl

Builds a minimal Alpine-based image with `anchorectl` pre-installed. Useful as a base image or sidecar in CI/CD pipelines where you want a lightweight, ready-to-use `anchorectl` without installing it at runtime.

### Build arguments

| Argument | Default | Description |
|---|---|---|
| `ANCHORECTL_VERSION` | `6.0.0` | Version of `anchorectl` to install |

### Build

```bash
docker build -f Dockerfile.anchorectl -t anchorectl:6.0.0 .

# Override version
docker build -f Dockerfile.anchorectl --build-arg ANCHORECTL_VERSION=5.27.1 -t anchorectl:5.27.1 .
```

### Usage

Run interactively against an Anchore Enterprise instance:

```bash
docker run --rm \
  -e ANCHORECTL_URL=https://anchore.example.com \
  -e ANCHORECTL_USERNAME=admin \
  -e ANCHORECTL_PASSWORD=foobar \
  anchorectl:6.0.0 system status
```

Use as a base image in your own Dockerfile:

```dockerfile
FROM anchorectl:6.0.0
# add your scripts or tooling here
```

### Notes

- The binary is installed to `/usr/local/bin/anchorectl` and is the default `CMD`.
- `curl` and `tar` are included in the image (added during install and not removed) to keep the layer count low; the apk cache is cleared.
- Only the `linux/amd64` binary is downloaded. Rebuild with a different tarball URL if you need `arm64`.
