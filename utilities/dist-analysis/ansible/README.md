# Distributed analysis with Ansible

An example Ansible playbook that runs **Anchore Enterprise distributed analysis** across a set of VMs. Ansible connects to each host, puts `anchorectl` on it, and analyzes on the host itself:

- the **host filesystem** (OS and application packages installed on the VM), and
- the images of **running containers** under **Docker** and/or **Podman**.

Only the resulting SBOMs are sent back to Anchore Enterprise. Anchore never needs registry access or a connection into the VM.

> [!IMPORTANT]
> This is a reference example, not a production-ready role. Like everything in this repository it is **unmaintained and provided "AS IS"**. Read it, adapt it, and test it in a non-production environment first.

## How it works

```
 Ansible controller                     Target VM                                Anchore Enterprise
 ──────────────────                     ─────────                                ──────────────────
 distributed-analysis.yml ──ssh──▶ 1. anchorectl placed in /tmp/anchore-dist-analysis
   (push: copies anchorectl)            (push from controller, or pull from a repo)
                                   2. anchorectl system status ───────────────▶ connectivity check
                                   3. app add / app version add ──────────────▶ App = host, Version = run
                                   4. asset add filesystem /  (Syft runs here) ─▶ filesystem asset
                                   5. docker|podman ps → for each image:
                                        image add --from docker|podman ───────▶ Images
                                        asset add container-image ────────────▶ container asset on App
                                        image check ◀────────────────────────── policy result
                                   6. work dir removed
```

In Anchore Enterprise each host gets an **App** (named after the inventory hostname). Every run adds a **Version** (a UTC timestamp), so you get a history per host. The host filesystem and each running image are **assets** on that Version. Images are also added to the regular **Images** view, where they get vulnerabilities and a policy evaluation.

## Prerequisites

| Where | What |
|---|---|
| Controller | Ansible ≥ 2.14 (only `ansible.builtin` modules are used) |
| Targets | Linux (amd64 or arm64), SSH access, `sudo` for the Ansible user, Python for Ansible |
| Targets (containers) | Docker and/or Podman CLI. For Podman, the API socket (see [Podman notes](#podman-notes)) |
| Anchore Enterprise | A version that supports **Applications** and anchorectl **v6** (`anchorectl app version asset add filesystem`) |
| Network | Targets → Anchore Enterprise API. With `pull`, also targets → the download location |

> The CI/CD examples elsewhere in this repo pin anchorectl **v5.27.1**. This example needs **v6** because host-filesystem analysis uses the App / Version / Asset commands. Set `anchorectl_version` to match your Anchore Enterprise release, or download from your Enterprise server so the versions always match (see below).

## Files

| File | Purpose |
|---|---|
| `distributed-analysis.yml` | The playbook |
| `inventory.yml` | Example inventory (Docker hosts, Podman hosts, hosts without containers, `localhost`) |
| `group_vars/all.yml` | Every setting, with comments |
| `tasks/install-anchorectl.yml` | Push or pull install of anchorectl |
| `tasks/app-version.yml` | Creates the host's App (if missing) and this run's Version |
| `tasks/scan-host.yml` | Filesystem analysis |
| `tasks/scan-containers.yml`, `tasks/scan-runtime.yml` | Container discovery and image analysis per runtime / user |
| `templates/anchorectl.yaml.j2` | anchorectl config written on each host (no password inside) |

## Quick start

```bash
cd utilities/dist-analysis/ansible

# Anchore Enterprise connection details, read on the controller
export ANCHORECTL_URL=https://anchore.example.com
export ANCHORECTL_USERNAME=dist-analysis
export ANCHORECTL_PASSWORD='...'
# export ANCHORECTL_ACCOUNT=my-account     # optional

# 1. Edit inventory.yml with your hosts
# 2. Check connectivity and the anchorectl install only
ansible-playbook distributed-analysis.yml --tags install

# 3. Full run
ansible-playbook distributed-analysis.yml
```

More examples:

```bash
# Only the host filesystem, on one group
ansible-playbook distributed-analysis.yml -l plain_hosts --tags host

# Only running containers on Podman hosts
ansible-playbook distributed-analysis.yml -l podman_hosts --tags containers

# Have each host download anchorectl itself from an internal mirror
ansible-playbook distributed-analysis.yml -e anchorectl_install_method=pull \
  -e anchorectl_download_url=https://nexus.example.com/repository/tools/anchorectl_6.2.0_linux_amd64.tar.gz

# Narrower filesystem scan and a fixed version label
ansible-playbook distributed-analysis.yml \
  -e '{"anchore_host_scan_paths": ["/usr", "/etc", "/var/lib/rpm", "/opt"]}' \
  -e anchore_app_version=2026-Q4-baseline

# Try it on the controller itself
ansible-playbook distributed-analysis.yml -l local -K
```

## Installing anchorectl: push or pull

Pick one with `anchorectl_install_method`. Both put the binary in `anchore_work_dir` (default `/tmp/anchore-dist-analysis`), which is removed at the end of the run (`anchore_cleanup: true`). Nothing is installed permanently.

### `push` (default): controller → hosts

The controller downloads `anchorectl_download_url` once per CPU architecture into `.cache/` next to the playbook, then copies it to each host. Targets need **no outbound access** apart from the Anchore API.

For fully air-gapped controllers, point `anchorectl_local_path` at a binary or `.tar.gz` that already exists on the controller. Nothing is downloaded then:

```yaml
anchorectl_install_method: push
anchorectl_local_path: /opt/tools/anchorectl_6.2.0_linux_amd64.tar.gz
anchorectl_download_is_archive: true   # false if it's the bare binary
```

### `pull`: each host downloads from a repository

Each host fetches `anchorectl_download_url` itself. This suits environments with an internal artifact repository (Artifactory, Nexus, an internal web server).

```yaml
anchorectl_install_method: pull
anchorectl_download_url: "https://artifactory.example.com/tools/anchorectl/{{ anchorectl_version }}/anchorectl_{{ anchorectl_version }}_linux_{{ anchorectl_arch }}.tar.gz"
anchorectl_download_username: svc-reader          # optional basic auth
anchorectl_download_password: "{{ vault_artifactory_password }}"
anchorectl_checksum: "sha256:..."                 # optional
```

### Download location options (both methods)

| Source | `anchorectl_download_url` | Notes |
|---|---|---|
| Public releases (default) | `https://anchorectl-releases.anchore.io/anchorectl/v{{ anchorectl_version }}/anchorectl_{{ anchorectl_version }}_linux_{{ anchorectl_arch }}.tar.gz` | |
| Internal mirror | your URL | Mirror the release tarball, or a bare binary with `anchorectl_download_is_archive: false` |
| Your Anchore Enterprise | `{{ anchore_url \| regex_replace('/$', '') }}/v2/system/anchorectl?operating_system=linux&architecture={{ anchorectl_arch }}` | Always matches the server version. Set `anchorectl_download_username/password` to Anchore credentials (e.g. `"{{ anchore_username }}"` / `"{{ anchore_password }}"`) |

`anchorectl_arch` is worked out per host (`amd64` / `arm64`), so mixed-architecture fleets work with both methods.

## Credentials

By default `anchore_url`, `anchore_username`, `anchore_password` and `anchore_account` are read from the `ANCHORECTL_*` environment variables **on the controller**. On each host:

- `anchorectl.yaml` in the work dir holds only the URL, username, account and TLS setting.
- The password is given to anchorectl via the `ANCHORECTL_PASSWORD` environment variable on each task and is **never written to disk**.

To use **ansible-vault** instead:

```bash
ansible-vault create group_vars/vault.yml
#   anchore_url: https://anchore.example.com
#   anchore_username: dist-analysis
#   anchore_password: ...
ansible-playbook distributed-analysis.yml -e @group_vars/vault.yml --ask-vault-pass
```

Use a dedicated Anchore user with the least privilege it needs (create images, apps and app versions, run policy evaluations) in the account the results belong to.

## Settings

All in `group_vars/all.yml`. Override them per host or group in the inventory, or with `-e`.

| Variable | Default | Description |
|---|---|---|
| `anchore_url` / `anchore_username` / `anchore_password` / `anchore_account` | `ANCHORECTL_*` env on the controller | Anchore Enterprise connection |
| `anchore_tls_insecure` | `false` | Skip TLS verification (lab only) |
| `anchorectl_version` | `6.2.0` | Version used in the default download URL |
| `anchorectl_install_method` | `push` | `push` or `pull` |
| `anchorectl_download_url` | public release URL | Where to download anchorectl |
| `anchorectl_download_is_archive` | `true` | URL serves a `.tar.gz` (`true`) or the bare binary (`false`) |
| `anchorectl_download_username` / `_password` | `""` | Basic auth for the download |
| `anchorectl_checksum` | `""` | e.g. `sha256:…`. One value only, so set it per arch group if you have mixed architectures |
| `anchorectl_download_validate_certs` | `true` | TLS verification for the download |
| `anchorectl_local_path` | `""` | push: use this file on the controller instead of downloading |
| `anchorectl_controller_cache_dir` | `<playbook dir>/.cache` | push: download cache |
| `anchore_work_dir` | `/tmp/anchore-dist-analysis` | Where anchorectl runs on the host |
| `anchore_cleanup` | `true` | Remove the work dir at the end |
| `anchore_app_name` | inventory hostname | App per host |
| `anchore_app_version` | UTC timestamp | Version label, evaluated once per run |
| `anchore_app_contact_name` / `anchore_app_description` | | Used when the App is created |
| `anchore_scan_host` | `true` | Analyze the host filesystem |
| `anchore_host_scan_paths` | `['/']` | Each path becomes a `filesystem` asset |
| `anchore_scan_containers` | `true` | Analyze running containers |
| `anchore_container_runtimes` | `[docker, podman]` | Runtimes to look at. Missing CLIs are skipped |
| `anchore_podman_users` | `[]` | Users whose rootless Podman containers are also scanned |
| `anchore_podman_start_socket` | `true` | Start the rootful `podman.socket` if needed |
| `anchore_attach_containers_to_app` | `true` | Also add each image as a `container` asset on the App Version |
| `anchore_policy_check` | `true` | Run `anchorectl image check` per image |
| `anchore_fail_on_policy` | `false` | Fail the host if any image fails policy |

## Caveats and notes

### Scanning `/`

`anchorectl app version asset add filesystem` has no exclude option, so scanning `/` walks everything on the host. That includes container storage (`/var/lib/docker`, `/var/lib/containers`, `~/.local/share/containers`). Packages inside images then also appear in the host's filesystem asset, and a large disk takes a while. If you'd rather keep host and container results apart, list the paths that matter instead, for example:

```yaml
anchore_host_scan_paths: [/etc, /usr, /var/lib/rpm, /var/lib/dpkg, /opt]
```

Each path becomes its own asset. The OS package database and `/etc/os-release` must fall under a path you scan for OS packages to be detected.

### Podman notes

- anchorectl reads Podman images through the Podman **API socket**. For rootful Podman the playbook starts `podman.socket` (`anchore_podman_start_socket`), which uses `/run/podman/podman.sock`.
- **Rootless** containers belong to a user and are invisible to root. Add those users to `anchore_podman_users`. Each needs their user socket running, and the playbook only warns if it is missing:
  ```bash
  sudo loginctl enable-linger appuser
  sudo -iu appuser systemctl --user enable --now podman.socket
  ```
  Becoming an unprivileged user needs Ansible's usual setup for that (e.g. `setfacl` on the target or `pipelining = True`).

### Containers

- Only **running** containers are looked at (`docker ps` / `podman ps`). Images that are present but not running are ignored.
- A container whose image tag was removed shows only an image ID. It has no name to record it under, so it is skipped and reported.
- Images are added with `--no-auto-subscribe`, because a locally built image may not exist in any registry.
- With `anchore_attach_containers_to_app: true` each image is analyzed twice (once for the Images view, once as an App asset). Turn it off if that time matters to you.

### Other

- `become: true` is used for the whole play. Reading the full filesystem and the Docker socket needs root.
- Large fleets: tune `forks` in `ansible.cfg` and expect a CPU/IO spike on each host while Syft runs.
- Scheduling (cron, AWX/AAP schedules, systemd timers) is left to you.
