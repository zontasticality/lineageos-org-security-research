# Phase 3: LineageOS Build Pipeline Security Analysis

## Insider Threat Assessment of Build Infrastructure

**Date:** 2026-02-22
**Scope:** Complete build flow from repo sync to unsigned target-files upload, Docker environment, Buildkite configuration, build server access, blob.lineageos.org staging, and reproducibility

---

## Table of Contents

1. [Annotated Build Pipeline Diagram](#1-annotated-build-pipeline-diagram)
2. [Detailed Build Flow Trace](#2-detailed-build-flow-trace)
3. [Docker Environment Integrity Assessment](#3-docker-environment-integrity-assessment)
4. [Buildkite Pipeline Configuration Analysis](#4-buildkite-pipeline-configuration-analysis)
5. [Build Infrastructure Access Enumeration](#5-build-infrastructure-access-enumeration)
6. [blob.lineageos.org Staging Analysis](#6-bloblineageosorg-staging-analysis)
7. [Reproducibility Assessment](#7-reproducibility-assessment)
8. [Key Vulnerabilities from Insider Threat Perspective](#8-key-vulnerabilities-from-insider-threat-perspective)
9. [Sources](#9-sources)

---

## 1. Annotated Build Pipeline Diagram

```
                    LINEAGEOS BUILD PIPELINE - COMPLETE FLOW
                    =========================================

  [A] hudson repo                [B] build-config repo
  (lineage-build-targets)        (generator.py, build.sh)
        |                               |
        |  Device list fed              |  Pipeline YAML generated
        |  to generator.py              |  (device, version, UUID)
        v                               v
 +---------------------------------------------------------+
 |  [C] BUILDKITE: android-nightly pipeline                |
 |       Runs generator.py daily                           |
 |       Reads hudson/lineage-build-targets via stdin      |
 |       Applies cadence filtering (N/W/M)                 |
 |       Generates BUILD_UUID per device                   |
 |       Triggers "android" pipeline per device            |
 |  INJECTION POINT 1: Generator can add/modify devices    |
 |  INJECTION POINT 2: BUILD_UUID controls artifact path   |
 +---------------------------------------------------------+
              |
              | trigger (per device)
              v
 +---------------------------------------------------------+
 |  [D] BUILDKITE: android pipeline                        |
 |       Runs build.sh inside Docker container             |
 |       Environment: DEVICE, VERSION, TYPE,               |
 |                    RELEASE_TYPE, BUILD_UUID              |
 +---------------------------------------------------------+
              |
              v
 +---------------------------------------------------------+
 |  [E] DOCKER CONTAINER (docker-android image)            |
 |       Base: ubuntu:16.04 [!!! EOL !!!]                  |
 |       Buildkite agent + Android build deps              |
 |       SSH keys loaded from /buildkite-secrets/*         |
 |  INJECTION POINT 3: Docker image supply chain           |
 |  INJECTION POINT 4: SSH keys accessible in container    |
 +---------------------------------------------------------+
              |
              v
 +---------------------------------------------------------+
 |  [F] BUILD.SH EXECUTION (inside container)              |
 |                                                         |
 |  Step 1: repo init                                      |
 |    - Clones from github.com/lineageos/android.git       |
 |    - Branch = $VERSION                                  |
 |    - Uses repo rev v2.50.1                              |
 |    - Sources /lineage/setup.sh if exists                |
 |    INJECTION POINT 5: /lineage/setup.sh on volume       |
 |    INJECTION POINT 6: repo manifest manipulation        |
 |                                                         |
 |  Step 2: repo sync                                      |
 |    - Syncs ~600+ repos from GitHub                      |
 |    - git reset --hard && git clean -fdx on all repos    |
 |    - Retries up to 3 times                              |
 |    - Git LFS pull for repos with .gitattributes         |
 |    INJECTION POINT 7: GitHub repo compromise            |
 |    INJECTION POINT 8: MITM during sync (no pinning)     |
 |                                                         |
 |  Step 3: source build/envsetup.sh                       |
 |    INJECTION POINT 9: envsetup.sh code execution        |
 |                                                         |
 |  Step 4: rm -rf out* (clobber)                          |
 |                                                         |
 |  Step 5: breakfast $DEVICE $TYPE                        |
 |    - Sets up device-specific build config               |
 |    - Validates TARGET_PRODUCT starts with lineage_      |
 |                                                         |
 |  Step 6: (experimental only) repopick changes           |
 |    INJECTION POINT 10: EXP_PICK_CHANGES env var         |
 |                                                         |
 |  Step 7: mka otatools-package target-files-package dist |
 |    - Full Android build                                 |
 |    - Produces unsigned target-files .zip                 |
 |    - Produces otatools.zip                              |
 |    INJECTION POINT 11: Build system compromise          |
 +---------------------------------------------------------+
              |
              v
 +---------------------------------------------------------+
 |  [G] UPLOAD TO BLOB.LINEAGEOS.ORG                       |
 |       Via SCP as jenkins@ user                          |
 |       Path: /home/jenkins/incoming/$DEVICE/$BUILD_UUID/ |
 |       Files: *target_files*.zip + otatools.zip          |
 |  INJECTION POINT 12: SSH transport to blob server       |
 |  INJECTION POINT 13: blob server file replacement       |
 +---------------------------------------------------------+
              |
              v
 +---------------------------------------------------------+
 |  [H] SIGNING (separate, not in source code)             |
 |       Presumably runs on blob server or signing server  |
 |       sign_target_files_apks with LineageOS private keys|
 |       Produces signed target-files                      |
 |       ota_from_target_files creates OTA .zip            |
 |  INJECTION POINT 14: Signing key compromise             |
 |  INJECTION POINT 15: Signing server code modification   |
 +---------------------------------------------------------+
              |
              v
 +---------------------------------------------------------+
 |  [I] DISTRIBUTION                                       |
 |       download.lineageos.org (mirrorbits)               |
 |       OTA updates to devices                            |
 +---------------------------------------------------------+


  --- PARALLEL PIPELINES ---

  [J] android-sync pipeline
      - Pre-syncs repos on build hosts
      - Targets specific hosts via HOSTS env var
      - Runs repo sync -j128
      INJECTION POINT: Direct host targeting via env vars

  [K] crowdin pipeline (crowdin.sh)
      - Syncs translations
      - Pushes to Gerrit as c3po@ user
      - Builds ingot device to validate translations
      - Can abandon Gerrit changes on failure
      INJECTION POINT: c3po service account access

  [L] android-cleanup pipeline
      - Destroys and recreates Docker volume "lineage"
      - Targets specific host via HOST env var
      INJECTION POINT: Volume destruction = denial of service

  [M] forcepush pipeline
      - Force pushes branches from external repos to Gerrit
      - Uses --force and -o skip-validation flags
      - Pushes as c3po@ to review.lineageos.org:29418
      INJECTION POINT: Bypasses Gerrit code review entirely

  [N] hudson-device-deps pipeline
      - Regenerates device dependency mappings
      - Auto-submits to Gerrit with +2 review and submit
      - Pushes as c3po@ with refs/for/main%l=Code-Review+2,l=Verified,submit
      INJECTION POINT: Auto-approved Gerrit submissions
```

---

## 2. Detailed Build Flow Trace

### 2.1 Pipeline Generation (repo sync to build trigger)

The nightly build process starts with the `android-nightly` Buildkite pipeline, which runs `generator.py` from the `build-config` repo.

**Source file:** `sources/build-config/android/generator.py`

The generator reads `lineage-build-targets` from the `hudson` repo via stdin. This file contains device entries in the format:
```
<device> <build_type> <branch_name> <period>
```

The generator applies cadence filtering:
- **N (Nightly):** Built every day
- **W (Weekly):** Built once per week, day determined by `random.Random(device).randint(1, 7)`
- **M (Monthly):** Built once per month, day determined by `random.Random(device).randint(1, 28)`

For each device passing the filter, it generates a Buildkite pipeline step that triggers the `android` pipeline with environment variables:
- `DEVICE` - device codename
- `RELEASE_TYPE` - "nightly"
- `TYPE` - build type (usually "userdebug")
- `VERSION` - branch name (e.g., "lineage-23.2")
- `BUILD_UUID` - randomly generated UUID (uuid4)

**Security observation:** The `SHIP` and `SKIP` environment variables allow overriding cadence filtering. `SHIP=lineage-23.2` would force all devices for that version to build. These are controlled by whoever can set Buildkite environment variables.

### 2.2 Build Execution (build.sh)

**Source file:** `sources/build-config/android/build.sh`

Key steps in order:

1. **Environment setup:** Unsets `CCACHE_EXEC` (disabling ccache), sets `BUILD_ENFORCE_SELINUX=1`, computes `BUILD_NUMBER` from `BUILDKITE_BUILD_NUMBER + 10000000`

2. **repo init:** Initializes from `https://github.com/lineageos/android.git` at the specified `$VERSION` branch. Uses `--repo-rev=v2.50.1` (pinned repo tool version). Accepts license with `yes |`.

3. **Critical: `/lineage/setup.sh` sourcing:** If the file `/lineage/setup.sh` exists on the Docker volume, it is **sourced** (executed in the current shell). This file is not part of any tracked repository -- it lives on the persistent volume and can contain arbitrary shell commands.

4. **repo sync:** Runs `repo forall -c "git reset --hard && git clean -fdx"` to nuke all local changes, then syncs with up to 3 retries. Syncs with `--detach --current-branch --no-tags --force-remove-dirty --force-sync -j16`.

5. **Clobber:** `rm -rf out*` removes all previous build outputs.

6. **breakfast:** Configures for the target device. Validates the product name starts with `lineage_`.

7. **Experimental picks:** If `RELEASE_TYPE=experimental` and `EXP_PICK_CHANGES` is set, runs `repopick` on specified Gerrit change numbers. This allows cherry-picking arbitrary changes into the build.

8. **Build:** `mka otatools-package target-files-package dist` -- builds the unsigned target-files zip and the OTA tools package.

9. **Upload:** Uses `scp` as `jenkins@blob.lineageos.org` to upload:
   - `out/dist/*target_files*.zip` to `/home/jenkins/incoming/$DEVICE/$BUILD_UUID/`
   - `otatools.zip` to the same directory
   - Note: Commented-out `s3cmd` lines suggest a previous or planned S3-based upload path

10. **Cleanup:** `rm -rf out*`

### 2.3 Error Handling

**Source file:** `sources/build-config/android/error.sh`

On build failure, logs are uploaded via SCP to `jenkins@blob.lineageos.org` under `/home/jenkins/incoming/failures/$DEVICE/$BUILD_UUID/`. This uses the same SSH credentials as the build upload.

### 2.4 Branch Mirroring

**Source file:** `sources/build-config/.github/workflows/mirror-branches.yml`

A GitHub Actions workflow force-pushes `main` to `lineage-21.0`, `lineage-22.2`, `lineage-23.0`, and `lineage-23.2` branch names. This means all version branches are identical to `main` -- a single commit to `main` propagates to all active branches.

**Security implication:** Compromising the `main` branch of `build-config` instantly affects all LineageOS version builds, because the version-specific branches are just mirrors.

---

## 3. Docker Environment Integrity Assessment

### 3.1 docker-android Image (Buildkite Agent + Build Environment)

**Source file:** `sources/docker-android/Dockerfile`

#### Base Image

```dockerfile
FROM ubuntu:16.04
```

**CRITICAL FINDING:** The base image is `ubuntu:16.04` (Xenial Xerus), which reached standard support end-of-life in April 2021 and ESM end-of-life in April 2026. This image:
- Receives no free security updates
- Contains hundreds of known vulnerabilities (Snyk reports)
- Is not pinned by digest hash -- `ubuntu:16.04` tag is mutable and could be modified on Docker Hub

#### Unpinned Binary Downloads

```dockerfile
RUN curl -Lfs -o /sbin/tini https://github.com/krallin/tini/releases/download/v0.18.0/tini \
    && chmod +x /sbin/tini
```

The `tini` init process is downloaded directly from GitHub releases over HTTPS but **without hash verification**. An attacker controlling the GitHub release or performing a CDN compromise could substitute a malicious binary.

```dockerfile
RUN curl -sLo /usr/local/bin/buildkite-agent https://download.buildkite.com/agent/stable/latest/buildkite-agent-linux-amd64 \
    && chmod +x /usr/local/bin/buildkite-agent
```

The Buildkite agent binary is downloaded from Buildkite's CDN at the **`latest`** version -- not even pinned to a specific version. This is downloaded without hash verification. A Buildkite CDN compromise or DNS hijack would allow injecting a malicious agent binary.

```dockerfile
RUN curl -sLo /usr/local/bin/repo https://commondatastorage.googleapis.com/git-repo-downloads/repo \
    && chmod +x /usr/local/bin/repo
```

The Android `repo` tool is downloaded from Google's CDN without hash verification. Note that build.sh later uses `--repo-rev=v2.50.1` to pin the repo version at runtime, but the initial download in the Dockerfile is unpinned.

#### SSH Key Loading

**Source file:** `sources/docker-android/hooks/environment`

```bash
eval "$(ssh-agent -s)"
ssh-add -k /buildkite-secrets/*
```

The Buildkite agent's `environment` hook starts an SSH agent and loads **all** private keys from `/buildkite-secrets/`. This directory is presumably a mounted volume. Every build job has access to these SSH keys -- the same keys used to SCP to `blob.lineageos.org` as `jenkins@`.

**Security implications:**
- Any code running during the build (including code from synced repositories) has access to the SSH agent and can use the loaded SSH keys
- The keys are loaded with `-k` (add to keyring), meaning they persist for the entire job duration
- There is no key scoping -- all secrets in the directory are loaded for every job

#### Git Configuration

```dockerfile
RUN git config --global user.name "LineageOS Android Builder"
RUN git config --global user.email "nobody@localhost"
```

The git identity is generic, which means all automated commits/pushes from the builder would be attributed uniformly, making it harder to audit which specific build action made which change.

### 3.2 android-docker Image (Build-Config Repo Variant)

**Source file:** `sources/build-config/android-docker/Dockerfile`

```dockerfile
FROM ubuntu:20.04
```

This second Dockerfile uses `ubuntu:20.04` (Focal Fossa), which is newer but also approaching end of standard support (April 2025). It includes similar unpinned downloads:

```dockerfile
RUN curl -sLo /usr/local/bin/repo https://commondatastorage.googleapis.com/git-repo-downloads/repo && chmod +x /usr/local/bin/repo
```

This variant does NOT include the Buildkite agent -- it appears to be a build-only environment without CI integration. It enables ccache:

```dockerfile
ENV USE_CCACHE=1
ENV CCACHE_EXEC=/usr/bin/ccache
ENV CCACHE_DIR=/ccache
```

Note that `build.sh` explicitly unsets `CCACHE_EXEC`, so the ccache configuration in this Dockerfile is overridden at build time.

### 3.3 Docker Image Supply Chain Summary

| Component | Pinned? | Hash Verified? | Risk |
|-----------|---------|----------------|------|
| ubuntu:16.04 base | Tag only (mutable) | No | HIGH - EOL, tag can be updated |
| ubuntu:20.04 base | Tag only (mutable) | No | MEDIUM - Tag can be updated |
| tini v0.18.0 | Version pinned | No hash check | MEDIUM |
| buildkite-agent | `latest` (unpinned) | No hash check | HIGH |
| repo tool | Unpinned download | No hash check | MEDIUM (runtime pin via --repo-rev) |
| apt packages | Unpinned versions | Via apt signing | LOW-MEDIUM |
| pip packages | Unpinned (crowdin flow) | No | MEDIUM |

---

## 4. Buildkite Pipeline Configuration Analysis

### 4.1 Known Pipelines

Based on public Buildkite dashboard at `buildkite.com/lineageos`:

| Pipeline | Purpose | Frequency | Reliability |
|----------|---------|-----------|-------------|
| android | Run individual device builds | Per-device | 73% |
| android-nightly | Trigger nightly builds | 7/week | 93% |
| forcepush | Force push repos to Gerrit | ad-hoc | 95% |
| wiki-preview | Preview wiki changes | 16/week | 60% |
| www-preview | Preview website changes | 6/week | 93% |
| (3 hidden) | Unknown | Unknown | Unknown |

The Buildkite organization is publicly browsable at `https://buildkite.com/lineageos`.

### 4.2 Pipeline Modification Access

Buildkite pipelines can be configured to read their pipeline definition from:
1. The Buildkite web UI (editable by org members)
2. A `pipeline.yml` in the repository
3. A dynamically generated pipeline (like `generator.py`)

In LineageOS's case, the `android-nightly` pipeline uses `generator.py` to dynamically create pipeline steps. The `android` pipeline runs `build.sh`. Both files live in the `build-config` repository on GitHub.

**Who can modify pipeline behavior:**
- Anyone with push access to the `lineageos-infra/build-config` GitHub repository
- Anyone with admin access to the Buildkite organization "lineageos"
- The `main` branch force-mirror workflow means modifying `main` once propagates to all version branches

### 4.3 Build-Config Branch Mirroring Risk

The GitHub Actions workflow at `.github/workflows/mirror-branches.yml` force-pushes `main` to all active version branches (`lineage-21.0`, `lineage-22.2`, `lineage-23.0`, `lineage-23.2`). This means:

1. A malicious commit to `main` in `build-config` instantly becomes the build script for ALL LineageOS versions
2. The force-push (`-f`) means branch protections on version branches are bypassed
3. The workflow runs on every push to `main` with no additional approval

### 4.4 Experimental Build Pipeline

**Source file:** `sources/build-config/android/generator-android-experimental.py`

The experimental generator creates builds with `RELEASE_TYPE=experimental`. This pathway enables `repopick` of arbitrary Gerrit changes via the `EXP_PICK_CHANGES` environment variable:

```bash
if [ "$RELEASE_TYPE" '==' "experimental" ]; then
  if [ ! -z "$EXP_PICK_CHANGES" ]; then
    read -ra EXP_PICK_CHANGES <<< "$EXP_PICK_CHANGES"
    repopick ${EXP_PICK_CHANGES[@]}
  fi
fi
```

Anyone who can trigger an experimental build with custom `EXP_PICK_CHANGES` can inject arbitrary Gerrit changes into a build.

---

## 5. Build Infrastructure Access Enumeration

### 5.1 Tailscale Network Access

**Source file:** `sources/tailscale-config/policy.hujson`

```json
{
    "groups": {
        "group:infra": ["zifnab06@github", "chirayudesai@github"],
        "group:admin": ["zifnab06@github"],
    },
    "tagOwners": {
        "tag:infra": ["group:admin"],
        "tag:build": ["group:admin"],
    },
    "acls": [
        {"action": "accept", "users": ["group:infra"], "ports": ["tag:infra:*"]},
        {"action": "accept", "users": ["tag:infra"], "ports": ["tag:infra:443"]},
    ],
    "ssh": [
        {
            "action": "check",
            "src":    ["group:infra"],
            "dst":    ["tag:infra"],
            "users":  ["autogroup:nonroot", "root"],
        },
    ],
}
```

#### Access Matrix

| Person | Tailscale Group | SSH to Infra? | SSH as Root? | Can Tag Hosts? |
|--------|----------------|---------------|--------------|----------------|
| Tom Powell (zifnab06) | group:infra, group:admin | Yes (all ports) | Yes | Yes (tag:infra, tag:build) |
| Chirayu Desai (chirayudesai) | group:infra | Yes (all ports) | Yes | No |

**Key findings:**
- Only **two people** have SSH access to infrastructure via Tailscale: Tom Powell and Chirayu Desai
- Only **one person** (Tom Powell / zifnab06) is in `group:admin` and can assign tags to hosts
- `tag:build` exists as a tag but has NO ACL rules referencing it -- build servers may be tagged `tag:infra` instead, or the build tag may be unused
- SSH access uses `"action": "check"` which means Tailscale SSH with identity checking (not just network-level)
- Both users can SSH as **root** to any `tag:infra` host
- Infrastructure machines tagged `tag:infra` can reach each other only on port 443

### 5.2 Tailscale ACL Deployment

**Source file:** `sources/tailscale-config/.github/workflows/tailscale.yml`

The Tailscale ACL policy is automatically deployed via GitHub Actions using `tailscale/gitops-acl-action@v1`. On push to `main`, it applies; on PR, it tests. This means:
- Whoever has push access to the `tailscale-config` repo can modify network access controls
- The `TS_API_KEY` and `TS_TAILNET` secrets in GitHub grant full Tailscale admin API access

### 5.3 Buildkite Organization Access

Based on the Buildkite dashboard being publicly accessible at `buildkite.com/lineageos`, the organization exists but membership details are not public. However, from the codebase:

- The Buildkite agent token is referenced in `buildkite-agent.cfg` (commented out as `#token="xxx"`)
- The agent is tagged `queue=android-docker`
- The agent token would be passed at container runtime (environment variable or mounted file)

Whoever controls the Buildkite organization can:
- View and modify all pipeline configurations
- View build logs (which may contain secrets if not sanitized)
- Trigger manual builds with arbitrary environment variables
- Add new agents

### 5.4 Service Accounts

| Account | Used Where | Access Level |
|---------|-----------|--------------|
| `jenkins@blob.lineageos.org` | SCP upload from build agents | Write to `/home/jenkins/incoming/` |
| `c3po@review.lineageos.org:29418` | Gerrit push from multiple scripts | Code-Review+2, Verified, submit, force push, skip-validation |
| `nobody@localhost` | Git identity in Docker | Git commits from builder |

The `c3po` service account is particularly powerful:
- In `forcepush.sh`: Uses `--force` and `-o skip-validation` to force push to Gerrit, bypassing code review
- In `hudson-device-deps.sh`: Auto-submits changes with `%l=Code-Review+2,l=Verified,submit` -- self-approving and submitting without human review
- In `crowdin.sh`: Pushes translation changes and can abandon changes
- In `kernelpush.sh`: Force pushes kernel trees with `skip-validation`

### 5.5 Complete Access Summary

Individuals with the most critical access:

1. **Tom Powell (zifnab06):** Head Developer + Infrastructure Manager. Tailscale admin (sole admin). SSH root to all infra. Can tag/untag build hosts. Listed as Director.

2. **Chirayu Desai (cdesai/chirayudesai):** Head Developer + Infrastructure Manager. Tailscale infra group. SSH root to all infra. Listed as co-manager of signing processes.

3. **Anyone with push access to `lineageos-infra/build-config`:** Can modify build scripts that execute on all build agents.

4. **Anyone with Buildkite org admin access:** Can modify pipeline configs, trigger builds, view secrets in logs.

---

## 6. blob.lineageos.org Staging Analysis

### 6.1 Role in Pipeline

`blob.lineageos.org` serves as the **staging server** between the build phase and the signing/distribution phase. Based on the source code analysis:

**Inbound data flow (from build agents):**
```
build agent --[SCP as jenkins@]--> blob.lineageos.org:/home/jenkins/incoming/$DEVICE/$BUILD_UUID/
```

Files uploaded:
- `*target_files*.zip` -- unsigned target-files archive
- `otatools.zip` -- tools needed to sign and create OTA packages

**Failure logs:**
```
build agent --[SCP as jenkins@]--> blob.lineageos.org:/home/jenkins/incoming/failures/$DEVICE/$BUILD_UUID/
```

### 6.2 What We Know

- The server accepts SSH connections from build agents using the `jenkins` user
- SSH keys for `jenkins@blob.lineageos.org` are loaded from `/buildkite-secrets/*` in every build container
- The incoming directory structure is `$DEVICE/$BUILD_UUID/` -- the BUILD_UUID provides some unpredictability to paths
- There are commented-out `s3cmd` lines suggesting a planned or previous S3-based artifact storage:
  ```bash
  # s3cmd --no-check-md5 put out/dist/*target_files*.zip s3://lineageos-blob/${DEVICE}/${BUILD_UUID}/ || true
  ```
  Note the `--no-check-md5` flag and `|| true` (failure is silently ignored) in the S3 path.

### 6.3 What We Do NOT Know (gaps in available sources)

- What happens to artifacts AFTER they arrive on blob.lineageos.org (the signing pipeline is not in any publicly available repository)
- Whether the blob server has integrity monitoring
- How the signing server fetches files from blob.lineageos.org
- Whether there is any verification of the uploaded target-files (checksums, size checks, provenance attestation)
- Whether the blob server is accessible from the public internet or only via Tailscale
- How long artifacts persist on the blob server

### 6.4 Security Assessment of blob.lineageos.org

**Attack surface for an insider:**

1. **Direct file replacement:** Anyone with SSH access to the blob server (infra group: zifnab06, chirayudesai) could replace uploaded target-files with a trojaned version before signing occurs.

2. **Build agent credential abuse:** The `jenkins@blob.lineageos.org` SSH key is loaded into every build container. Malicious code in any synced repository that executes during the build could use the SSH agent to upload arbitrary files to the blob server, or overwrite existing builds.

3. **Race condition:** Between upload completion and signing pickup, there is a window where files could be swapped. The BUILD_UUID provides some protection (attacker must know the UUID), but the UUID is visible in Buildkite build logs.

4. **No integrity chain:** There is no cryptographic attestation linking a specific source code checkout to the uploaded target-files. The signing server presumably signs whatever it finds in the incoming directory.

---

## 7. Reproducibility Assessment

### 7.1 Current State: NOT Reproducible

LineageOS builds are **not reproducible** based on the following evidence:

#### Non-deterministic build inputs:

1. **Unpinned repo sync:** The build syncs from `github.com/lineageos/android.git` at a branch head, not a pinned commit. The exact source code used depends on the moment `repo sync` completes. Two builds triggered seconds apart could get different code.

2. **No manifest snapshot:** The build does not save or log the exact manifest (list of all repos at their synced commit SHAs). There is no `repo manifest -r` output preserved alongside the build artifacts.

3. **Docker image not pinned by digest:** The build environment uses tag-based Docker images that can change between builds.

4. **`/lineage/setup.sh` is opaque:** This file lives on the persistent Docker volume and its contents are not tracked or versioned.

5. **System package versions:** `apt update && apt -y upgrade` in the Dockerfile installs whatever package versions are current at image build time. Different image builds get different package versions.

6. **`pip3 install --user -r requirements.txt`** in several scripts installs unpinned Python packages at runtime.

#### Non-deterministic build process:

1. **Timestamps:** Android builds embed timestamps throughout. Without `SOURCE_DATE_EPOCH` or equivalent, builds are timestamp-dependent.

2. **Build numbering:** `BUILD_NUMBER` is computed from `BUILDKITE_BUILD_NUMBER` which is a monotonically increasing counter, not derived from source content.

3. **No hermetic build:** The build has network access during execution (for repo sync, pip install, etc.). Side-channel inputs can affect the build.

4. **ccache disabled but paths vary:** While `CCACHE_EXEC` is unset (disabling ccache), build paths like `/lineage/$VERSION/` mean different version branches produce different build paths, and absolute paths may be embedded in outputs.

### 7.2 What Would Be Needed for Reproducibility

- Pin all source repos to exact commit SHAs (save and publish `repo manifest -r` output)
- Pin Docker base image by digest hash (`FROM ubuntu:20.04@sha256:...`)
- Pin all downloaded binaries by hash
- Set `SOURCE_DATE_EPOCH` for timestamp normalization
- Eliminate network access during the build step itself
- Use a hermetic build system (Bazel-like)
- Publish build environment specifications alongside artifacts
- Multiple independent rebuilds by different parties

### 7.3 Third-Party Reproducibility Efforts

The robotnix project (Nix-based Android builder) has explored reproducible LineageOS builds. As of 2020, bit-for-bit reproducible target-files were achieved for select devices (crosshatch, marlin) with vanilla flavor, but this has not been maintained or expanded to cover all official devices.

---

## 8. Key Vulnerabilities from Insider Threat Perspective

### CRITICAL Vulnerabilities

#### V1: Single Point of Compromise -- `/lineage/setup.sh` Volume File
- **Location:** Persistent Docker volume, sourced by `build.sh` line 51
- **Risk:** Any code placed in this file executes with full build privileges in every build
- **Who can exploit:** Anyone with SSH root access to build hosts (zifnab06, chirayudesai)
- **Detection difficulty:** HIGH -- file is not version-controlled, not logged, not audited
- **Source reference:** `build.sh` line 50-52:
  ```bash
  if [ -f /lineage/setup.sh ]; then
      source /lineage/setup.sh
  fi
  ```

#### V2: SSH Keys Available to All Build Code
- **Location:** `/buildkite-secrets/*` mounted into every container, loaded by `hooks/environment`
- **Risk:** Any code executing during the build (from any of ~600+ synced repos) can use the SSH agent to access `blob.lineageos.org` and potentially other infrastructure
- **Who can exploit:** Any LineageOS repo maintainer who can merge code
- **Detection difficulty:** MEDIUM -- would show up in build logs if commands are logged, but builds produce large output

#### V3: Force Push Pipeline Bypasses All Code Review
- **Location:** `build-config/git/forcepush.sh`
- **Risk:** Force pushes to Gerrit with `--force` and `-o skip-validation` using the `c3po` service account. Can replace any branch's content without code review.
- **Who can exploit:** Anyone who can trigger the forcepush Buildkite pipeline
- **Detection difficulty:** LOW -- force push events are logged in Gerrit, but the pipeline's legitimate purpose provides cover
- **Source reference:** `forcepush.sh` line 15:
  ```bash
  git push -o skip-validation --force gerrit HEAD:refs/heads/${DEST_BRANCH}
  ```

#### V4: Auto-Approved Gerrit Submissions
- **Location:** `build-config/hudson-device-deps/hudson-device-deps.sh`
- **Risk:** Pushes changes to Gerrit with automatic `Code-Review+2`, `Verified`, and `submit` -- completely bypassing human review
- **Who can exploit:** Anyone who can modify the device-deps-regenerator scripts or influence their output
- **Detection difficulty:** MEDIUM -- changes appear in Gerrit history but look like routine automation
- **Source reference:** `hudson-device-deps.sh` line 35:
  ```bash
  git push ssh://c3po@review.lineageos.org:29418/LineageOS/hudson HEAD:refs/for/main%l=Code-Review+2,l=Verified,submit
  ```

#### V5: build-config Branch Mirroring Creates Single Point of Failure
- **Location:** `.github/workflows/mirror-branches.yml`
- **Risk:** A single malicious commit to `main` in `build-config` propagates via force push to all active version branches, affecting all LineageOS builds
- **Who can exploit:** Anyone with push access to the build-config repo on GitHub
- **Detection difficulty:** LOW -- the commit would be visible, but the force push means version branches have no independent history

### HIGH Vulnerabilities

#### V6: Docker Image Supply Chain
- **Risk:** Base image `ubuntu:16.04` is EOL with hundreds of known CVEs. Buildkite agent downloaded at `latest` without hash verification. Multiple unpinned binary downloads.
- **Who can exploit:** Upstream supply chain attackers, or insiders who control Docker image builds
- **Detection difficulty:** HIGH -- image contents are not audited or published

#### V7: blob.lineageos.org Staging Server -- No Integrity Verification
- **Risk:** No cryptographic link between build source code and uploaded artifacts. Artifacts can be replaced on the blob server before signing.
- **Who can exploit:** zifnab06 and chirayudesai (SSH access), or anyone who compromises the jenkins SSH key
- **Detection difficulty:** HIGH -- no published checksums of pre-signing artifacts

#### V8: Two-Person Infrastructure Control
- **Risk:** Only two people (zifnab06 and chirayudesai) have infrastructure access. No separation of duties between building, staging, and signing. No evidence of multi-party approval for infrastructure changes.
- **Impact:** Either individual could theoretically compromise the entire pipeline from build to distribution

#### V9: Experimental Build Path Allows Arbitrary Code Injection
- **Risk:** The `EXP_PICK_CHANGES` environment variable allows cherry-picking arbitrary Gerrit changes into a build. If an experimental build's artifacts accidentally enter the release pipeline, injected code would be signed and distributed.
- **Who can exploit:** Anyone who can trigger experimental builds with custom environment variables

### MEDIUM Vulnerabilities

#### V10: repo sync Without Commit Pinning
- **Risk:** Builds use branch heads, not pinned commits. A compromised GitHub repo or a well-timed malicious merge could inject code into a specific build.
- **Detection difficulty:** MEDIUM -- the specific commits built are not recorded alongside artifacts

#### V11: Crowdin Translation Pipeline
- **Risk:** The crowdin.sh script installs pip packages at runtime (`pip3 install --user -r requirements.txt`), downloads translations from an external service, and builds a device. A compromised crowdin dependency or translation file could inject code.
- **Detection difficulty:** HIGH -- translation files are complex and not commonly reviewed for malicious content

#### V12: Tailscale ACL Deployment via GitHub Actions
- **Risk:** Network access policies are deployed automatically from the GitHub repo. Compromising the repo or the `TS_API_KEY` secret would allow modifying network ACLs to grant access to build infrastructure.

---

## 9. Sources

### Primary Source Files Analyzed

- `sources/build-config/android/build.sh` -- Main build script
- `sources/build-config/android/generator.py` -- Nightly pipeline generator
- `sources/build-config/android/generator-android-experimental.py` -- Experimental build generator
- `sources/build-config/android/error.sh` -- Error log upload script
- `sources/build-config/android-sync/generator.py` -- Sync pipeline generator
- `sources/build-config/android-docker/Dockerfile` -- Build-only Docker image
- `sources/build-config/android-cleanup/generator.py` -- Cleanup pipeline generator
- `sources/build-config/hudson-device-deps/hudson-device-deps.sh` -- Device dependency auto-submission
- `sources/build-config/git/forcepush.sh` -- Force push script
- `sources/build-config/git/kernelpush.sh` -- Kernel force push script
- `sources/build-config/crowdin/crowdin.sh` -- Translation sync and build
- `sources/build-config/.github/workflows/mirror-branches.yml` -- Branch mirroring workflow
- `sources/docker-android/Dockerfile` -- Buildkite agent Docker image
- `sources/docker-android/entrypoint.sh` -- Container entrypoint
- `sources/docker-android/buildkite-agent.cfg` -- Agent configuration
- `sources/docker-android/hooks/environment` -- SSH key loading hook
- `sources/docker-android/lineage-init.sh` -- Repo initialization for legacy branches
- `sources/tailscale-config/policy.hujson` -- Tailscale network ACL policy
- `sources/tailscale-config/.github/workflows/tailscale.yml` -- ACL deployment workflow

### Web Sources

- [LineageOS Buildkite Pipelines](https://buildkite.com/lineageos)
- [LineageOS Contributors](https://wiki.lineageos.org/contributors)
- [LineageOS Infrastructure GitHub Organization](https://github.com/lineageos-infra)
- [LineageOS Verifying Builds](https://wiki.lineageos.org/verifying-builds)
- [LineageOS Signing Builds](https://wiki.lineageos.org/signing_builds)
- [LineageOS hudson/lineage-build-targets](https://github.com/LineageOS/hudson/blob/main/lineage-build-targets)
- [lineageos-infra/updater](https://github.com/lineageos-infra/updater)
- [Buildkite Agent Security Documentation](https://buildkite.com/docs/agent/v3/securing)
- [Buildkite Agent SSH Keys](https://buildkite.com/docs/agent/v3/ssh-keys)
- [ubuntu:16.04 Vulnerability Report (Snyk)](https://snyk.io/test/docker/ubuntu:16.04)
- [robotnix Reproducible Builds Issue #18](https://github.com/nix-community/robotnix/issues/18)
- [LineageOS Infrastructure Status Blog Post](https://lineageos.org/Infrastructure-Status-and-Official-Builds/)
