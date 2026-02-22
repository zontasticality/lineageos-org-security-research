# LineageOS Institutional Security Assessment

**Date:** February 22, 2026
**Scope:** Organizational security posture — governance, code review, build pipeline, signing, OTA distribution, vendor blob supply chain
**Methodology:** Primary-source analysis of 13 public repositories and web documentation. No systems were accessed or tested.

---

## Disclaimers

**This is not a vulnerability disclosure.** This document assesses LineageOS's *institutional* security posture — the organizational and infrastructure practices that determine how well the project can resist insider threats and supply chain attacks. No systems were accessed, no exploits were developed, and no private data was obtained.

**All sources are public.** Every finding is derived from publicly accessible GitHub repositories across the [LineageOS](https://github.com/LineageOS) and [lineageos-infra](https://github.com/lineageos-infra) organizations, public wiki pages, blog posts, trademark filings, and status pages. All code quotes are linked to commit-pinned GitHub permalinks.

**Scope limitations.** This assessment does NOT cover:

- Android framework security (AOSP-level vulnerabilities)
- Device-specific hardware security or firmware
- Individual CVEs in LineageOS-patched code
- The security posture of third-party platforms (Gerrit, Buildkite, Fly.io)

**Comparative context.** LineageOS is a volunteer-driven open-source project. Many findings here may apply to similar community projects. The intent is constructive: to identify areas where security posture could be strengthened, proportional to the project's impact on millions of users. Where comparable projects (GrapheneOS, CalyxOS, F-Droid) implement stronger controls, this is noted as evidence that such controls are feasible, not as a value judgment.

**Acknowledgment of strengths.** LineageOS maintains several noteworthy transparency practices:

- A [public governance charter](https://github.com/LineageOS/charter/blob/873eada469434d754dcdd9ca0b73a953d5a0407f/directors-working-agreement.md) with codified decision thresholds
- Open-source infrastructure configurations (Gerrit permissions, Tailscale ACLs, build scripts)
- Rapid detection and response during the [2020 SaltStack breach](https://status.lineageos.org/issues/5eae596b4a0ebd114676545f) ([archived](https://web.archive.org/web/2026*/https://status.lineageos.org/issues/5eae596b4a0ebd114676545f))
- Build verification tools ([update_verifier](https://github.com/LineageOS/update_verifier)) for independent OTA signature checking

These are genuine strengths that many comparable projects lack.

**Contact.** If any finding is inaccurate or missing important context, please open an issue on this repository.

---

## Executive Summary

This assessment identified five systemic concerns in LineageOS's institutional security:

1. **Critical concentration of power** — A single individual simultaneously holds LLC ownership with legal veto power, sole Tailscale network admin rights, infrastructure manager access, and a director seat. No documented mechanism exists to override or remove this individual. ([Finding 1](#1-critical-concentration-of-power-in-a-single-individual))

2. **Opaque signing pipeline** — The process that transforms unsigned builds into signed OTA updates has no public source code, no audit trail, and no multi-party controls. ([Finding 2](#2-opaque-signing-pipeline))

3. **Signing keys with no modern protections** — OTA signing keys are stored as unencrypted files (password explicitly stripped during generation), use RSA-2048/SHA-1, have never been rotated since January 2017, and show no evidence of HSM usage. ([Findings 3, 5](#3-signing-keys-stored-unencrypted-with-no-hsm))

4. **No mandatory code review** — All ~250 maintainers and 9 directors can bypass Gerrit review via direct push to any repository in their scope. No server-side hook enforces peer review. ([Finding 4](#4-no-mandatory-code-review))

5. **Unguarded build environment** — The build pipeline uses an EOL Docker base image, loads SSH keys into every build container, and sources an unversioned file (`/lineage/setup.sh`) in every build. ([Findings 7, 9](#7-unversioned-setupsh-executes-in-every-build))

---

<details>
<summary><strong>Trust Boundary Diagram</strong> (click to expand)</summary>

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL WORLD                                    │
│  Users, OEM firmware images, upstream AOSP, mirror operators             │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────────────────┐
         │         TRUST BOUNDARY 1: Code Contribution                 │
         │                                                             │
         │  Gerrit Review (review.lineageos.org)                       │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ ~250 maintainers can BYPASS review (direct push)    │    │
         │  │ 9 directors can push to ANY repo                    │    │
         │  │ c3po service account: force push + skip-validation  │    │
         │  │ No mandatory peer review                            │    │
         │  │ forgeCommitter allows identity spoofing             │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                           │                                 │
         │  GitHub Mirror ◄──────────┤ (auto-replicated from Gerrit)   │
         │  Build system pulls from GitHub (not Gerrit)                │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │         TRUST BOUNDARY 2: Build Pipeline                    │
         │                                                             │
         │  Buildkite CI + Docker containers                           │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ EOL Docker base image (ubuntu:16.04)                │    │
         │  │ SSH keys exposed to all build code                  │    │
         │  │ /lineage/setup.sh: unversioned arbitrary execution  │    │
         │  │ Unpinned source sync (branch heads, not commits)    │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                                                             │
         │  Vendor blobs (TheMuppets, 501+ repos)                      │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ Binary content — no code review possible            │    │
         │  │ SHA1 pinning is non-fatal                           │    │
         │  │ No provenance verification                          │    │
         │  └─────────────────────────────────────────────────────┘    │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │     TRUST BOUNDARY 3: Signing  ██ OPAQUE ██                 │
         │                                                             │
         │  blob.lineageos.org receives unsigned artifacts             │
         │  Signing happens somewhere — no public source code          │
         │  Keys: unencrypted RSA-2048/SHA-1, no HSM                   │
         │  No multi-party control, no audit trail                     │
         │  No key rotation (since January 7, 2017)                    │
         │  2 people have infrastructure access (1 is sole admin)      │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │     TRUST BOUNDARY 4: Distribution                          │
         │                                                             │
         │  OTA API (Flask on Fly.io, auto-deployed from GitHub)       │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ No response signing (API JSON is unsigned)          │    │
         │  │ Upstream data trusted without verification          │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                                                             │
         │  Updater App (on device)                                    │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ No certificate pinning, no hash verification        │    │
         │  │ RecoverySystem.verifyPackage() is the SOLE gate     │    │
         │  │ → Everything reduces to the signing key             │    │
         │  └─────────────────────────────────────────────────────┘    │
         └─────────────────────────────────────────────────────────────┘
```

</details>

---

## Key Findings

### 1. Critical concentration of power in a single individual

**Severity: CRITICAL**

Tom Powell (zifnab06) simultaneously holds LLC ownership (with absolute veto on legal/financial decisions and all director removals), sole Tailscale network admin rights, Infrastructure Manager access (SSH root to all servers), a director seat (1/9 vote), and membership in Developer Relations and Public Relations teams.

The charter grants LLC owners an absolute veto on "items of legal consequence" with no override mechanism:

> ```
> For items of legal consequence, that is direct or indirect legal and/or
> financial exposure to the project, veto power is reserved for LineageOS
> LLC owners.
> ```
>
> *Source:* [`directors-working-agreement.md` L17](https://github.com/LineageOS/charter/blob/873eada469434d754dcdd9ca0b73a953d5a0407f/directors-working-agreement.md) | Full analysis: [Phase 1](phase1-governance.md)

Director removals also require LLC owner sign-off (L29, L35), meaning no director can be removed without the consent of an LLC owner. The charter contains no mechanism to remove or override an LLC owner.

The Tailscale network configuration shows a sole admin:

> ```json
> "group:admin": ["zifnab06@github"],
> ```
>
> *Source:* [`policy.hujson` L4](https://github.com/lineageos-infra/tailscale-config/blob/5e2db47b8ea3894953c761b6dcc533c20596d8c0/policy.hujson#L4) | Full analysis: [Phase 1](phase1-governance.md)

Only `group:admin` can assign `tag:infra` and `tag:build` to machines (L7-L9). This means only one person can onboard or offboard infrastructure nodes. The other Infrastructure Manager (chirayudesai) can *access* existing infrastructure but cannot modify the network topology, and their access can be unilaterally revoked by the sole admin.

**Why this matters:** Any individual in this position — regardless of their intentions — represents a single point of failure for the entire project. A compromised account, a legal coercion event, or an incapacitation scenario would leave the project with no documented recovery path.

**Counterargument addressed:** Trust concentration exists in many open-source projects. This is true, and is acknowledged. The concern here is the *degree* — the combination of LLC legal control, infrastructure admin, and signing access in one person, with no override mechanism, is unusual even for volunteer projects.

---

### 2. Opaque signing pipeline

**Severity: CRITICAL**

The build script uploads unsigned artifacts to a staging server via SCP, and then signed OTA updates appear on the distribution server. No public source code documents what happens in between.

> ```bash
> scp out/dist/*target_files*.zip \
>     jenkins@blob.lineageos.org:/home/jenkins/incoming/${DEVICE}/${BUILD_UUID}/
> ```
>
> *Source:* [`build.sh` L91](https://github.com/lineageos-infra/build-config/blob/d60b136ae54a3513459ba576b81f97da3f56a584/android/build.sh#L91) | Full analysis: [Phase 3](phase3-build-pipeline.md)

The build script contains no signing commands. What happens between the unsigned upload to `blob.lineageos.org` and signed output appearing on `download.lineageos.org` is entirely opaque. No public repository contains the signing automation, logging configuration, or approval workflow.

**What is absent:** No signing audit log. No multi-party approval. No reproducibility check between unsigned input and signed output. No public attestation of what was signed, when, or by whom.

**Counterargument addressed:** A private signing pipeline could be a security measure (obscurity as a layer). However, obscurity without documented controls (HSM, threshold signing, audit logs) is not a substitute for verifiable security. The opacity prevents independent verification that adequate controls exist.

---

### 3. Signing keys stored unencrypted with no HSM

**Severity: CRITICAL**

The key generation template explicitly strips password protection from private keys:

> ```bash
> bash <(sed "s/2048/${2:-2048}/;/Enter password/,+1d" \
>     ../../../development/tools/make_key) \
>     $1 \
>     '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/...'
> ```
>
> *Source:* [`make_key.sh` L7](https://github.com/LineageOS/scripts/blob/2d92096b9b63e5f29a762fa77c1f0eb3b2eb0ae3/lineage-priv-template/make_key.sh#L7) | Full analysis: [Phase 4](phase4-signing.md)

The `sed` command `/Enter password/,+1d` deletes the password prompt and the subsequent input line from the upstream `make_key` script before executing it. The resulting `.pk8` private key files have no passphrase protection — any filesystem access equals full key compromise.

Searches across all 13 repositories for "HSM", "hardware security", "key vault", "threshold", "multi-party", and "quorum" returned no relevant results. No evidence of Hardware Security Module integration was found.

The keys reside in a private Git repository (`vendor/lineage-priv/keys/`) accessible to Infrastructure Managers via Tailscale SSH. The Tailscale policy shows exactly [two people](https://github.com/lineageos-infra/tailscale-config/blob/5e2db47b8ea3894953c761b6dcc533c20596d8c0/policy.hujson#L2-L5) have infrastructure access.

---

### 4. No mandatory code review

**Severity: CRITICAL**

The Gerrit permission configuration grants all PROJECT and OEM maintainer groups `push` permission on `refs/heads/*`, which allows bypassing Gerrit review entirely:

> ```python
> 'push': {
>     'rules': { group: {
>         'action': 'ALLOW',
>         'force': False
>     }}
> },
> ```
>
> *Source:* [`cron_group_perms.py` L64-69](https://github.com/lineageos-infra/gerrit-config/blob/fa3a8c073e4f7b11ca9da7983d31b5e57fe86fbf/cron_group_perms.py#L64-L69) | Full analysis: [Phase 2](phase2-code-review.md)

Every maintainer group also receives `forgeAuthor`, `forgeCommitter`, and `forgeServerAsCommitter` (L58-87), allowing commits attributed to any identity — including the Gerrit server itself.

The [only deployed Gerrit hook](https://github.com/lineageos-infra/gerrit-hooks/blob/076a3f465f428702bd7f1712892444ba11299f71/patchset-created) (`patchset-created`) triggers CI workflows. It does not block merges, enforce review requirements, or validate approval status. Hooks that could enforce policy (`ref-update`, `submit`, `commit-received`) are not deployed.

The LineageOS wiki [documents direct push as a standard workflow](https://wiki.lineageos.org/bypassing_gerrit) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/bypassing_gerrit)) for maintainers, used for mass-submitting commits and AOSP merges.

**Impact:** A single Head Developer can write code, self-review (+2), and self-submit in one action. No automated check prevents this on any repository, including `android_frameworks_base`, `android_system_core`, and `android_system_security`.

---

### 5. Signing keys unchanged for 9+ years, no rotation policy

**Severity: HIGH**

The public OTA signing certificate was generated on January 7, 2017, and has never been rotated:

> ```
> Not Before: Jan  7 04:21:25 2017 GMT
> Not After : May 25 04:21:25 2044 GMT
> ```
>
> *Source:* [`lineage.x509.pem`](https://github.com/LineageOS/android_vendor_lineage/blob/a1cee09ee3d35038d64b46e3b6a017e216e72500/build/target/product/security/lineage.x509.pem) | Full analysis: [Phase 4](phase4-signing.md)

The certificate uses RSA-2048 with SHA-1 (`sha1WithRSAEncryption`). SHA-1 has been considered cryptographically broken for collision resistance since 2017 ([SHAttered](https://shattered.io/)), and NIST deprecated SHA-1 for digital signatures in 2011. While preimage resistance remains, this does not meet modern signing standards.

No rotation occurred even after the [May 2020 infrastructure breach](#historical-precedent), despite the potential that attackers may have had deeper access than detected. No rotation policy, rotation tooling, or key revocation mechanism is documented anywhere in the analyzed repositories. The 27-year certificate validity (expiring 2044) suggests no planned rotation.

APEX module keys (added in LineageOS 19.1+) do use RSA-4096/SHA-256, indicating awareness of stronger algorithms — but the most critical keys (releasekey, platform) remain at RSA-2048/SHA-1.

---

### 6. c3po service account bypasses all review

**Severity: HIGH**

The `c3po` service account can force-push to any Gerrit repository with all validation bypassed:

> ```bash
> git remote add gerrit ssh://c3po@review.lineageos.org:29418/${REPO}
> # ...
> git push -o skip-validation --force gerrit HEAD:refs/heads/${DEST_BRANCH}
> ```
>
> *Source:* [`forcepush.sh` L8, L15](https://github.com/lineageos-infra/build-config/blob/d60b136ae54a3513459ba576b81f97da3f56a584/git/forcepush.sh#L8-L15) | Full analysis: [Phase 3](phase3-build-pipeline.md)

The `--force` flag overwrites branch history and `-o skip-validation` bypasses all Gerrit validation hooks and review requirements. This account is also used in `hudson-device-deps.sh` to auto-submit changes with `Code-Review+2`, `Verified`, and `submit` — self-approving without human review.

The `c3po` SSH credentials are stored in `/buildkite-secrets/` and loaded into every build container (see [Finding 9](#9-eol-docker-base-image-with-unpinned-dependencies)). Compromise of any build agent grants access to these credentials.

**Counterargument addressed:** Service accounts with elevated access are standard in CI/CD. The concern is the combination: unrestricted scope (any repository), no audit beyond Gerrit logs, and credentials accessible to all build code.

---

### 7. Unversioned setup.sh executes in every build

**Severity: HIGH**

Every official build sources a file from the persistent Docker volume that is not tracked in any repository:

> ```bash
> if [ -f /lineage/setup.sh ]; then
>     source /lineage/setup.sh
> fi
> ```
>
> *Source:* [`build.sh` L50-52](https://github.com/lineageos-infra/build-config/blob/d60b136ae54a3513459ba576b81f97da3f56a584/android/build.sh#L50-L52) | Full analysis: [Phase 3](phase3-build-pipeline.md)

This file lives on the persistent Docker volume, not in version control. Its contents are not logged, audited, or published. Anyone with SSH root access to a build host can place arbitrary code in this file, and it will execute with full build privileges in every subsequent build. The Tailscale policy shows [two people have such access](https://github.com/lineageos-infra/tailscale-config/blob/5e2db47b8ea3894953c761b6dcc533c20596d8c0/policy.hujson#L2-L5).

---

### 8. No hash verification by updater app

**Severity: HIGH**

The OTA API serves SHA-256 hashes of build files, but the Updater app uses these only as string identifiers — never comparing them against the downloaded content:

> ```java
> update.setDownloadId(object.getString("id"));
> ```
>
> *Source:* [`Utils.java` L79](https://github.com/LineageOS/android_packages_apps_Updater/blob/6910ef903f4eb9290f530eaa50e8ba6e621e7c64/app/src/main/java/org/lineageos/updater/misc/Utils.java#L79) | Full analysis: [Phase 5](phase5-ota-update.md)

The server-side API populates the `id` field with [`rom['files'][0]['sha256']`](https://github.com/lineageos-infra/updater/blob/62f9080c2519a7940078611ae59bddb9d6b4fb95/api_common.py#L132), but the client treats it as an opaque identifier. The sole verification mechanism is `RecoverySystem.verifyPackage()`:

> ```java
> private boolean verifyPackage(File file) {
>     try {
>         android.os.RecoverySystem.verifyPackage(file, null, null);
>         Log.e(TAG, "Verification successful");
>         return true;
>     } catch (Exception e) {
>         Log.e(TAG, "Verification failed", e);
>         // ...
>     }
> }
> ```
>
> *Source:* [`UpdaterController.java` L276-292](https://github.com/LineageOS/android_packages_apps_Updater/blob/6910ef903f4eb9290f530eaa50e8ba6e621e7c64/app/src/main/java/org/lineageos/updater/controller/UpdaterController.java#L276-L292)

The app also lacks certificate pinning and does not validate the download URL domain. This means the entire security of OTA updates for every LineageOS device reduces to a single control: the secrecy of the signing key.

---

### 9. EOL Docker base image with unpinned dependencies

**Severity: MEDIUM**

The build environment uses an end-of-life base image:

> ```dockerfile
> FROM ubuntu:16.04
> ```
>
> *Source:* [`Dockerfile` L1](https://github.com/lineageos-infra/docker-android/blob/f03533050aaf8f1408e6f84b8312fa86b6a209f0/Dockerfile#L1) | Full analysis: [Phase 3](phase3-build-pipeline.md)

Ubuntu 16.04 reached standard support end-of-life in April 2021. The image tag is not pinned by digest, meaning it is mutable. The Buildkite agent binary is downloaded at the unpinned `latest` version without hash verification (L31).

SSH keys for infrastructure access are loaded into every build container:

> ```bash
> eval "$(ssh-agent -s)"
> ssh-add -k /buildkite-secrets/*
> ```
>
> *Source:* [`hooks/environment` L5-7](https://github.com/lineageos-infra/docker-android/blob/f03533050aaf8f1408e6f84b8312fa86b6a209f0/hooks/environment#L5-L7)

The wildcard `*` loads all private keys from `/buildkite-secrets/` into the SSH agent. Any code executing during the build — from any of the ~600 synced repositories — can use these keys. The same keys are used to SCP unsigned builds to `blob.lineageos.org`.

---

### 10. SHA1 blob pinning is non-fatal

**Severity: MEDIUM**

The vendor blob extraction tooling uses SHA1 for file-level hash verification, but hash mismatches do not stop extraction:

> ```python
> elif file.hash is not None:
>     self.process_pinned_file(
>         file,
>         file_path,
>         False,
>     )
> # ...
> return True
> ```
>
> *Source:* [`module.py` L1091-1103](https://github.com/LineageOS/android_tools_extract-utils/blob/48bb722f4ee6413d0fdd7a37c0a25f4c0cae5564/extract_utils/module.py#L1091-L1103) | Full analysis: [Phase 6](phase6-vendor-blobs.md)

The return value of `process_pinned_file()` (which indicates MATCH, MISMATCH, or BAD_FIXUP) is discarded. The function always returns `True` regardless of whether the hash matched. A mismatch generates a warning but extraction continues. The [wiki documentation](https://wiki.lineageos.org/proprietary_blobs) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/proprietary_blobs)) confirms this is by design — SHA1 pinning is a *preservation* mechanism for "kanged" blobs, not a security control.

The [TheMuppets](https://github.com/TheMuppets) organization hosts 501+ repositories of pre-extracted binary blobs with opaque governance, no mandatory commit signing, and shallow clones (`clone-depth="1"`) that limit audit capability.

---

## Attack Scenarios

These scenarios are condensed from the [Phase 8 threat models](phase8-synthesis.md). Each describes a plausible attack path using only documented, legitimate access mechanisms.

<details>
<summary><strong>Scenario 1: Malicious Infrastructure Manager</strong></summary>

An Infrastructure Manager with signing key access could:

1. SSH to the signing infrastructure as root (via Tailscale `group:infra`)
2. Access unencrypted `.pk8` signing key files (no passphrase, no HSM)
3. Sign a pre-prepared malicious target-files package
4. Place the signed OTA on the distribution server
5. Users auto-download via the Updater app

**Mitigations present:** None — no multi-party signing, no signing audit log, no HSM key binding.
**Detection:** Near zero — the signing process is opaque with no published logs.

If the Infrastructure Manager is also the sole Tailscale admin (as is currently the case), they could additionally revoke the other manager's access by modifying the Tailscale policy, then use their LLC veto to block any governance response.

Full attack trees in [Phase 8 §2](phase8-synthesis.md).

</details>

<details>
<summary><strong>Scenario 2: Malicious Head Developer</strong></summary>

Any of the 9 Head Developers could:

1. Direct-push a backdoor to a security-critical repository (e.g., `android_frameworks_base`, `android_system_core`)
2. Use `forgeCommitter` to attribute the commit to another developer or the Gerrit server
3. The change auto-replicates to GitHub, where the build system pulls from
4. The next nightly build incorporates the malicious code and is signed normally

**Mitigations present:** The commit is visible in git history.
**Detection:** Low — direct pushes are routine for AOSP merges, and forged authorship looks legitimate. No commit signing is enforced.

Full attack trees in [Phase 8 §3](phase8-synthesis.md).

</details>

<details>
<summary><strong>Scenario 3: Compromised Build Server</strong></summary>

An attacker who gains access to a build agent could:

1. Modify `/lineage/setup.sh` on the persistent Docker volume
2. Every subsequent build executes this code with full build privileges
3. The code can access SSH keys loaded from `/buildkite-secrets/*`
4. Use these keys to SCP modified artifacts to `blob.lineageos.org`
5. The signing process signs whatever it finds in the staging directory

**Mitigations present:** None — `setup.sh` is unversioned, SSH keys are broadly scoped, and there is no integrity verification of uploaded artifacts.
**Detection:** Near zero — no file integrity monitoring on the persistent volume, and build logs are voluminous.

Full attack trees in [Phase 8 §4](phase8-synthesis.md).

</details>

<details>
<summary><strong>Scenario 4: Compromised Vendor Blob Source</strong></summary>

An attacker with push access to a TheMuppets `proprietary_vendor_*` repository could:

1. Replace a HAL library or system daemon binary blob with a backdoored version
2. Update the SHA1 hash in `proprietary-files.txt` to match (or rely on the majority of blobs being unpinned)
3. The next LineageOS build incorporates the malicious blob
4. No automated check detects the modification — blobs are opaque binaries not subject to code review

**Mitigations present:** None — binary content cannot be code-reviewed, SHA1 pinning is non-fatal, and TheMuppets governance is undocumented.
**Detection:** Near zero — no provenance verification, no binary diffing.

Full attack trees in [Phase 8 §5](phase8-synthesis.md).

</details>

---

## Single Points of Failure Ranking

### Tier 1: CRITICAL (System-wide compromise)

| # | Single Point of Failure | Impact | Current Mitigations |
|---|------------------------|--------|---------------------|
| 1 | **OTA Signing Key** — Unencrypted `.pk8` file, RSA-2048/SHA-1, accessible to 2 people | All devices can receive malicious updates | None: no HSM, no threshold signing, no rotation, no audit |
| 2 | **Tom Powell (zifnab06)** — LLC veto + sole Tailscale admin + infra access + director vote | Total organizational control with no override | None: no mechanism to override LLC owner |
| 3 | **Opaque signing pipeline** — No public source, no transparency | Unsigned-to-signed transformation is invisible | None: no reproducibility, no external verification |

### Tier 2: HIGH (Multi-device or infrastructure-wide)

| # | Single Point of Failure | Impact | Current Mitigations |
|---|------------------------|--------|---------------------|
| 4 | **c3po service account** — Force push + skip-validation to all repos | Unrestricted Gerrit write access | Gerrit logs (but c3po usage is routine) |
| 5 | **build-config `main` branch** — [Mirror workflow](https://github.com/lineageos-infra/build-config/blob/d60b136ae54a3513459ba576b81f97da3f56a584/.github/workflows/mirror-branches.yml) force-pushes to all version branches | Single commit affects all LineageOS version builds | Commit visible in git history |
| 6 | **/lineage/setup.sh** — Unversioned on persistent volume | Arbitrary code in every build | None |
| 7 | **GitHub org admin** — Build pulls from GitHub, not Gerrit | Can modify source of truth for builds | GitHub audit log |

### Tier 3: MEDIUM (Per-device or partial)

| # | Single Point of Failure | Impact | Current Mitigations |
|---|------------------------|--------|---------------------|
| 8 | **TheMuppets repos** — 501+ repos of binary blobs | Blob injection per device | None for binary content |
| 9 | **OTA API server** — Auto-deployed from GitHub to Fly.io | Update metadata manipulation | OTA signature prevents false packages (but allows rollback) |
| 10 | **Individual device maintainer** — Direct push to device repos | Compromise repos for their device(s) | Commit visible in history |

---

## Historical Precedent

These risks are not theoretical. The LineageOS ecosystem has experienced incidents that exercised several of the weaknesses documented above.

**May 2020: SaltStack infrastructure breach.** Attackers exploited CVE-2020-11651/CVE-2020-11652 on LineageOS servers, gaining infrastructure access. The project [detected the intrusion within hours](https://status.lineageos.org/issues/5eae596b4a0ebd114676545f) ([archived](https://web.archive.org/web/2026*/https://status.lineageos.org/issues/5eae596b4a0ebd114676545f)) and claimed signing keys were on separate infrastructure. This claim is credible but unverified — the [detailed post-mortem was promised](https://lineageos.org/Infrastructure-Status-and-Official-Builds/) ([archived](https://web.archive.org/web/2026*/https://lineageos.org/Infrastructure-Status-and-Official-Builds/)) but appears to have never been published. The 3-day gap between patch availability and exploitation highlights patch management challenges. Full analysis: [Phase 7 §7.2](phase7-incidents.md).

**January–December 2025: LineageOS4microG key exposure.** A maintainer of this derivative project inadvertently committed signing keys to a public git repository. They remained exposed for [11 months before detection by an external researcher](https://github.com/lineageos4microg/l4m-wiki/wiki/December-2025-security-issues). While L4M is a separate project, this incident demonstrates the risks inherent in volunteer-managed signing key infrastructure without automated secret scanning or HSM usage. Full analysis: [Phase 7 §7.3](phase7-incidents.md).

**February 2017: Incorrect build signing.** During a CAF rebase, a signing tool relocation caused builds to be incorrectly signed. The error was detected after distribution, not before. Full analysis: [Phase 7 §7.4.1](phase7-incidents.md).

---

## Comparative Analysis

| Security Practice | LineageOS | GrapheneOS | CalyxOS | F-Droid |
|---|---|---|---|---|
| **HSM for signing keys** | No evidence | Yes ([documented](https://grapheneos.org/faq#build-signing)) | Unknown | Yes ([documented](https://f-droid.org/en/docs/Signing_Process/)) |
| **Multi-party signing** | No | Unknown | Unknown | Yes |
| **Key rotation** | Never (9+ years) | Has rotated | Unknown | Has rotated |
| **Mandatory code review** | No | Yes | Unknown | Yes |
| **Reproducible builds** | No | Partial | No | Yes (for apps) |
| **Certificate pinning in updater** | No | Yes | Unknown | Yes (repo signing) |
| **Build environment pinning** | No (EOL Ubuntu, unpinned deps) | Yes | Unknown | Yes |
| **Locked bootloader support** | No (unlocked required) | Yes | No | N/A |
| **Post-incident transparency** | Poor¹ | Good | Unknown | Good |
| **Independent security audit** | Never published | Yes (multiple) | Unknown | Partial |
| **Governance transparency** | Good (public charter) | Limited | Moderate | Good |

¹ *The 2020 SaltStack post-mortem was promised but not published.*

"Unknown" cells indicate that public documentation was not found during this assessment. This does not imply the practice is absent — only that it could not be verified.

---

## Recommendations

### Immediate Priority (Addresses Critical Risk)

1. **Implement multi-party signing.** Require 2-of-3 key holders to sign each build using threshold cryptography or a multi-signature scheme.
2. **Move signing keys to HSMs.** Hardware Security Modules prevent key exfiltration and provide audit logging.
3. **Document and publish the signing pipeline.** Make the signing process source-available and publish signing logs.
4. **Resolve the concentration-of-power.** Add at least one more person to Tailscale `group:admin`. Document LLC membership. Create a "break glass" procedure for infrastructure lockout. Establish symmetric access revocation.

### High Priority

5. **Enforce mandatory code review** for security-critical repositories via a Gerrit `submit` requirement mandating +2 from a reviewer who is not the author.
6. **Scope build container credentials.** Don't load all SSH keys into every build container. Use ephemeral, per-build credentials.
7. **Pin and verify the Docker build environment.** Pin base images by digest hash, verify all downloaded binaries by SHA-256, and upgrade from EOL Ubuntu 16.04.
8. **Version-control `/lineage/setup.sh`** by moving its content into the build-config repo or removing the sourcing mechanism.
9. **Implement build attestation.** Save `repo manifest -r` output alongside each build for third-party verification. Consider [SLSA](https://slsa.dev/) framework compliance.

### Medium Priority

10. **Rotate signing keys** and establish a rotation policy. Migrate from RSA-2048/SHA-1 to RSA-4096/SHA-256 or Ed25519.
11. **Add certificate pinning** to the Updater app and verify SHA-256 hashes of downloaded files against the API response.
12. **Strengthen vendor blob security.** Migrate from SHA1 to SHA256 in `proprietary-files.txt`, make hash mismatches fatal, and implement provenance metadata.
13. **Publish post-incident reports** and commission an independent security audit of signing infrastructure.
14. **Require commit signing** (GPG or SSH) for at least Head Developers and infrastructure commits.

---

## Methodology

This assessment analyzed 13 public repositories and web documentation. No systems were accessed, probed, or tested. No credentials were obtained or attempted.

### Repositories Analyzed

| Repository | Org | Content | Commit |
|---|---|---|---|
| [charter](https://github.com/LineageOS/charter) | LineageOS | Governance documents | [`873eada`](https://github.com/LineageOS/charter/tree/873eada469434d754dcdd9ca0b73a953d5a0407f) |
| [gerrit-config](https://github.com/lineageos-infra/gerrit-config) | lineageos-infra | Gerrit permissions & automation | [`fa3a8c0`](https://github.com/lineageos-infra/gerrit-config/tree/fa3a8c073e4f7b11ca9da7983d31b5e57fe86fbf) |
| [build-config](https://github.com/lineageos-infra/build-config) | lineageos-infra | Build scripts & pipeline | [`d60b136`](https://github.com/lineageos-infra/build-config/tree/d60b136ae54a3513459ba576b81f97da3f56a584) |
| [docker-android](https://github.com/lineageos-infra/docker-android) | lineageos-infra | Build environment Docker image | [`f035330`](https://github.com/lineageos-infra/docker-android/tree/f03533050aaf8f1408e6f84b8312fa86b6a209f0) |
| [tailscale-config](https://github.com/lineageos-infra/tailscale-config) | lineageos-infra | Network access control | [`5e2db47`](https://github.com/lineageos-infra/tailscale-config/tree/5e2db47b8ea3894953c761b6dcc533c20596d8c0) |
| [auth](https://github.com/lineageos-infra/auth) | lineageos-infra | GitHub org membership | [`7f19e91`](https://github.com/lineageos-infra/auth/tree/7f19e913be6ffb66343c25b598b9d325e0e5dadd) |
| [gerrit-hooks](https://github.com/lineageos-infra/gerrit-hooks) | lineageos-infra | Gerrit server-side hooks | [`076a3f4`](https://github.com/lineageos-infra/gerrit-hooks/tree/076a3f465f428702bd7f1712892444ba11299f71) |
| [updater](https://github.com/lineageos-infra/updater) | lineageos-infra | OTA metadata API | [`62f9080`](https://github.com/lineageos-infra/updater/tree/62f9080c2519a7940078611ae59bddb9d6b4fb95) |
| [android_packages_apps_Updater](https://github.com/LineageOS/android_packages_apps_Updater) | LineageOS | On-device updater app | [`6910ef9`](https://github.com/LineageOS/android_packages_apps_Updater/tree/6910ef903f4eb9290f530eaa50e8ba6e621e7c64) |
| [android_vendor_lineage](https://github.com/LineageOS/android_vendor_lineage) | LineageOS | Vendor config & signing cert | [`a1cee09`](https://github.com/LineageOS/android_vendor_lineage/tree/a1cee09ee3d35038d64b46e3b6a017e216e72500) |
| [android_tools_extract-utils](https://github.com/LineageOS/android_tools_extract-utils) | LineageOS | Vendor blob extraction | [`48bb722`](https://github.com/LineageOS/android_tools_extract-utils/tree/48bb722f4ee6413d0fdd7a37c0a25f4c0cae5564) |
| [scripts](https://github.com/LineageOS/scripts) | LineageOS | Key generation & migration | [`2d92096`](https://github.com/LineageOS/scripts/tree/2d92096b9b63e5f29a762fa77c1f0eb3b2eb0ae3) |
| [update_verifier](https://github.com/LineageOS/update_verifier) | LineageOS | OTA signature verification tool | [`9ffcf56`](https://github.com/LineageOS/update_verifier/tree/9ffcf56a0fe152467da2971f0e6b2b79a42f7890) |

### What Was NOT Done

- No network scanning, penetration testing, or active probing of any LineageOS system
- No access to private repositories, internal communication channels, or non-public infrastructure
- No attempts to exploit any finding
- No contact with LineageOS team members during the assessment
- No analysis of compiled build outputs (only source code and configuration)

---

## Phase Reports

Detailed analysis for each area is available in the phase report files:

| Phase | Focus Area | Report |
|---|---|---|
| 1 | Governance & Legal Structure | [phase1-governance.md](phase1-governance.md) |
| 2 | Code Review & Commit Access | [phase2-code-review.md](phase2-code-review.md) |
| 3 | Build Pipeline Security | [phase3-build-pipeline.md](phase3-build-pipeline.md) |
| 4 | Signing Infrastructure | [phase4-signing.md](phase4-signing.md) |
| 5 | OTA Update & Distribution | [phase5-ota-update.md](phase5-ota-update.md) |
| 6 | Vendor Blob Supply Chain | [phase6-vendor-blobs.md](phase6-vendor-blobs.md) |
| 7 | Historical Incidents | [phase7-incidents.md](phase7-incidents.md) |
| 8 | Threat Modeling & Synthesis | [phase8-synthesis.md](phase8-synthesis.md) |

---

## External Sources

All external URLs are archived to [web.archive.org](https://web.archive.org) for long-term availability.

### LineageOS Official

- [LineageOS Contributors Wiki](https://wiki.lineageos.org/contributors) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/contributors))
- [Signing Builds Wiki](https://wiki.lineageos.org/signing_builds) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/signing_builds))
- [Verifying Build Authenticity Wiki](https://wiki.lineageos.org/verifying-builds) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/verifying-builds))
- [Bypassing Gerrit Wiki](https://wiki.lineageos.org/bypassing_gerrit) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/bypassing_gerrit))
- [Proprietary Blobs Wiki](https://wiki.lineageos.org/proprietary_blobs) ([archived](https://web.archive.org/web/2026*/https://wiki.lineageos.org/proprietary_blobs))
- [Legal Page](https://lineageos.org/legal/) ([archived](https://web.archive.org/web/2026*/https://lineageos.org/legal/))
- [Mirroring Documentation](https://lineageos.org/mirroring/) ([archived](https://web.archive.org/web/2026*/https://lineageos.org/mirroring/))
- [Infrastructure Status and Official Builds](https://lineageos.org/Infrastructure-Status-and-Official-Builds/) ([archived](https://web.archive.org/web/2026*/https://lineageos.org/Infrastructure-Status-and-Official-Builds/))
- [Status Page: May 2020 Outage](https://status.lineageos.org/issues/5eae596b4a0ebd114676545f) ([archived](https://web.archive.org/web/2026*/https://status.lineageos.org/issues/5eae596b4a0ebd114676545f))

### GitHub Organizations

- [LineageOS](https://github.com/LineageOS) — Main project organization
- [lineageos-infra](https://github.com/lineageos-infra) — Infrastructure repositories
- [TheMuppets](https://github.com/TheMuppets) — Vendor blob repositories
- [Buildkite Dashboard](https://buildkite.com/lineageos) ([archived](https://web.archive.org/web/2026*/https://buildkite.com/lineageos))

### Trademark & Legal

- [LineageOS Trademark — Justia](https://trademarks.justia.com/877/14/lineageos-87714781.html) ([archived](https://web.archive.org/web/2026*/https://trademarks.justia.com/877/14/lineageos-87714781.html))

### Incident References

- [The Hacker News: SaltStack Breach](https://thehackernews.com/2020/05/saltstack-rce-exploit.html) ([archived](https://web.archive.org/web/2026*/https://thehackernews.com/2020/05/saltstack-rce-exploit.html))
- [SecurityAffairs: LineageOS Hacked](https://securityaffairs.com/102708/hacking/lineageos-hacked.html) ([archived](https://web.archive.org/web/2026*/https://securityaffairs.com/102708/hacking/lineageos-hacked.html))
- [LineageOS4microG: December 2025 Security Issues](https://github.com/lineageos4microg/l4m-wiki/wiki/December-2025-security-issues)

---

*This assessment was conducted independently and is not affiliated with, endorsed by, or coordinated with the LineageOS project.*
