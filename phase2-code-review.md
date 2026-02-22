# Phase 2: Code Review & Commit Access Analysis
## LineageOS Institutional Resilience Against Insider Threats

**Date:** 2026-02-22
**Scope:** Gerrit permission hierarchy, direct push capabilities, review enforcement, automated guardrails, mirror sync security

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Gerrit Permission Hierarchy & Matrix](#2-gerrit-permission-hierarchy--matrix)
3. [Individuals with Direct Push (Bypass) Capability](#3-individuals-with-direct-push-bypass-capability)
4. [Mandatory Review Enforcement Analysis](#4-mandatory-review-enforcement-analysis)
5. [Automated Guardrails (Gerrit Hooks)](#5-automated-guardrails-gerrit-hooks)
6. [GitHub Mirror Sync Security Assessment](#6-github-mirror-sync-security-assessment)
7. [Repos with Weak Review Gates](#7-repos-with-weak-review-gates)
8. [Key Vulnerabilities from Insider Threat Perspective](#8-key-vulnerabilities-from-insider-threat-perspective)
9. [Appendices](#9-appendices)

---

## 1. Executive Summary

LineageOS uses Gerrit (v3.13.1, at `review.lineageos.org`) as its primary code review system, with GitHub serving as a read-only mirror. The project's permission model is hierarchical, using Gerrit's project inheritance tree to delegate authority to device-specific and project-specific groups. However, analysis reveals several significant findings from an insider threat perspective:

- **9 "Head Developers" (Project Directors) have effective god-mode access** across the entire codebase, including the ability to bypass Gerrit review entirely via direct push (`refs/heads/*`).
- **~240+ device maintainers have direct push capability** scoped to their project groups, but the permissions granted are extremely broad -- including `push`, `pushMerge`, `forgeAuthor`, `forgeCommitter`, and `forgeServerAsCommitter` on `refs/heads/*`.
- **No server-side Gerrit hooks enforce mandatory code review.** The only deployed hook (`patchset-created`) triggers CI workflows on GitHub/Buildkite -- it does not block merges or enforce review requirements.
- **The `skip-validation` push option is actively used** in infrastructure scripts (e.g., `forcepush.sh`, `kernelpush.sh`), bypassing Gerrit review entirely for automated operations.
- **The GitHub mirror is a replication target, not a gating mechanism.** An insider with Gerrit push access can inject code that is immediately replicated to GitHub without any additional review.
- **Infrastructure control is concentrated in 1-2 individuals** (primarily `zifnab06`, with `chirayudesai` having partial access), creating a critical single-point-of-compromise for network-level infrastructure.

---

## 2. Gerrit Permission Hierarchy & Matrix

### 2.1 Project Inheritance Tree

The Gerrit project structure is defined in `structure.yml` (source: `sources/gerrit-config/structure.yml`). The inheritance chain flows as follows:

```
All-Projects (root)
  |
  +-- All-Users
  +-- Lineage-11.0-Projects
  |     +-- Lineage-13.0-Projects
  |           +-- Lineage-14.1-Projects
  |                 +-- Lineage-15.1-Projects
  |                       +-- Lineage-16.0-Projects
  |                             +-- Lineage-17.0-Projects
  |                                   +-- Lineage-17.1-Projects
  |                                         +-- Lineage-18.0-Projects
  |                                               +-- Lineage-18.1-Projects
  |                                                     +-- Lineage-19.0-Projects
  |                                                           +-- Lineage-19.1-Projects
  |                                                                 +-- Lineage-20.0-Projects
  |                                                                       +-- Lineage-21.0-Projects
  |                                                                             +-- Lineage-22.0-Projects
  |                                                                                   +-- Lineage-22.1-Projects
  |                                                                                         +-- Lineage-22.2-Projects
  |                                                                                               +-- Lineage-23.0-Projects
  |                                                                                                     +-- Lineage-23.1-Projects
  |                                                                                                           +-- Lineage-23.2-Projects
  |                                                                                                                 +-- Head-Developers
  |
  +-- Lineage-Device-Projects
  |     +-- OEM-Google, OEM-Samsung, OEM-Xiaomi, ... (60+ OEM groups)
  |           +-- PROJECT-Google-gs101, PROJECT-Samsung-exynos9820, ... (300+ project groups)
  |
  +-- Lineage-Unmaintained-Projects (580+ legacy repos)
  +-- Main-Enabled (web services, scripts, mirror, infrastructure)
  +-- PROJECT-Lineage-telephony
```

**Key inheritance insight:** Every Lineage-23.2-Projects child inherits from `Head-Developers`, which inherits from all versioned project groups up to `All-Projects`. This means permissions set at `All-Projects` level (e.g., for the `Head-Developers` group) cascade to ALL repositories in the project.

### 2.2 Permission Groups & Their Roles

Source: `sources/auth/github/data.yml`

| Group | Role | Member Count | Key Permissions |
|-------|------|-------------|-----------------|
| **Head Developers** | Project Directors | 9 | Global +2 Code-Review, Submit, Push (direct), Force Push, Forge Author/Committer |
| **Developer Relations** | Community/contributor management | 10 | Elevated review capabilities, device acceptance authority |
| **Maintainers** | Device/repo maintainers | ~240 | Code-Review, Verified, Submit, Push on assigned PROJECT/OEM groups |
| **Public Relations** | Communications | 7 | Likely limited to web-services repos |
| **Test Team** | QA | 0 (empty) | Unknown -- currently no members |
| **Retired Directors** | Former directors | Unknown | Inherits "Committers-Inactive" -- retains global Code-Approval permissions (per charter) |

### 2.3 Full Permission Matrix: PROJECT/OEM Groups

As defined in `cron_group_perms.py` (source: `sources/gerrit-config/cron_group_perms.py`), every PROJECT-* and OEM-* Gerrit group gets the following permissions on `refs/heads/*`:

| Permission | Scope | Force | Notes |
|------------|-------|-------|-------|
| `label-Code-Review` | -2 to +2 | No | Can approve OR block any change |
| `label-Verified` | -1 to +1 | No | Can mark as verified |
| `submit` | ALLOW | No | Can submit (merge) approved changes |
| `push` | ALLOW | No | **DIRECT PUSH -- bypasses Gerrit review entirely** |
| `pushMerge` | ALLOW | No | Can push merge commits directly |
| `forgeAuthor` | ALLOW | No | Can commit with someone else's author identity |
| `forgeCommitter` | ALLOW | No | Can commit with someone else's committer identity |
| `forgeServerAsCommitter` | ALLOW | No | Can forge commits as if from the Gerrit server itself |
| `abandon` | ALLOW | No | Can abandon changes |
| `editTopicName` | ALLOW | No | Can modify topic names |

Additionally, on specific branch refs (e.g., `refs/heads/staging/*`, `refs/heads/backup/*`, `refs/heads/lineage-18.1` through `refs/heads/lineage-23.2`):

| Permission | Scope | Notes |
|------------|-------|-------|
| `create` | ALLOW | Can create new branches matching these patterns |

**CRITICAL FINDING:** The `push` permission on `refs/heads/*` means that every member of a PROJECT/OEM group can bypass Gerrit review entirely for all repositories under that project group. Combined with `forgeAuthor`, `forgeCommitter`, and `forgeServerAsCommitter`, an insider can push code that appears to come from any other developer or from the Gerrit server itself.

### 2.4 Head Developers: Effective Permissions

The `Head-Developers` group sits at the top of the active project hierarchy (Lineage-23.2-Projects -> Head-Developers). Two specific repos are directly under Head-Developers:

- `LineageOS/android` (the repo manifest -- controls what gets included in builds)
- `LineageOS/hudson` (the build configuration -- controls which devices are built)

Head Developers, by virtue of Gerrit's built-in admin/owner capabilities and the inheritance chain, effectively have:
- Global `+2` Code-Review on ALL repositories
- Global `Submit` on ALL repositories
- Global `Push` (direct, bypassing review) on ALL repositories
- Access to Gerrit administration functions

### 2.5 Group Ownership Enforcement

Source: `sources/gerrit-config/cron_group_ownership.py`

A daily cron job (GitHub Actions, `0 0 * * *`) enforces that all PROJECT-* and OEM-* groups are owned by the `Head Developers` group. If any group's ownership has been changed, it is automatically corrected back. This prevents maintainers from escalating their group's privileges, but it also means that only Head Developers can modify group membership.

---

## 3. Individuals with Direct Push (Bypass) Capability

### 3.1 Head Developers (Global Direct Push)

These 9 individuals have unrestricted direct push access to ALL LineageOS repositories:

| GitHub Username | Notes |
|----------------|-------|
| `bgcngm` | Also in Maintainers list |
| `chirayudesai` | Also Tailscale infra access |
| `haggertk` | Also in DevRel, PR, Maintainers |
| `luca020400` | Also in DevRel, Maintainers |
| `luk1337` | Also in DevRel, Maintainers |
| `mikeNG` | Also in DevRel, Maintainers |
| `npjohnson` | Also in PR, Maintainers |
| `razorloves` | Also in DevRel, Maintainers |
| `zifnab06` | Also in DevRel, PR, Maintainers; primary infra admin |

### 3.2 Developer Relations (Elevated Access, Likely Direct Push)

10 members. Overlaps significantly with Head Developers. Unique non-Head-Developer members with DevRel access:

| GitHub Username | Notes |
|----------------|-------|
| `ciwrl` | Also in Maintainers, PR |
| `fourkbomb` | Also in Maintainers |
| `Rashed97` | Also in Maintainers |
| `sam3000` | Also in Maintainers |

### 3.3 Device/Project Maintainers (~240 individuals)

Every maintainer who is a member of a PROJECT-* or OEM-* Gerrit group has direct push access scoped to their assigned project's repositories. The full list of ~240 maintainer GitHub usernames is in:
`sources/auth/github/data.yml`

Notable: Service accounts with direct push:
- `cm-gerrit` -- legacy service account
- `lineageos-gerrit` -- current Gerrit service account

### 3.4 Infrastructure Service Account

The `c3po` SSH user is used for automated operations against Gerrit:
- Used in `forcepush.sh`: `ssh://c3po@review.lineageos.org:29418/`
- Used in `kernelpush.sh`: `ssh://c3po@review.lineageos.org:29418/`
- Both scripts use `--force` and `-o skip-validation` flags
- This account can push to ANY repository and explicitly skips all Gerrit validation (including review requirements)

---

## 4. Mandatory Review Enforcement Analysis

### 4.1 Is Gerrit Configured to Require Review Before Merge?

**No mandatory review enforcement was found in the analyzed configuration.**

Key evidence:

1. **The `push` permission on `refs/heads/*`** is granted to all PROJECT/OEM groups. In Gerrit, the `push` permission on `refs/heads/*` allows direct pushes that bypass the code review workflow entirely. This is the "bypassing Gerrit" mechanism documented at `https://wiki.lineageos.org/bypassing_gerrit`.

2. **No `label-Code-Review` requirement blocks submit.** While groups can give +2 Code-Review, there is no evidence of a `submit` requirement configuration that mandates a +2 from a different user before submission. The same user who uploads a change can +2 and submit it.

3. **No `Verified` requirement from CI.** The `patchset-created` hook triggers GitHub Actions and Buildkite workflows, but there is no mechanism observed that sets a `Verified` label back on Gerrit, nor any configuration requiring `Verified +1` before submission.

4. **The `forgeServerAsCommitter` permission** allows a maintainer to make commits appear as if they came from the Gerrit server itself, making it even harder to audit who actually pushed a change.

### 4.2 Wiki Documentation Confirms Bypass Is Expected

From `https://wiki.lineageos.org/bypassing_gerrit`:

> To bypass Gerrit review entirely:
> `git push lineage HEAD:refs/heads/lineage-23.2`

This is documented as a normal workflow for maintainers with `Push` and `Create Reference` permissions. The wiki explicitly states this is for mass-submitting commits, merges from AOSP, etc.

### 4.3 Security-Critical Repos Without Mandatory Review

The following security-critical repositories lack any additional review protections beyond the standard PROJECT/OEM group permissions:

| Repository | Parent Group | Risk |
|-----------|-------------|------|
| `LineageOS/android` (manifest) | Head-Developers | Controls which repos/branches are included in all builds |
| `LineageOS/hudson` | Head-Developers | Controls build configuration for all official devices |
| `LineageOS/android_build` | Lineage-23.2-Projects | Core build system |
| `LineageOS/android_build_soong` | Lineage-23.2-Projects | Modern build system |
| `LineageOS/android_vendor_lineage` | Lineage-23.2-Projects | Lineage-specific vendor configuration |
| `LineageOS/android_frameworks_base` | Lineage-23.2-Projects | Android framework (highest attack surface) |
| `LineageOS/android_system_sepolicy` | Lineage-23.2-Projects | SELinux policy |
| `LineageOS/android_system_core` | Lineage-23.2-Projects | Core system components (init, adb, etc.) |
| `LineageOS/android_system_security` | Lineage-23.2-Projects | Keystore, certificate management |
| `LineageOS/android_system_vold` | Lineage-23.2-Projects | Volume management, encryption |
| `LineageOS/scripts` | Main-Enabled | Build/release scripts |
| `LineageOS/android_external_openssh` | Lineage-23.2-Projects | SSH implementation |
| `LineageOS/android_external_wpa_supplicant_8` | Lineage-23.2-Projects | WiFi security |
| `LineageOS/ansible` | PROJECT-Infrastructure | Infrastructure configuration |
| `LineageOS/mirror` | PROJECT-Mirror | Mirror sync mechanism |

---

## 5. Automated Guardrails (Gerrit Hooks)

### 5.1 Deployed Hooks

Source: `sources/gerrit-hooks/`

**Only ONE Gerrit hook is deployed: `patchset-created`**

This hook (`sources/gerrit-hooks/patchset-created`):

1. **Triggers GitHub Actions workflows** on the corresponding GitHub repo when a new patchset is uploaded to Gerrit. It looks for workflows whose name starts with "gerrit" and dispatches them with the change reference.

2. **Triggers Buildkite preview builds** for `LineageOS/www` and `LineageOS/lineage_wiki` only.

3. **Explicitly skips certain events:**
   ```python
   if kind == "NO_CHANGE" or kind == "NO_CODE_CHANGE":
       return
   ```

4. **Does NOT:**
   - Block any pushes or submissions
   - Enforce review requirements
   - Check for approval status
   - Validate commit signatures
   - Verify that reviews were done by someone other than the author
   - Log security events beyond basic hook invocations to `/data/gerrit/review/logs/hook_logs`

### 5.2 Missing Hooks

The following Gerrit hooks that could enforce security policies are **NOT deployed**:

| Hook | Purpose | Impact of Absence |
|------|---------|-------------------|
| `ref-update` | Validates ref updates before they occur | No pre-push validation |
| `commit-received` | Validates individual commits | No commit content validation |
| `submit` | Validates before a change is submitted | No submit-time enforcement |
| `change-merged` | Post-merge actions | No post-merge auditing hook |
| `ref-updated` | Post-ref-update actions | No post-push auditing hook |

### 5.3 Cron-Based Guardrails (GitHub Actions)

Two automated enforcement mechanisms run via GitHub Actions:

1. **Group Permissions Reset** (`cron_group_perms.py`, hourly at `0 * * * *`):
   - Resets all PROJECT/OEM group permissions to the standard template
   - Prevents privilege escalation within project groups
   - Sends Discord notification if changes were made
   - **Limitation:** Cannot detect or prevent abuse of existing legitimate permissions

2. **Group Ownership Reset** (`cron_group_ownership.py`, daily at `0 0 * * *`):
   - Ensures all PROJECT/OEM groups are owned by `Head Developers`
   - Prevents maintainers from taking ownership of their group
   - **Limitation:** Head Developers can still modify any group

### 5.4 GitHub CODEOWNERS (Gerrit-Config Repo Only)

Source: `sources/gerrit-config/.github/CODEOWNERS`

```
*   @lineageos-infra/Infrastructure
```

This requires approval from the Infrastructure team for changes to the gerrit-config repository on GitHub. However, this only protects the GitHub copy -- it does not protect the actual Gerrit configuration from being modified by someone with Gerrit admin access.

---

## 6. GitHub Mirror Sync Security Assessment

### 6.1 Architecture: Gerrit Is Source of Truth

LineageOS uses Gerrit as its primary source of truth. GitHub serves as a mirror. The replication flow is:

```
Developer -> Gerrit (review.lineageos.org) -> [Gerrit Replication Plugin] -> GitHub (github.com/LineageOS)
```

Evidence from `kernelpush.sh` (source: `sources/build-config/git/kernelpush.sh`):
```bash
ssh -p 29418 c3po@review.lineageos.org replication start LineageOS/${REPO} --wait
```

This confirms Gerrit's built-in replication plugin pushes to GitHub.

### 6.2 Mirror Injection Risks

**Risk 1: Direct Push to Gerrit = Immediate Mirror Propagation**

Any user with `push` permission on `refs/heads/*` can push code directly to Gerrit, which is then automatically replicated to GitHub. There is no secondary review gate between Gerrit and GitHub.

**Risk 2: `skip-validation` Push Option**

The `forcepush.sh` script demonstrates that the `skip-validation` push option is used:
```bash
git push -o skip-validation --force gerrit HEAD:refs/heads/${DEST_BRANCH}
```

This skips ALL Gerrit validation, including any hooks or label requirements. The `c3po` service account has this capability.

**Risk 3: Force Push Capability**

The `forcepush.sh` script performs force pushes (`--force`) to Gerrit, which means it can overwrite branch history. An insider with access to the `c3po` credentials or the Buildkite CI system could rewrite history on any branch.

**Risk 4: GitHub-Side Push (Separate from Gerrit)**

The `mirror-branches.yml` workflow in build-config (source: `sources/build-config/.github/workflows/mirror-branches.yml`) force-pushes directly on GitHub:
```yaml
git push origin -f refs/remotes/origin/main:refs/heads/lineage-21.0
git push origin -f refs/remotes/origin/main:refs/heads/lineage-22.2
```

This shows that some GitHub repos have workflows that can write directly to branches, bypassing Gerrit entirely. An insider who compromises the `build-config` repo on GitHub (or its CI secrets) could inject code at the GitHub level.

**Risk 5: Build System Trusts GitHub**

The build system (`android/build.sh`) does `repo init -u https://github.com/lineageos/android.git` -- it pulls from GitHub, not Gerrit. If GitHub is compromised, builds will incorporate malicious code:
```bash
repo init -u https://github.com/lineageos/android.git -b ${VERSION}
```

### 6.3 Mirror Attack Surface Summary

| Attack Vector | Requires | Impact |
|--------------|----------|--------|
| Direct push to Gerrit | PROJECT/OEM group membership | Code lands in Gerrit + GitHub mirror |
| `skip-validation` push | `c3po` SSH credentials or CI access | Bypasses ALL Gerrit validation |
| Force push via CI scripts | Buildkite/CI access | Can rewrite branch history |
| GitHub Actions workflow compromise | Write access to `build-config` on GitHub | Can force-push to lineage branches |
| GitHub org admin compromise | GitHub org admin | Can push directly to GitHub mirror |
| Build system poisoning | Compromise of GitHub `LineageOS/android` repo | All builds pull from compromised manifest |

---

## 7. Repos with Weak Review Gates

### 7.1 Most Critical: No Extra Protection Beyond Standard Permissions

All of the following repos are under `Lineage-23.2-Projects` or `Head-Developers`, meaning any Head Developer can direct-push without review:

**Build Infrastructure:**
- `LineageOS/android` -- repo manifest, controls what gets built
- `LineageOS/hudson` -- device build configuration
- `LineageOS/android_build` -- build system
- `LineageOS/android_build_soong` -- modern build system
- `LineageOS/android_vendor_lineage` -- LineageOS vendor overlay

**Core Framework (highest impact):**
- `LineageOS/android_frameworks_base` -- Android framework
- `LineageOS/android_frameworks_av` -- Audio/video framework
- `LineageOS/android_frameworks_native` -- Native framework

**Security-Critical:**
- `LineageOS/android_system_sepolicy` -- SELinux policy
- `LineageOS/android_system_security` -- Keystore, crypto
- `LineageOS/android_system_core` -- init, adb, logcat
- `LineageOS/android_system_vold` -- disk encryption
- `LineageOS/android_system_netd` -- network daemon
- `LineageOS/android_bionic` -- C library
- `LineageOS/android_external_openssh` -- SSH
- `LineageOS/android_external_wpa_supplicant_8` -- WiFi security
- `LineageOS/android_external_boringssl` -- TLS library (Lineage-18.1+)

**Infrastructure:**
- `LineageOS/ansible` -- server configuration (under PROJECT-Infrastructure)
- `LineageOS/mirror` -- mirror configuration (under PROJECT-Mirror)
- `LineageOS/scripts` -- release/build scripts (under Main-Enabled)
- `LineageOS/cve_tracker` -- CVE tracking (under PROJECT-web-services)
- `LineageOS/lineageos_updater` -- OTA update server (under PROJECT-web-services)

### 7.2 OEM/Device Repos: Broad Maintainer Access

Each OEM group's repos can be direct-pushed by any member of that OEM's PROJECT group. Notable high-value targets:

- `PROJECT-qcom-hardware` (~90 repos) -- Qualcomm HAL code runs on majority of LineageOS devices
- `PROJECT-samsung-hardware` (~40 repos) -- Samsung HAL code
- `PROJECT-Google-*` groups -- Google Pixel device trees
- `PROJECT-Xiaomi-*` groups -- Xiaomi device trees (very popular devices)

### 7.3 Web Services (Public-Facing)

Under `PROJECT-web-services`:
- `LineageOS/cve_tracker` -- If compromised, could hide CVEs
- `LineageOS/lineage_wiki` -- Could distribute false instructions
- `LineageOS/lineageos_updater` -- **OTA update server; highest impact for end-user compromise**
- `LineageOS/tribble-tracker` -- Device tracking

---

## 8. Key Vulnerabilities from Insider Threat Perspective

### VULN-1: No Mandatory Peer Review for Any Repository (CRITICAL)

**Description:** Gerrit is configured to allow direct push (`refs/heads/*`) for all project groups. There is no `submit` requirement that mandates a second reviewer. A single Head Developer can push arbitrary code to any repository without any review.

**Impact:** A compromised Head Developer account (or a malicious Head Developer) could inject backdoors into `android_frameworks_base`, `android_system_core`, or the build system with no record of review.

**Evidence:** `push` permission on `refs/heads/*` in `cron_group_perms.py` lines 64-68; wiki documentation at `https://wiki.lineageos.org/bypassing_gerrit`.

### VULN-2: Forge Permissions Enable Identity Spoofing (HIGH)

**Description:** All PROJECT/OEM groups have `forgeAuthor`, `forgeCommitter`, and `forgeServerAsCommitter` permissions. This allows any maintainer to create commits attributed to any other developer, or to the Gerrit server itself.

**Impact:** Makes forensic investigation of malicious commits extremely difficult. An attacker could frame another developer or make malicious commits appear to come from automated processes.

**Evidence:** `cron_group_perms.py` lines 57-87.

### VULN-3: Single Infrastructure Administrator (HIGH)

**Description:** The Tailscale network configuration (source: `sources/tailscale-config/policy.hujson`) shows that `zifnab06` is the sole `group:admin` with full infrastructure control. `chirayudesai` has `group:infra` access. Only these two have SSH access to infrastructure servers.

**Impact:** Compromise of `zifnab06`'s account provides total control over all LineageOS infrastructure, including the Gerrit server, build systems, and signing infrastructure.

**Evidence:** `policy.hujson`: `"group:admin": ["zifnab06@github"]`

### VULN-4: Service Account with Unrestricted Access (HIGH)

**Description:** The `c3po` service account can push to any repository via SSH with `--force` and `-o skip-validation`, bypassing all Gerrit validation. Its credentials are stored as Buildkite secrets (`/buildkite-secrets/*`).

**Impact:** Compromise of the Buildkite CI system or the `c3po` SSH key grants unrestricted write access to all LineageOS repositories.

**Evidence:** `forcepush.sh`, `kernelpush.sh`, `docker-android/hooks/environment`.

### VULN-5: Build System Pulls from GitHub Mirror, Not Gerrit (MEDIUM)

**Description:** The build system (`android/build.sh`) initializes from `https://github.com/lineageos/android.git`, not from Gerrit directly. If the GitHub mirror is compromised independently of Gerrit, all builds would incorporate malicious code.

**Impact:** A GitHub-level compromise (e.g., via a compromised GitHub org admin account, or a GitHub Actions workflow vulnerability) could inject code into official builds without any trace in Gerrit.

**Evidence:** `build.sh` line 54: `repo init -u https://github.com/lineageos/android.git`

### VULN-6: OTA Updater Repository Lacks Enhanced Protection (HIGH)

**Description:** `LineageOS/lineageos_updater` is under `PROJECT-web-services`, which follows the standard PROJECT group permission model with direct push access. Compromise of this service could allow distribution of malicious updates.

**Impact:** An insider in the web-services project group could modify the OTA update server to distribute malicious builds to end users.

**Evidence:** `structure.yml` line 3915.

### VULN-7: Hourly Permission Reset Creates a 1-Hour Attack Window (MEDIUM)

**Description:** The `cron_group_perms.py` script resets project permissions hourly. If an insider modifies their group's permissions to gain additional access, they have up to 59 minutes before the change is detected and reverted.

**Impact:** An insider could temporarily escalate their permissions, perform malicious pushes, and have the evidence automatically cleaned up by the cron job.

**Evidence:** `gerrit_group_perms.yaml`: `cron: "0 * * * *"`

### VULN-8: No Commit Signing Enforcement (MEDIUM)

**Description:** While the Gerrit instance supports GPG keys and signed pushes, there is no evidence of mandatory commit signing enforcement. Combined with forge permissions, this means there is no cryptographic guarantee of commit authorship.

**Impact:** Commits can be attributed to any identity without cryptographic verification.

**Evidence:** Gerrit configuration indicates `gpg_key_editing: Supported` but no enforcement observed.

### VULN-9: Retired Directors Retain Code Approval Permissions (LOW-MEDIUM)

**Description:** Per the Directors Working Agreement (charter), retired directors are moved to a "Retired Directors" group that inherits "Committers-Inactive," retaining global Code-Approval permissions.

**Impact:** Former project leaders who may no longer be actively vetted retain the ability to approve code changes across all repositories.

**Evidence:** `directors-working-agreement.md` line 37.

### VULN-10: GitHub Actions Secrets Concentration (MEDIUM)

**Description:** Multiple GitHub Actions workflows hold sensitive secrets: `GERRIT_USER`/`GERRIT_PASS` (Gerrit admin credentials), `ADMIN_GITHUB_TOKEN` (GitHub admin token), `DISCORD_WEBHOOK`, `X_GITHUB_TOKEN`, `TS_API_KEY` (Tailscale API key). Compromise of any GitHub Actions workflow could leak these credentials.

**Impact:** A supply chain attack on a GitHub Actions dependency (e.g., `actions/checkout`, `actions/setup-python`) could exfiltrate admin credentials for both Gerrit and GitHub.

**Evidence:** Workflow files in `gerrit-config/.github/workflows/`, `auth/.github/workflows/`, `tailscale-config/.github/workflows/`.

---

## 9. Appendices

### Appendix A: Head Developers Cross-Membership

| Username | Head Dev | DevRel | Maintainer | PR | Notes |
|----------|----------|--------|------------|-----|-------|
| bgcngm | X | | X | | |
| chirayudesai | X | | X | | Tailscale infra |
| ciwrl | | X | X | X | |
| fourkbomb | | X | X | | |
| haggertk | X | X | X | X | |
| luca020400 | X | X | X | | |
| luk1337 | X | X | X | | |
| mikeNG | X | X | X | | |
| npjohnson | X | | X | X | |
| Rashed97 | | X | X | | |
| razorloves | X | X | X | | |
| sam3000 | | X | X | | |
| zifnab06 | X | X | X | X | Sole infra admin |

### Appendix B: Gerrit Configuration Automation Summary

| Workflow | Schedule | Action | Secrets Used |
|----------|----------|--------|-------------|
| `gerrit_group_perms.yaml` | Hourly | Reset PROJECT/OEM group permissions | GERRIT_USER, GERRIT_PASS, DISCORD_WEBHOOK |
| `gerrit_group_ownership.yaml` | Daily | Reset group ownership to Head Developers | GERRIT_USER, GERRIT_PASS, DISCORD_WEBHOOK |
| `gerrit_structure.yaml` | On push to main | Create missing repos, set parent hierarchy | GERRIT_USER, GERRIT_PASS, ADMIN_GITHUB_TOKEN, DISCORD_WEBHOOK |
| `github_auth.yaml` | Hourly + on push | Sync GitHub org membership from data.yml | X_GITHUB_TOKEN |
| `tailscale.yml` | On push/PR | Sync Tailscale ACLs | TS_API_KEY, TS_TAILNET |
| `mirror-branches.yml` | On push to main | Force-push main to lineage-* branches | GitHub token (default) |

### Appendix C: Source Files Analyzed

| File | Path |
|------|------|
| Structure definition | `sources/gerrit-config/structure.yml` |
| Group permissions cron | `sources/gerrit-config/cron_group_perms.py` |
| Group ownership cron | `sources/gerrit-config/cron_group_ownership.py` |
| Gerrit API library | `sources/gerrit-config/lib.py` |
| Structure update script | `sources/gerrit-config/update.py` |
| Patchset-created hook | `sources/gerrit-hooks/patchset-created` |
| Hook config example | `sources/gerrit-hooks/config.py.example` |
| GitHub auth data | `sources/auth/github/data.yml` |
| GitHub auth script | `sources/auth/github/main.py` |
| Force push script | `sources/build-config/git/forcepush.sh` |
| Kernel push script | `sources/build-config/git/kernelpush.sh` |
| Build script | `sources/build-config/android/build.sh` |
| Mirror branches workflow | `sources/build-config/.github/workflows/mirror-branches.yml` |
| Docker entrypoint hooks | `sources/docker-android/hooks/environment` |
| Tailscale ACL policy | `sources/tailscale-config/policy.hujson` |
| Directors working agreement | `sources/charter/directors-working-agreement.md` |
| Bypassing Gerrit wiki | `https://wiki.lineageos.org/bypassing_gerrit` |
| Gerrit instance | `https://review.lineageos.org` (v3.13.1) |

---

*End of Phase 2 Analysis*
