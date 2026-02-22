# Phase 4: LineageOS Signing Infrastructure Analysis

**Date:** 2026-02-22
**Classification:** Security Research -- Insider Threat Assessment
**Priority:** HIGHEST

---

## Table of Contents

1. [Complete Key Inventory](#1-complete-key-inventory)
2. [Key Storage Assessment](#2-key-storage-assessment)
3. [Multi-Party Signing Assessment](#3-multi-party-signing-assessment)
4. [Signing Pipeline Map](#4-signing-pipeline-map)
5. [Key Rotation History and Policy](#5-key-rotation-history-and-policy)
6. [Key Migration Risk Assessment](#6-key-migration-risk-assessment)
7. [Public Key Distribution / Trust Chain](#7-public-key-distribution--trust-chain)
8. [Insider Threat Vulnerability Assessment](#8-insider-threat-vulnerability-assessment)

---

## 1. Complete Key Inventory

### 1.1 Standard Platform Keys (RSA-2048, SHA-1 signatures)

All standard platform keys were generated on **January 7, 2017** (based on certificate `Not Before` dates in migration.sh and lineage.x509.pem). Subject DN for all release keys: `C=US, ST=Washington, L=Seattle, O=LineageOS, OU=LineageOS, CN=LineageOS`.

| Key Name | Algorithm | Purpose | File Format |
|----------|-----------|---------|-------------|
| `releasekey` | RSA-2048, SHA-1 | Default signing key for APKs; OTA package whole-file signature | `.pk8` + `.x509.pem` |
| `platform` | RSA-2048, SHA-1 | Platform-privileged apps (SystemUI, Settings, etc.) | `.pk8` + `.x509.pem` |
| `shared` | RSA-2048, SHA-1 | Apps sharing UID with other shared-signed apps | `.pk8` + `.x509.pem` |
| `media` | RSA-2048, SHA-1 | Media framework / media provider apps | `.pk8` + `.x509.pem` |
| `testkey` | RSA-2048, SHA-1 | Development/debug signing; aliased as releasekey in template | `.pk8` + `.x509.pem` |
| `bluetooth` | RSA-2048 | Bluetooth stack signing | `.pk8` + `.x509.pem` |
| `nfc` | RSA-2048 | NFC services signing | `.pk8` + `.x509.pem` |
| `networkstack` | RSA-2048 | Network stack module | `.pk8` + `.x509.pem` |
| `sdk_sandbox` | RSA-2048 | SDK sandbox process | `.pk8` + `.x509.pem` |
| `testcert` | RSA-2048 | Test certificate | `.pk8` + `.x509.pem` |
| `cyngn-app` | RSA-2048 | Legacy CyanogenMod app signing (carried forward) | `.pk8` + `.x509.pem` |

**Source:** Wiki signing_builds page lists: bluetooth, cyngn-app, media, networkstack, nfc, platform, releasekey, sdk_sandbox, shared, testcert, testkey.

**Critical observation:** The `lineage.x509.pem` certificate in `sources/android_vendor_lineage/build/target/product/security/` uses:
- **RSA-2048** public key
- **SHA-1** signature algorithm (sha1WithRSAEncryption)
- Self-signed CA certificate (CA:TRUE)
- Valid: 2017-01-07 to 2044-05-25 (27-year validity)

### 1.2 APEX Module Keys (RSA-4096, SHA-256)

Since LineageOS 19.1, each APEX module requires TWO keys:
1. An **outer certificate** (signs the APEX container): RSA-4096, `.pk8` + `.x509.pem`
2. An **inner payload key** (signs the filesystem image inside the APEX): RSA-4096, `.pem` (OpenSSL PEM format)

From `keys.mk`, there are **74+ APEX certificate overrides** defined in `PRODUCT_CERTIFICATE_OVERRIDES`, each mapping to a `.certificate.override` name. Examples include:

```
com.android.adbd:com.android.adbd.certificate.override
com.android.art:com.android.art.certificate.override
com.android.bluetooth:com.android.bluetooth.certificate.override
com.android.conscrypt:com.android.conscrypt.certificate.override
com.android.media:com.android.media.certificate.override
com.android.runtime:com.android.runtime.certificate.override
com.android.wifi:com.android.wifi.certificate.override
...
```

Each requires both an `.x509.pem`/`.pk8` pair AND a separate `.pem` payload key.

**Source:** `sources/scripts/lineage-priv-template/keys.mk` (lines 4-86), `keys.sh` (line 23 -- generates with 4096-bit size).

### 1.3 Recovery/OTA Verification Key

```makefile
# In android_vendor_lineage/config/common.mk line 286-287:
PRODUCT_EXTRA_RECOVERY_KEYS += \
    vendor/lineage/build/target/product/security/lineage
```

This adds the `lineage.x509.pem` certificate as an **extra recovery key**, meaning the recovery partition's `otacerts.zip` will contain BOTH the default dev certificate AND this lineage certificate. This is the key used by `RecoverySystem.verifyPackage()` to authenticate OTA updates.

**Note:** In the lineage-priv-template, `PRODUCT_EXTRA_RECOVERY_KEYS` is set to empty (line 89), indicating the template strips extra recovery keys -- official builds use the mechanism in common.mk instead.

### 1.4 Kernel Module Signing Key

```makefile
# In android_vendor_lineage/build/tasks/kernel.mk lines 556-558:
$(KERNEL_OUT)/scripts/sign-file sha1 \
    $(KERNEL_OUT)/certs/signing_key.pem \
    $(KERNEL_OUT)/certs/signing_key.x509 "$$m";
```

Kernel modules are signed with a **build-time ephemeral key** generated during the kernel compilation. This is standard Linux kernel module signing behavior -- the key is auto-generated per build and not persistent.

### 1.5 OTA Whole-File Signature Key

The `releasekey` is used with `ota_from_target_files -k` to produce the whole-file signature on the OTA ZIP. This is the signature verified by `RecoverySystem.verifyPackage()` and the external `update_verifier.py` tool.

### 1.6 Public Verification Key

The `lineageos_pubkey` file in the `update_verifier` GitHub repo contains the RSA-2048 public key corresponding to the releasekey. The modulus matches the certificate in `lineage.x509.pem`:
```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEApk3T4fhCA4/wP2e46b8JUw/CkTy1PjZUx47CDbyLHnETYoylq8CG
BWDLRCwbUfmLbc5eWcSQN/J/ZPSK7wSQq5kQbwgHohMOGos6rNg05lbwhUtgJne2
...
-----END RSA PUBLIC KEY-----
```

---

## 2. Key Storage Assessment

### 2.1 Evidence of Storage Method

**No HSM usage detected.** There is zero evidence across all examined repositories of Hardware Security Module integration, threshold cryptography, or any hardware-backed key protection. Specific searches for "HSM", "hardware security", "key vault", "threshold", "multi-party", and "quorum" returned no relevant results in any LineageOS source repository.

### 2.2 Password-Less Key Generation

**CRITICAL FINDING:** The `make_key.sh` template script in lineage-priv-template explicitly **removes password protection** from generated keys:

```bash
# sources/scripts/lineage-priv-template/make_key.sh
bash <(sed "s/2048/${2:-2048}/;/Enter password/,+1d" ../../../development/tools/make_key) \
    $1 \
    '/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=Android/emailAddress=android@android.com'
```

The `sed` command `/Enter password/,+1d` **deletes the password prompt and the line after it** from the `make_key` script before executing it. This means:
- Keys generated by this template have **no passphrase protection**
- Private keys (`.pk8` files) are stored as **unencrypted DER-encoded PKCS#8**
- Any file system access = full key compromise

### 2.3 Private Key Repository (`vendor/lineage-priv`)

The private keys are stored in a **separate private Git repository** at `vendor/lineage-priv/keys/`. Evidence:

- `keys.mk` sets: `PRODUCT_DEFAULT_DEV_CERTIFICATE := vendor/lineage-priv/keys/testkey`
- `common.mk` includes: `-include vendor/lineage-priv/keys/keys.mk` (soft include, non-fatal if absent)
- README instructs: "Copy to $TOP/vendor/lineage-priv/keys"

This repository is **not publicly accessible** -- it is a private repo that must be present on build infrastructure. The template in `scripts/lineage-priv-template/` is the public template for generating one's own keys.

### 2.4 Assessed Storage Architecture

Based on all evidence:

| Aspect | Assessment |
|--------|-----------|
| **Key storage medium** | Plain filesystem in a private Git repository |
| **Encryption at rest** | None (password prompt explicitly removed) |
| **HSM protection** | None detected |
| **Access control** | Git repository access control + filesystem permissions |
| **Key backup** | Git repository (version control history contains all key material) |
| **Physical protection** | Unknown; keys reside on build servers accessible via Tailscale VPN |

### 2.5 Build Server Key Access

From the Tailscale policy (`sources/tailscale-config/policy.hujson`):
```json
"groups": {
    "group:infra": ["zifnab06@github", "chirayudesai@github"],
    "group:admin": ["zifnab06@github"],
}
```

Only **two individuals** (zifnab06, chirayudesai) have infrastructure access. Only **one** (zifnab06) has admin privileges. The signing keys, residing on build infrastructure, are accessible to these individuals.

---

## 3. Multi-Party Signing Assessment

### 3.1 Finding: No Multi-Party Signing Exists

There is **zero evidence** of:
- Threshold signing (m-of-n key schemes)
- Multi-party key ceremony
- Split knowledge controls
- Dual control requirements
- Key custodian rotation
- Signing quorum requirements

### 3.2 Single-Point-of-Authority

The signing architecture is a **single-party, single-key** model:
- One set of keys exists
- Stored in one private repository
- Accessible to a very small number of people (2 per Tailscale policy)
- No approval workflow for signing operations
- No separation of key custody from signing authority

---

## 4. Signing Pipeline Map

### 4.1 Complete Pipeline (Visible + Opaque Sections)

```
[VISIBLE: build-config/android/build.sh]
    |
    v
1. BUILD PHASE (Buildkite CI)
   - repo sync from GitHub
   - breakfast ${DEVICE} ${TYPE}
   - mka otatools-package target-files-package dist
   |
   v
   Output: *target_files*.zip (UNSIGNED)
           otatools.zip
   |
   v
2. UPLOAD PHASE (build.sh lines 88-99)
   - ssh jenkins@blob.lineageos.org mkdir -p /home/jenkins/incoming/${DEVICE}/${BUILD_UUID}/
   - scp out/dist/*target_files*.zip jenkins@blob.lineageos.org:/home/jenkins/incoming/${DEVICE}/${BUILD_UUID}/
   - scp otatools.zip jenkins@blob.lineageos.org:/home/jenkins/incoming/${DEVICE}/${BUILD_UUID}/
   |
   v
=======================================================
   OPAQUE ZONE: What happens on blob.lineageos.org
   is NOT visible in any public repository
=======================================================
   |
   v
3. SIGNING PHASE (OPAQUE - inferred from wiki + AOSP tooling)
   Expected operations (based on wiki documentation):
   a. sign_target_files_apks \
        -o -d /path/to/keys \
        --extra_apks [74+ APEX mappings] \
        --extra_apex_payload_key [74+ payload key mappings] \
        target_files.zip \
        signed-target_files.zip

   b. ota_from_target_files \
        -k /path/to/keys/releasekey \
        --block --backup=true \
        signed-target_files.zip \
        signed-ota.zip
   |
   v
4. DISTRIBUTION PHASE
   - Signed OTA placed on mirrorbits.lineageos.org
   - download.lineageos.org serves via mirrorbits API
   - Updater app fetches from https://download.lineageos.org/api/v1/{device}/{type}/{incr}
```

### 4.2 Key Observations About the Pipeline

**The signing step is completely opaque.** The `build.sh` script in build-config shows that:

1. Build nodes produce **unsigned** `target-files-package` (line 86: `mka otatools-package target-files-package dist`)
2. Unsigned artifacts are SCP'd to `blob.lineageos.org` as `jenkins` user (lines 89-98)
3. The build script then runs cleanup (`rm -rf out*`, line 102)
4. **There is no signing command in the build script**

What happens between the unsigned upload to `blob.lineageos.org` and the signed output appearing on `download.lineageos.org/mirrorbits.lineageos.org` is entirely opaque. The signing process presumably runs on a different host or as a separate pipeline step that is not captured in any publicly available repository.

### 4.3 Infrastructure Endpoints

| Endpoint | Role | Access |
|----------|------|--------|
| `blob.lineageos.org` | Unsigned artifact staging | jenkins user via SSH (build nodes) |
| `mirrorbits.lineageos.org` | Signed build distribution | Public HTTP |
| `download.lineageos.org` | Updater API + web frontend | Public HTTP |
| Build nodes (Buildkite) | Compilation only | Tailscale VPN + SSH |

---

## 5. Key Rotation History and Policy

### 5.1 Key Generation Date

All release keys were generated on **January 7, 2017**, as evidenced by certificate validity dates:
```
Not Before: Jan  7 04:21:25 2017 GMT
Not After : May 25 04:21:25 2044 GMT
```

The certificates in migration.sh show timestamps of `170107042125Z` (2017-01-07) through `170107042128Z` for the release keys (platform, media, shared, releasekey -- all within a 3-second window).

### 5.2 Key Rotation: None Detected

**There is no evidence of any key rotation since initial generation in January 2017.** The same keys have been in continuous use for over 9 years. Evidence:

1. The `lineage.x509.pem` in the public vendor_lineage repo matches the release key in migration.sh
2. The `lineageos_pubkey` in the update_verifier repo matches the same key
3. No rotation policy is documented anywhere
4. No rotation tooling exists beyond the migration mechanism (which migrates users between key sets, not between old and new versions of the same key)
5. Certificate validity extends to 2044, indicating no planned rotation window

### 5.3 2020 Server Breach Implications

In May 2020, LineageOS servers were compromised via SaltStack vulnerabilities (CVE-2020-11651/CVE-2020-11652). LineageOS stated signing keys were "not affected" because they were stored on separate infrastructure. Notably, **no key rotation occurred after this breach** despite the potential that attackers may have had deeper access than detected.

### 5.4 Policy Assessment

| Policy Aspect | Status |
|---------------|--------|
| Key rotation schedule | None |
| Post-incident rotation | Not performed (2020 breach) |
| Key expiration | 2044 (27 years from generation) |
| Algorithm upgrade path | None defined (still SHA-1 for platform keys) |
| Key revocation capability | Not documented |

---

## 6. Key Migration Risk Assessment

### 6.1 Migration Mechanism

The migration script (`sources/scripts/key-migration/migration.sh`) enables users to transition between test-signed (unofficial) and release-signed (official) builds. It operates as follows:

1. **Runs on-device** as a shell script (`#!/system/bin/sh`)
2. Reads `/data/system/packages.xml`
3. Performs **string replacement** of certificate fingerprints and public keys
4. Replaces test key certs/keys with release key certs/keys (or vice versa)
5. Writes modified `packages.xml` back
6. Handles ABX (Android Binary XML) format for Android 12+

### 6.2 Public Key Exposure in Migration Script

**CRITICAL:** The migration script embeds the **complete DER-encoded release certificates** and **base64-encoded public keys** for all four core signing keys (media, platform, shared, release) directly in the shell script. This is the public portion only, but it provides:

- Full certificate fingerprints for all release keys
- Complete public key material
- Exact mapping between test and release key identities

### 6.3 Migration Security Risks

| Risk | Severity | Description |
|------|----------|-------------|
| **On-device XML manipulation** | HIGH | Direct modification of `packages.xml` bypasses PackageManager's integrity checks. If the script is interrupted mid-operation, the package database could be corrupted. |
| **No signature verification** | HIGH | The migration script performs blind string replacement without verifying that the source certificates are actually the expected ones. A malicious modification to the script could redirect trust to attacker-controlled keys. |
| **Backup overwrite risk** | MEDIUM | If `packages-backup.xml` exists, it overwrites the main file (lines 60-63), which could be exploited to inject a pre-crafted package database. |
| **Permission preservation** | MEDIUM | Script sets `chmod 660` and `chown system:system` but relies on correct SELinux labeling via `restorecon`. |
| **Bidirectional migration** | LOW | The script supports migration in both directions (official-to-unofficial and unofficial-to-official), meaning it can also be used to REMOVE official key trust. |

### 6.4 Export Keys Script

The `export-keys.sh` script (`sources/scripts/key-migration/export-keys.sh`) extracts public key material and DER-encoded certificates from `.x509.pem` files for embedding in the migration script. It outputs raw public keys and certificate hex for platform, media, shared, and releasekey.

---

## 7. Public Key Distribution / Trust Chain

### 7.1 Complete Trust Chain: Key Material to User Device

```
SIGNING KEYS (vendor/lineage-priv/keys/)
    |
    |--- [at build time, keys.mk loaded by build system]
    |
    v
sign_target_files_apks
    |
    |--- Signs all APKs with appropriate key (platform/media/shared/releasekey)
    |--- Signs all APEX containers with 4096-bit override keys
    |--- Signs APEX payloads with corresponding payload keys
    |
    v
ota_from_target_files -k releasekey
    |
    |--- Produces whole-file signature on OTA ZIP
    |--- Embeds signature in ZIP comment area (Android OTA signature format)
    |
    v
SIGNED OTA ZIP (on download.lineageos.org)
    |
    |--- Contains signed system image with signed APKs/APEXes
    |--- Contains META-INF/com/android/otacert (signing certificate)
    |--- Contains whole-file RSA signature
    |
    v
[DELIVERY TO DEVICE via Updater app or manual download]
    |
    v
VERIFICATION LAYER 1: Updater App (UpdaterController.java line 278)
    |--- Calls android.os.RecoverySystem.verifyPackage(file, null, null)
    |--- RecoverySystem.verifyPackage() reads /system/etc/security/otacerts.zip
    |--- otacerts.zip contains certificates trusted for OTA verification
    |--- Verifies the whole-file signature matches a cert in otacerts.zip
    |
    v
VERIFICATION LAYER 2: Recovery System (at install time)
    |--- Recovery reads otacerts from recovery ramdisk
    |--- Re-verifies whole-file signature before applying update
    |--- otacerts in recovery contains certs from:
    |      * PRODUCT_DEFAULT_DEV_CERTIFICATE (releasekey from vendor/lineage-priv/keys/)
    |      * PRODUCT_EXTRA_RECOVERY_KEYS (lineage.x509.pem from vendor/lineage/build/)
    |
    v
VERIFICATION LAYER 3: External verification (optional)
    |--- update_verifier.py + lineageos_pubkey
    |--- Reads ZIP signature, verifies against hardcoded public key
    |--- RSA-PKCS#1 v1.5 verification via oscrypto
    |
    v
POST-INSTALL: Package Manager
    |--- Reads APK signatures during boot
    |--- Verifies against stored certificates in packages.xml
    |--- APEX verification via apexd
```

### 7.2 otacerts.zip Construction

The `otacerts.zip` file, which is the on-device trust anchor, is constructed during the build from:

1. **`PRODUCT_DEFAULT_DEV_CERTIFICATE`** -- set to `vendor/lineage-priv/keys/testkey` (which in the template symlinks to the actual release key). This is the PRIMARY OTA verification certificate.

2. **`PRODUCT_EXTRA_RECOVERY_KEYS`** -- adds `vendor/lineage/build/target/product/security/lineage` (the public `lineage.x509.pem`). This is a SECONDARY recovery key.

The `lineage.x509.pem` public key is committed to the public `android_vendor_lineage` repository and contains the **same key** as the releasekey. This means:
- The public certificate for OTA verification is distributed via the open-source vendor repo
- The private key is in the private `vendor/lineage-priv` repository
- The `PRODUCT_EXTRA_RECOVERY_KEYS` mechanism provides a way to add recovery-only trust anchors separate from the default dev cert

### 7.3 Updater App Verification Code

The Updater app (`sources/android_packages_apps_Updater/`) uses `RecoverySystem.verifyPackage()` at three points:

1. **UpdaterController.java:278** -- After download completes, before marking as VERIFIED
2. **UpdateImporter.java:165** -- When importing a local update ZIP
3. **UpdateInstaller.java:104** -- `RecoverySystem.installPackage()` (which internally verifies before installing)

All three calls pass `null` for both the progress listener and the certificate file, meaning they rely on the **system default `otacerts.zip`** for trust validation.

### 7.4 Download Transport Security

Updates are fetched from `https://download.lineageos.org/api/v1/{device}/{type}/{incr}` over HTTPS. The actual file download goes through `https://mirrorbits.lineageos.org` which provides geographic mirror selection. The integrity chain relies on:
- HTTPS/TLS for transport security
- OTA signature for content authenticity
- SHA-256 checksums for integrity (bacon.mk generates `.sha256sum` files)

---

## 8. Insider Threat Vulnerability Assessment

### 8.1 Critical Vulnerabilities

#### V1: Single Point of Compromise -- Unencrypted Keys on Filesystem
**Severity: CRITICAL**

The signing keys have no passphrase protection (explicitly stripped by `make_key.sh`), are stored as plain files in a Git repository, and are accessible to anyone with access to `vendor/lineage-priv` or the build/signing infrastructure. A single compromised account with access to the key repository or the signing server grants full ability to produce authentically-signed malicious builds.

#### V2: Opaque Signing Process with No Audit Trail
**Severity: CRITICAL**

The signing step between unsigned target-files upload to `blob.lineageos.org` and signed output on `download.lineageos.org` is entirely opaque. There is no visible:
- Logging of what was signed and when
- Approval workflow before signing
- Audit trail of signing operations
- Reproducibility check between unsigned input and signed output
- Comparison/diff of signed vs unsigned content

An insider on the signing server could substitute a modified target-files package before signing, or sign arbitrary packages, with no detection mechanism.

#### V3: No Multi-Party Control
**Severity: HIGH**

There is no threshold signing, no dual-control, no key ceremony, and no separation of duties. The same individual who has the signing keys can also modify the build pipeline, the source code, and the distribution infrastructure. The Tailscale policy shows only 2 people have infrastructure access, with 1 having admin rights.

#### V4: Weak Cryptographic Algorithms
**Severity: HIGH**

The core platform keys use **RSA-2048 with SHA-1 signatures**. SHA-1 has been considered cryptographically broken for collision resistance since 2017 (SHAttered attack). While preimage resistance remains, the use of SHA-1 in a signing context is considered deprecated and does not meet modern security standards. NIST deprecated SHA-1 for digital signatures in 2011.

APEX keys use RSA-4096 with SHA-256, which is appropriate. But the most critical keys (releasekey, platform) remain at RSA-2048/SHA-1.

#### V5: No Key Rotation in 9+ Years
**Severity: HIGH**

The keys generated on 2017-01-07 have never been rotated. No rotation policy exists. No rotation occurred even after the 2020 server compromise. This means:
- Long exposure window for any key compromise
- No mechanism to recover from a compromised key
- A compromised key would allow signing of updates for any past, present, or future device
- The migration mechanism (migration.sh) is designed for user key transitions, NOT for project-level key rotation

#### V6: Key Material in Version Control History
**Severity: MEDIUM**

Private keys in a Git repository means all historical versions are preserved. Even if keys were to be rotated, the old keys would persist in Git history unless the repository is recreated (force-pushed with history rewrite). Anyone who ever cloned the private repo retains all key material.

### 8.2 Insider Attack Scenarios

#### Scenario A: Malicious Build Injection
An insider with access to `blob.lineageos.org` or the signing server could:
1. Intercept an unsigned target-files package after upload
2. Modify it to include a backdoor (additional APK, modified system app, etc.)
3. Sign it with the legitimate keys
4. Place it on the distribution network

**Detection likelihood: VERY LOW** -- No reproducible build verification, no hash comparison between build output and signed output.

#### Scenario B: Silent Key Exfiltration
An insider could copy the unencrypted `.pk8` key files and use them indefinitely to:
1. Sign custom builds that appear official
2. Create targeted malicious OTA updates for specific devices
3. Potentially bypass the OTA delivery system entirely (sideload-capable signed updates)

**Detection likelihood: NEAR ZERO** -- No key usage logging, no hardware-bound keys, no key access monitoring.

#### Scenario C: Supply Chain Modification
An insider with both build system access and signing access could:
1. Modify the build configuration to include malicious dependencies
2. Ensure the modification is only present in the build artifacts (not in public source)
3. Sign the modified build normally
4. The opaque nature of the signing pipeline prevents external verification

### 8.3 Summary Risk Matrix

| Risk Area | Insider Threat Level | Mitigation Status |
|-----------|---------------------|-------------------|
| Key storage security | CRITICAL | Unmitigated -- no encryption, no HSM |
| Signing authorization | CRITICAL | Unmitigated -- no multi-party control |
| Audit trail | CRITICAL | Unmitigated -- opaque signing process |
| Key longevity | HIGH | Unmitigated -- no rotation in 9 years |
| Algorithm strength | HIGH | Partially mitigated -- APEX uses RSA-4096/SHA-256, but core keys use RSA-2048/SHA-1 |
| Post-compromise recovery | HIGH | Unmitigated -- no rotation mechanism, no revocation capability |
| Build integrity | MEDIUM | Partially mitigated -- check_keys.py verifies APK/APEX signatures post-build |
| Transport security | LOW | Mitigated -- HTTPS + OTA signatures + SHA-256 checksums |

---

## Appendix A: Key Source Files Referenced

| File | Path |
|------|------|
| Key override mappings | `sources/scripts/lineage-priv-template/keys.mk` |
| Key generation script | `sources/scripts/lineage-priv-template/keys.sh` |
| make_key wrapper (STRIPS PASSWORDS) | `sources/scripts/lineage-priv-template/make_key.sh` |
| Post-build key checker | `sources/scripts/lineage-priv-template/check_keys.py` |
| Key migration script (on-device) | `sources/scripts/key-migration/migration.sh` |
| Key export for migration | `sources/scripts/key-migration/export-keys.sh` |
| Recovery key inclusion | `sources/android_vendor_lineage/config/common.mk` (line 286-287) |
| Public lineage certificate | `sources/android_vendor_lineage/build/target/product/security/lineage.x509.pem` |
| Build pipeline (unsigned) | `sources/build-config/android/build.sh` |
| Tailscale access policy | `sources/tailscale-config/policy.hujson` |
| Updater verification code | `sources/android_packages_apps_Updater/app/src/main/java/org/lineageos/updater/controller/UpdaterController.java` |
| Update import verification | `sources/android_packages_apps_Updater/app/src/main/java/org/lineageos/updater/UpdateImporter.java` |
| Version/build type config | `sources/android_vendor_lineage/config/version.mk` |

## Appendix B: External Sources Referenced

- LineageOS Signing Builds Wiki: https://wiki.lineageos.org/signing_builds
- LineageOS Verifying Builds Wiki: https://wiki.lineageos.org/verifying-builds
- LineageOS update_verifier: https://github.com/LineageOS/update_verifier
- LineageOS public key: https://github.com/LineageOS/update_verifier/blob/master/lineageos_pubkey
- 2020 SaltStack breach reports: https://thehackernews.com/2020/05/saltstack-rce-exploit.html
- LineageOS Infrastructure GitHub: https://github.com/lineageos-infra
