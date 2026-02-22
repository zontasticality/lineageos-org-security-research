# Phase 1: LineageOS Governance & Legal Structure Analysis

## Insider Threat Security Research -- Governance Layer

**Date:** 2026-02-22
**Scope:** Governance hierarchy, legal ownership, director capture resistance, infrastructure manager unilateral powers

---

## 1. Organizational Hierarchy

### 1.1 Full Governance Chart

```
LineageOS LLC Owners (unknown number; at least 1 is Tom Powell / zifnab06)
  |
  |-- VETO POWER on all items of legal/financial consequence
  |-- SIGN-OFF required on all director removals
  |
  +-- Project Directors (9 seats -- "Head Developers" in GitHub/Gerrit)
  |     Decision thresholds:
  |       - Simple majority: 5/9
  |       - Device/software exceptions: 3/9
  |       - Supermajority (substantial change/controversy): 6/9
  |       - Director removal for cause: 6/9 + LLC owner sign-off
  |       - Director removal for inactivity: all 4 inactivity conditions + LLC owner sign-off
  |
  |     Current Directors (from auth/github/data.yml "Head Developers" team):
  |       1. bgcngm        (Bruno Martins)
  |       2. chirayudesai   (Chirayu Desai)      ** also Infrastructure Manager **
  |       3. haggertk       (Kevin Haggerty)
  |       4. luca020400     (Luca Stefani)
  |       5. luk1337        (Lukasz Patron)
  |       6. mikeNG         (Michael Bestas / mikeioannina)
  |       7. npjohnson      (Nolen Johnson)
  |       8. razorloves
  |       9. zifnab06       (Tom Powell)         ** also Infrastructure Manager + LLC Owner **
  |
  |     Retired Directors (per wiki): Abhisek Devkota (ciwrl), Rashed Abdel-Tawab,
  |                                    Sam Mortimer (sam3000), Simon Shields (fourkbomb)
  |
  +-- Developer Relations Managers (subset of directors + others)
  |     Members: ciwrl, fourkbomb, haggertk, luca020400, luk1337, mikeNG,
  |              Rashed97, razorloves, sam3000, zifnab06
  |     NOTE: Includes retired directors (ciwrl, fourkbomb, Rashed97, sam3000)
  |     Role: onboarding, submission review, contributor pathways, device access grants
  |
  +-- Infrastructure Managers (2 people)
  |     Members: Tom Powell (zifnab06) and Chirayu Desai (chirayudesai)
  |     Role: day-to-day infrastructure, signing processes, build servers,
  |           Tailscale network, Gerrit, GitHub org management
  |
  +-- Public Relations (7 people)
  |     Members: ciwrl, haggertk, harryyoud, javelinanddart, jrizzoli, npjohnson, zifnab06
  |
  +-- Committers (6 people per wiki)
  |     Have merge authority (Code-Review +2, submit) on Gerrit
  |     Members: Cosmin Tanislav, Danny Baumann, Jan Altensen, Joey Rizzoli,
  |              Michael W., Joseph Annareddy
  |
  +-- Reviewers (6 people per wiki)
  |     Constructive review authority but no merge
  |
  +-- Device Maintainers (~240 people in auth/github/data.yml "Maintainers" team)
  |     Per-device responsibility, must own the device
  |     Governed by Device Support Requirements charter document
  |
  +-- Translation Managers & Wiki Maintainers
        Documentation and localization
```

### 1.2 Key Decision Thresholds Summary

| Decision Type | Threshold | Additional Requirement |
|---|---|---|
| Routine governance | 5/9 directors | None |
| Device/software exception | 3/9 directors | None |
| Substantial change / controversy | 6/9 directors | Open contributor response period |
| Legal/financial items | Directors vote | **LLC owner veto** |
| Director removal (cause) | 6/9 directors | LLC owner sign-off + CoC violation + prior warning |
| Director removal (inactivity) | N/A (procedural) | All 4 inactivity criteria + 3 contact attempts + LLC owner sign-off |
| Charter changes | 3 directors approve on Gerrit | Per charter README |
| Org membership changes | Pull request to auth repo | Automated hourly via GitHub Actions |

---

## 2. Legal Ownership Chain Analysis

### 2.1 The Entity: LineageOS LLC

- **Type:** Limited Liability Company (NOT a 501(c)(3) non-profit)
- **Trademark:** Registration No. 6197805, Serial No. 87714781, filed 2017-12-10
- **Registered Address:** 718 26th Ave S Apt 3, Seattle, Washington 98144, USA
- **Contact:** legal@lineageos.org, infra@lineageos.org
- **Copyright:** "(C) 2016 - 2026 The LineageOS Project"

### 2.2 LLC Ownership (What Can Be Determined)

**Critical finding:** The identity of all LLC owners/members is not publicly documented in any governance charter, wiki page, or public filing readily accessible online.

**Evidence for Tom Powell (zifnab06) as LLC owner/member:**
- The LLC's registered address (718 26th Ave S Apt 3, Seattle, WA) matches Tom Powell's location (Seattle, WA)
- He is listed in the `group:admin` in Tailscale config -- the sole member of the admin supergroup
- He is identified as "cofounder" of LineageOS in web profiles
- He appears in every privileged group: Head Developers, Developer Relations, Infrastructure Managers, Public Relations, and Tailscale admin

**Other potential LLC owners:**
- The charter uses the plural "LLC owners" (Rule 2), suggesting more than one owner
- Sam Mortimer (sam3000) is a retired director also based in Seattle and still listed in Developer Relations -- could be an LLC member
- Abhisek Devkota (ciwrl) was the original co-founder and is still listed in Developer Relations despite being retired -- could be an LLC member
- The LLC operating agreement (not public) would definitively answer this

### 2.3 Legal Powers Conferred by LLC Ownership

Per the Directors Working Agreement, LLC owners hold:

1. **Veto power over all legal/financial decisions** (Rule 2): "For items of legal consequence, that is direct or indirect legal and/or financial exposure to the project, veto power is reserved for LineageOS LLC owners."
   - This is an absolute veto -- no threshold of director votes can override it
   - "Legal consequence" is broadly defined as "direct or indirect legal and/or financial exposure"

2. **Sign-off authority on director removals** (Rules 7 & 8): "At least one LineageOS LLC owner signs off on result of the vote" / "At least one LineageOS LLC owner signs off on the removal"
   - No director can be removed without LLC owner consent
   - This makes LLC owners the ultimate gatekeepers of board composition

3. **Implicit trademark control:** As the LLC owns the LineageOS trademark, LLC members control the legal right to use the name, logo, and brand -- a powerful lever over the entire ecosystem

4. **Implicit infrastructure control:** The LLC likely holds contracts for domains (lineageos.org), hosting, and cloud services. LLC members can terminate or transfer these unilaterally under applicable law.

---

## 3. Director Capture Resistance Assessment

### 3.1 Director Selection Process

**Current mechanism (Rule 6):**
- Directors may step down voluntarily at any time
- Replacement is voted on by existing directors
- Feedback and recommendations are solicited from the contributor pool (advisory only)
- Selection criteria: "meritocracy basis and ability to commit the time necessary"

**Capture resistance: WEAK**

| Attack Vector | Difficulty | Notes |
|---|---|---|
| Gradual capture via replacement appointments | MODERATE | Current directors select replacements; if 5 collude they control all future appointments |
| Waiting out inactive directors | LOW-MODERATE | 9-month inactivity threshold with 3 contact attempts, but LLC owner must sign off on removal |
| Social engineering new director appointments | MODERATE | No external oversight; contributor pool is advisory only |
| Capturing through LLC ownership | HIGH (external) / CRITICAL (if already LLC owner) | LLC owners have veto on removals, so capturing the LLC captures the director appointment pipeline |

### 3.2 Director Removal Resistance

**For-cause removal requires ALL of:**
1. Continued CoC/Working Agreement violation after warning
2. 6/9 director supermajority vote
3. LLC owner sign-off

**Inactivity removal requires ALL of:**
1. No commits for 9+ months
2. No infrastructure/process contributions for 9+ months
3. No chat participation for 9+ months
4. 3+ failed contact attempts
5. LLC owner sign-off

**Assessment:** The removal bar is extremely high, particularly because:
- A hostile director who maintains minimal activity (one chat message every 8 months) can never be removed for inactivity
- For-cause removal requires proving "continued violation" after a warning -- subjective and arguable
- In both cases, an LLC owner can unilaterally block removal by withholding sign-off
- There is NO mechanism to remove an LLC owner from the LLC itself through the charter process

### 3.3 The "Retired Director" Safety Net

Per Rule 8 NOTE, removed-for-inactivity directors retain:
- Global Code-Approval permissions via "Retired Directors" Gerrit group inheriting "Committers-Inactive"
- GitHub/GitLab permissions at Maintainer level
- Access to private directorial communication channels with input rights

**Risk:** Retired directors retain significant code approval power and informational access even after departure. A compromised retired director could still approve malicious code.

---

## 4. Infrastructure Manager Unilateral Power Enumeration

### 4.1 The Two Infrastructure Managers

| Handle | Real Name | Additional Roles | Tailscale Group |
|---|---|---|---|
| zifnab06 | Tom Powell | Director, DevRel, PR, **LLC Owner**, **Tailscale Admin (sole)** | group:admin + group:infra |
| chirayudesai | Chirayu Desai | Director | group:infra |

### 4.2 Tailscale Network Access (from policy.hujson)

```json
"groups": {
    "group:infra": ["zifnab06@github", "chirayudesai@github"],
    "group:admin": ["zifnab06@github"],       // <-- SOLE ADMIN
}
```

**Tag ownership (who can assign infrastructure tags):**
```json
"tagOwners": {
    "tag:infra": ["group:admin"],    // Only zifnab06
    "tag:build": ["group:admin"],    // Only zifnab06
}
```

**Access control rules:**
- `group:infra` (both) -> `tag:infra:*` (all ports on all infra servers)
- `tag:infra` -> `tag:infra:443` (inter-server HTTPS only)
- SSH access: `group:infra` -> `tag:infra` servers (both root and non-root)

**Critical asymmetry:** Only `zifnab06` is in `group:admin`, which means:
- Only Tom Powell can assign `tag:infra` and `tag:build` to new machines
- Only Tom Powell can onboard/offboard infrastructure nodes
- Chirayu Desai can ACCESS existing infra but cannot add new machines or change the network topology
- The Tailscale API key (`TS_API_KEY`) and tailnet identity (`TS_TAILNET`) are stored as GitHub Actions secrets -- controlled by whoever has admin access to the `lineageos-infra/tailscale-config` repo

### 4.3 GitHub Organization Control (from auth repo)

**The auth automation system:**
- Runs hourly via GitHub Actions cron (`0 * * * *`)
- Reads `data.yml` to determine who should be in the GitHub org and which teams
- Uses `X_GITHUB_TOKEN` (stored as GitHub Actions secret) to manage membership
- **Additions are automatic**: anyone added to `data.yml` gets invited
- **Removals are MANUAL**: the script only prints "needs to be removed" but does NOT auto-remove (line 22: `# NOTE: This is a manual process, DO NOT MAKE THIS AUTOMATIC`)

**Who can modify `data.yml`?**
- Anyone with merge access to the `lineageos-infra/auth` repo (likely the 2 infra managers + possibly directors)
- The GitHub Actions workflow runs on push to `main` branch

**Unilateral powers via auth repo:**
- Either infra manager could add arbitrary GitHub users to any team (Head Developers, Maintainers, etc.)
- Either could remove users from `data.yml` to trigger the manual removal notification
- Team membership controls Gerrit group membership indirectly

### 4.4 Enumerated Unilateral Powers per Infrastructure Manager

#### Tom Powell (zifnab06) -- can unilaterally:

| Power | Mechanism | Reversible By |
|---|---|---|
| Access all infrastructure servers (SSH root) | Tailscale group:infra | Changing Tailscale policy |
| Add/remove machines from infrastructure network | Tailscale group:admin (sole) | No one else can via Tailscale |
| Tag machines as build servers | Tailscale tag:build owner (sole) | No one else can via Tailscale |
| Modify Tailscale ACL policy in production | Push to main on tailscale-config repo | Reverting the push |
| Add/remove GitHub org members | Modify auth/github/data.yml | Reverting the change |
| Control GitHub Actions secrets (API keys) | Repo admin on lineageos-infra repos | Other repo admins |
| Veto any legal/financial decision | LLC owner veto power | Other LLC owners (if any) |
| Block any director removal | LLC owner sign-off withheld | Other LLC owners (if any) |
| Control the LineageOS trademark | LLC membership | Other LLC members |
| Control domain registration (lineageos.org) | Likely registered to LLC/personal account | Domain registrar |
| Control OTA signing keys | Infrastructure access + likely key custodian | Key rotation by other infra manager |
| Publish official builds | Build server access | Other infra manager |

#### Chirayu Desai (chirayudesai) -- can unilaterally:

| Power | Mechanism | Reversible By |
|---|---|---|
| Access all infrastructure servers (SSH root) | Tailscale group:infra | zifnab06 changing Tailscale policy |
| Add/remove GitHub org members | Modify auth/github/data.yml | Reverting the change |
| Access OTA signing keys (if on build servers) | SSH to tag:infra servers | Key rotation |
| Publish official builds (if on build servers) | SSH to tag:infra servers | Access revocation by zifnab06 |

**Critical asymmetry:** Chirayu Desai's infrastructure access can be revoked by Tom Powell (via Tailscale admin), but Tom Powell's access cannot be revoked by Chirayu Desai through any documented mechanism.

### 4.5 Build & Signing Infrastructure

- Infrastructure Managers are described as responsible for "managing internal signing processes" (per wiki contributors page)
- All official LineageOS builds are signed with private keys controlled by Infrastructure Managers
- The build-config repo (lineageos-infra/build-config) contains build automation
- The updater system (lineageos-infra/updater) distributes OTA updates
- The Tailscale `tag:build` tag (controlled solely by zifnab06) governs which machines are build servers

---

## 5. Key Findings and Vulnerability Assessment

### 5.1 Critical Findings

**FINDING 1: Single Point of Failure -- Tom Powell (zifnab06)**

Tom Powell simultaneously holds:
- LLC ownership (with legal veto power and trademark control)
- Director seat (1 of 9 votes on governance)
- Sole Tailscale admin (can add/remove all infrastructure nodes)
- Infrastructure Manager (SSH root to all servers)
- Developer Relations Manager
- Public Relations member

This concentration means a single compromised account or a single coerced individual could:
- Silently add a malicious build server to the network
- Modify the OTA signing pipeline
- Lock out the other infrastructure manager
- Veto any governance response to the attack
- Block the removal of compromised directors

**FINDING 2: LLC Ownership is Opaque and Unchecked**

- The LLC operating agreement is not public
- The number and identity of LLC owners is not formally disclosed
- LLC owners have absolute veto on legal/financial matters and director removals
- There is NO charter mechanism to remove or override an LLC owner
- The charter does not define what happens if LLC owners disagree with each other
- The charter does not define what happens if all LLC owners become hostile or incapacitated

**FINDING 3: Director Self-Perpetuation with No External Oversight**

- Directors choose their own replacements with only advisory contributor input
- No term limits
- No external board, advisory council, or community election mechanism
- The inactivity threshold (9 months) is long enough for significant damage before removal begins
- A coalition of 5 directors can control all future appointments indefinitely

**FINDING 4: Retired Directors Retain Code Approval Permissions**

- Retired directors keep global Code-Approval power through "Retired Directors" -> "Committers-Inactive" Gerrit group inheritance
- They retain access to private directorial communication channels
- There is no periodic review or re-certification of these retained privileges
- A compromised retired director (Devkota, Rashed, Mortimer, Shields) could approve malicious code merges

**FINDING 5: Infrastructure Access Cannot Be Revoked Symmetrically**

- Tom Powell can revoke Chirayu Desai's access unilaterally (Tailscale admin)
- Chirayu Desai cannot revoke Tom Powell's access through any documented mechanism
- There is no "break glass" procedure for infrastructure lockout scenarios
- There is no documented key rotation or access review process

**FINDING 6: Auth Automation Has Asymmetric Safety Controls**

- Adding members is fully automated (potential for rapid privilege escalation)
- Removing members is deliberately manual (slower response to compromise)
- The `X_GITHUB_TOKEN` secret that controls org membership is a single credential with org-wide power
- No approval workflow for auth changes -- a direct push to main triggers immediate sync

### 5.2 Adversarial Scenarios

**Scenario A: Malicious LLC Owner**
An LLC owner who turns hostile can:
1. Veto all legal/financial responses to the attack
2. Block removal of compromised directors
3. Transfer the trademark to another entity
4. Redirect the domain to a malicious distribution server
5. Use infrastructure admin access to inject malicious builds

Recovery path: Other LLC members (if any exist) would need to pursue legal action. The open-source community could fork but would lose the brand and infrastructure.

**Scenario B: Compromised Infrastructure Manager Account**
An attacker who gains access to zifnab06's credentials can:
1. SSH as root to all infrastructure servers
2. Add rogue machines to the Tailscale network
3. Modify build signing keys
4. Push malicious OTA updates to all devices
5. Modify GitHub org membership to grant broad access
6. Change Tailscale ACLs to lock out the other infra manager

Detection: Limited. The Tailscale gitops workflow creates an audit trail, but the GitHub Actions secrets and server-side access leave minimal logs visible to other team members.

**Scenario C: Slow Director Board Capture**
An adversary who controls 5 director seats can:
1. Approve any governance change via simple majority
2. Appoint allied replacements as directors depart
3. Modify the charter (only 3 director approvals needed)
4. Grant themselves infrastructure roles
5. Override device support requirements
6. Suppress security disclosures

The 9-month inactivity window means captured seats are hard to reclaim once established.

### 5.3 Mitigating Factors

1. **Open source transparency:** All code changes go through public Gerrit review; malicious commits are theoretically visible to the community
2. **Build verification:** Users can verify build signatures via the OTA verifier tool
3. **Distributed maintainers:** ~240 device maintainers provide broad community awareness
4. **Charter codification:** The governance rules are publicly documented and versioned in git, making covert charter changes difficult
5. **Manual removal safety:** The deliberate manual-only org removal in the auth script prevents automated mass lockout
6. **Community fork option:** As an open-source project, the code can be forked if governance is captured, though the brand/infrastructure would be lost

---

## 6. Sources

### Primary Sources (Local Repositories)
- `sources/charter/directors-working-agreement.md`
- `sources/charter/README.md`
- `sources/charter/code-of-conduct.md`
- `sources/charter/device-support-requirements.md`
- `sources/tailscale-config/policy.hujson`
- `sources/tailscale-config/.github/workflows/tailscale.yml`
- `sources/auth/github/data.yml`
- `sources/auth/github/main.py`
- `sources/auth/.github/workflows/github_auth.yaml`

### Web Sources
- [LineageOS Contributors Wiki](https://wiki.lineageos.org/contributors)
- [LineageOS Charter on GitHub](https://github.com/LineageOS/charter)
- [LineageOS LLC Trademark - Justia](https://trademarks.justia.com/877/14/lineageos-87714781.html)
- [LineageOS LLC Trademarks - Justia Owner Page](https://trademarks.justia.com/owners/lineageos-llc-3718780/)
- [LineageOS Legal Page](https://lineageos.org/legal/)
- [Tom Powell (zifnab06) GitHub Profile](https://github.com/zifnab06)
- [LineageOS Infrastructure GitHub Org](https://github.com/lineageos-infra)
- [LineageOS Gerrit Config Repo](https://github.com/lineageos-infra/gerrit-config)
- [LineageOS Verifying Builds Wiki](https://wiki.lineageos.org/verifying-builds)
- [LineageOS Wikipedia Article](https://en.wikipedia.org/wiki/LineageOS)
- [LineageOS LLC ZoomInfo Profile](https://www.zoominfo.com/c/lineageos-llc/399201960)
- [USPTO Report - LineageOS LLC](https://uspto.report/company/Lineageos-L-L-C)
