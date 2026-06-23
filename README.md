# VCF Content Factory vCommunity OS

A **Tier 2 Java SDK management-pack adapter** for VCF Operations — the
**Windows guest-OS fork** of the unified vCommunity adapter (native Java SDK
rewrite of [`vmbro/VCF-Operations-vCommunity`](https://github.com/vmbro/VCF-Operations-vCommunity),
Onur Yuzseven, CC-licensed). One of three paks the unified `vcfcf_vcommunity`
adapter was split into per
[`vcommunity-three-adapter-split.md`](../../../designs/managementpacks/vcommunity-three-adapter-split.md);
this pak (`vcfcf_vcommunity_os`) owns the **in-guest collection surface only**.

> ## KNOWN-OPEN BLOCKER — guest-ops collection is shelved
>
> In-guest collection (Windows services, in-guest CSV OS-info, event logs)
> returns **zero rows** on hardened Server 2025 DCs, on both this Java port and
> Onur's prod Python. The leading (unconfirmed) theory is that non-interactive,
> VMware-Tools-launched PowerShell is blocked by machine policy
> (ExecutionPolicy `Restricted`/`AllSigned` or ConstrainedLanguage / AppLocker /
> WDAC). The vim25 transport, SolutionConfig gate, service names, CSV format,
> and credential identity/privilege have all been **eliminated** as causes.
>
> **This pak is built structurally — guest-ops is NOT debugged here.** It was
> forked first specifically to capture the guest-ops code before it is stripped
> from `vcommunity-vsphere`. When un-shelved, the next step is to run
> `Get-ExecutionPolicy -List` + `$ExecutionContext.SessionState.LanguageMode` on
> a DC and (if confirmed) add `-ExecutionPolicy Bypass -NonInteractive` to
> `GuestOpsClient.runPowershell`, plus surface the swallowed `StartProgram`
> fault. Full diagnosis:
> `context/investigations/vcommunity-windows-services-empty-2026-06-23.md` and
> `context/investigations/vcommunity-guestops-execution-divergence-2026-06-22.md`.

## What it does

Opens its **own** vim25 vCenter SOAP session (deliberate duplication — design
§2: guest-ops rides vCenter's GuestOperationsManager, so the OS pak still needs
a vCenter session) and pushes the `vCommunity|Guest OS|` property namespace onto
**existing** VMWARE `VirtualMachine` resources (ARIA_OPS-style stitching — no
new object types):

- **VirtualMachine** — opt-in Windows guest-ops via the vim25
  GuestOperationsManager: Windows **services**, in-guest **OS info** (CSV path
  via `getWindowsOSInformation.ps1`), and Windows **event logs**.

The vSphere-side surface (clusters, hosts, VM config/SCSI/snapshots, and the
passive VMware-Tools `Guest OS|Operating System|*` path) belongs to the
**`vcommunity-vsphere`** pak and is **not** collected here.

A single synthetic `vCommunityWorld` resource carries per-cycle operability
metrics (VMs stitched, guest-ops attempts/degradations, config-file status, and
the build-9/10 guest-ops diagnostics that name *why* in-guest collection is
empty).

See [`REFERENCE.md`](REFERENCE.md) for the key catalog.

## Stitch identity (multi-vCenter safety — retained verbatim)

The build-2 `VMEntityVCID` MOID-scoping fix is **kept intact** in this fork
(`VCommunityStitcher.setOwningVcUuid` → `VMEntityVCID`-scoped VM load). A bare
MOID is not unique across vCenters; pinning the owning vCenter Instance UUID
from the live SOAP session each cycle is what keeps two adapters (this one and
`vcommunity-vsphere`) resolving the *same* MOID to the *same* VCF Ops resource.
See `lessons/stitch-moid-not-unique-across-vcenters.md`. Do not drop the scoping.

## Relationship to the original (fresh fork, fresh kind)

This is a **distinct adapter kind** (`vcfcf_vcommunity_os`), a fresh lineage —
not an in-place upgrade of the unified `vcfcf_vcommunity` pak or the original
`VCFOperationsvCommunity`. The unified kind is retired by this split.

### Migration runbook

1. **Uninstall the unified** `vcfcf_vcommunity` pak (and/or the original
   containerized `iSDK_VCFOperationsvCommunity`). Instances and credentials
   cascade away on uninstall.
2. **Install `vcommunity-vsphere`** (for the vSphere surface) and **this pak**
   (`vcfcf_vcommunity_os`) if Windows guest monitoring is wanted.
3. **Recreate adapter instances and credentials** against the new kind — there
   is no instance/credential carry-over across a kind change.

Because this adapter writes the *same* `vCommunity|Guest OS|` keys onto the
*same* VMware-owned VM resource UUIDs, historical series remain mechanically
continuous through the migration — a happy side effect of key-namespace
continuity, **not** a supported upgrade guarantee.

## Configuration

### Credentials (one combined kind)

A single credential kind (`vsphere_user`, "vCenter Credential") with four fields,
matching the prod original — an Ops adapter instance binds exactly one
credential, and guest-ops runs *through* the vCenter session, so both creds ride
one bound credential:

- **vCenter** (required) — `user` / `password`, used for this pak's own vim25
  session and GuestOperationsManager access.
- **Windows guest** — `winUser` / `winPass`, used for in-guest authentication.
  Leave them unset to disable guest-ops cleanly.

### Windows Monitoring

Two independent adapter-instance toggles, each `Enabled` / `Disabled` (default
`Disabled`), matching the original's two Advanced-Settings enums:

- **Guest OS Service Monitoring Status** (`serviceMonitoring`) — gates services
  **and** in-guest CSV OS-info (they run together under the same gate in the
  original).
- **Windows Event Log Monitoring Status** (`winEventMonitoring`).

Guest-ops runs only when at least one toggle is `Enabled` AND the Windows guest
credential fields are set; otherwise it is skipped (non-fatal). Only the literal
`Enabled` turns a gate on. One unreachable or mis-credentialed guest never aborts
the collection cycle.

### Central check-list files (two — Windows only)

Collection of services / event IDs is gated by **two** XML check-lists in the
VCF Ops **central configuration-file store** (`Administration → Configuration
Files`, path `SolutionConfig/`): `windows_service_list.xml` and
`windows_event_list.xml`. The four vSphere check-lists belong to the
`vcommunity-vsphere` pak. The pak ships byte-identical defaults under
`content/files/solutionconfig/`; they import into the central store at install
with **everything commented out**, so each gated collector emits nothing until an
admin uncomments entries. The two adapter-instance `win_*_config_file` fields
hold the file NAME (no path, no `.xml`).

The adapter fetches the named files via the SDK-injected Suite API channel each
cycle and caches the last-good parse — a transient fetch failure degrades to the
previous cycle's lists (never silently to empty), and `test()` plus the
`vCommunityWorld` `config_file_status` property report per-file status.

## Events (TOOLSET GAP #1)

The original emits Windows event-log entries as foreign-resource **events**. The
factory Suite API facade exposes only property/stat push (no foreign-resource
event endpoint), so this release degrades them to **alertable properties**
(`vCommunity|Guest OS|Last Event|…`) — visible and symptom-able, never silently
dropped. Real foreign-resource events are a v1.1 deliverable once the push path
is proven.

## Known gaps & roadmap (v1)

This is a v1 release shipped with documented gaps that close in later builds —
nothing below is a silent degradation; each is visible in the artifact and
alertable or surfaced where it matters.

### Carried into v1.1

- **Foreign-resource event push (TOOLSET GAP #1).** Windows event-log entries
  ship as alertable **properties** (`vCommunity|Guest OS|Last Event|…`) rather
  than real foreign-resource events, because the factory Suite API facade
  exposes only property/stat push (no event endpoint). Visible and symptom-able,
  never dropped. Real events land in v1.1 once the push path is proven. (See the
  Events section above.)
- **Positional `Last Event` keys may churn (NIT 1).** Event properties are keyed
  by position (`vCommunity|Guest OS|Last Event|{n}|…`), so as new events arrive
  the same `{n}` slot can describe a different event cycle-to-cycle. v1.1 moves
  to stable event-id keys (folds in with the real-event work).

### Deferred to v2

- **Guest-ops scope and concurrency.** Windows guest-ops is single-threaded with
  a **120 s per-VM poll ceiling**, and when enabled it runs against **all
  Windows VMs in scope** (no per-VM opt-in). Per-VM scoping is a v2 deliverable.
  One unreachable or mis-credentialed guest never aborts the cycle.

### EMPIRICAL-VERIFY at install

These behaviours are designed and code-complete but have **not** been verified
against a live appliance — confirm them during the first install:

- The credential dialog accepts an instance with the Windows Guest credential
  fields left unset (guest-ops cleanly disabled).
- The vim25 GuestOperationsManager surface resolves on the target vCenter(s),
  and (the SHELVED blocker above) in-guest PowerShell actually executes in the
  non-interactive, Tools-launched context.
- Suite API config-file fetch (`SolutionConfig/<name>.xml`) succeeds when the
  adapter runs on a **remote collector** / cloud proxy, not just the analytics
  node.

## Local dev build (preview)

The official `.pak` is built by CI on a tag. For a local preview the Broadcom SDK
jar (`vrops-adapters-sdk-2.2.jar`) is **not** shipped — supply it from your
appliance:

```sh
# Cheap loop first — exhaust this before building a pak:
python3 -m vcfops_managementpacks validate-sdk content/sdk-adapters/vcommunity-os

# scp root@<appliance>:/usr/lib/vmware-vcops/common-lib/vrops-adapters-sdk-2.2.jar .
export VCFCF_SDK_JAR=/path/to/vrops-adapters-sdk-2.2.jar
python3 -m vcfops_managementpacks build-sdk content/sdk-adapters/vcommunity-os -o dist
```

`vcfcf-adapter-base.jar` is provided by the builder; you do **not** commit it.

## CI release contract

The shippable `.pak` is built by CI, never on a laptop: commit + push to `main`,
then push a `vX.Y.Z` tag. The `build-pak-on-tag` workflow pulls the published
`sdk-buildkit`, fetches the private Broadcom SDK jar (`SDK_RUNTIME_TOKEN`
secret), builds deterministically, gates on `pak-compare`, and attaches the
`.pak` to the tag's GitHub Release. That Release asset **is** the release.

## C2 pak shape — no bundled jars

This pak never carries `vrops-adapters-sdk` or any Broadcom jar.
`vcfcf-adapter-base.jar` comes from the buildkit at build time;
`vrops-adapters-sdk-*.jar` is on the appliance classpath at runtime and supplied
to the compiler by the consumer. `.gitignore` ignores `lib/*.jar`.

## Building from source

You don't need this repo's CI or the VCF Content Factory checkout to
build the `.pak` — the toolchain is a portable tarball. You need:

- **JDK 11+** (`javac` + `jar` on PATH)
- **python3** with `pyyaml` (`python3 -m pip install pyyaml`)
- **The GitHub CLI** (`gh`) — used to download the build toolchain
  below. The factory repo is public, so no `gh auth login` is needed
  for the download (authenticate only if you hit anonymous API rate
  limits). No `gh`? See the `curl` alternative under step 1.
- **The Broadcom adapter SDK jar** (`vrops-adapters-sdk-2.2.jar`).
  This is a Broadcom build artifact with no public redistribution
  channel — it is **never** bundled in the toolchain or this repo.
  Get it from your own VCF Operations appliance:

  ```
  scp root@<appliance>:/usr/lib/vmware-vcops/common-lib/vrops-adapters-sdk-2.2.jar .
  ```

  (Also present at
  `/usr/lib/vmware-vcops/suite-api/WEB-INF/lib/vrops-adapters-sdk.jar`.
  Partners can pull it from the Broadcom TAP / partner SDK portal
  instead.)

Then, from the root of this repo:

```bash
# 1. Fetch the build toolchain (pin a full sdk-buildkit-vX.Y.Z tag for
#    reproducibility, or use the floating major sdk-buildkit-v1)
gh release download sdk-buildkit-v1 \
  --repo sentania-labs/vcf-content-factory \
  --pattern 'sdk-buildkit-*.tgz'
# No gh? The asset is public — fetch it with curl instead:
#   curl -sL https://github.com/sentania-labs/vcf-content-factory/releases/download/sdk-buildkit-v1/sdk-buildkit-v1.tgz -o sdk-buildkit-v1.tgz
tar xzf sdk-buildkit-*.tgz

# 2. Point the kit at your SDK jar and build
export VCFCF_SDK_JAR=/path/to/vrops-adapters-sdk-2.2.jar
python3 -m sdk_buildkit validate-sdk .   # cheap loop: compile-check
python3 -m sdk_buildkit build-sdk .      # emits the .pak
```

The kit carries everything else it needs (including the
`vcfcf-adapter-base.jar` framework runtime that ends up in the pak's
`lib/`). `validate-sdk` is the fast iteration loop; exhaust it before
building paks.

**Dev builds vs releases.** Anything you build this way is a *dev
build*. The **official** artifact for this repo is the one its own CI
builds and attaches to a GitHub Release when a `v*` tag is pushed —
deterministic, no developer machine in the path.

**If you fork this repo**, the CI workflow
(`.github/workflows/build-pak-on-tag.yml`) needs two adjustments
before your own `v*` tags will build:

1. **Runner**: it targets a `self-hosted` runner pool — switch
   `runs-on` to `ubuntu-latest` (the workflow comments call this out).
2. **SDK jar sourcing**: the upstream workflow fetches the Broadcom
   jar from a private repo via an `SDK_RUNTIME_SSH_KEY` deploy-key
   secret you won't have. Replace that step with your own source —
   e.g. store the appliance-extracted jar in your own private repo or
   an Actions secret/artifact store. Then **also update the
   `--sdk-jar` argument** on the `build-sdk` line of the workflow to
   point at wherever your replacement step puts the jar. The explicit
   `--sdk-jar` flag overrides `VCFCF_SDK_JAR`, so setting the env var
   alone is not enough — if you leave `--sdk-jar _sdk_runtime/...` in
   place the build will look for the upstream path and fail. Do **not**
   commit the jar to a public repo (no redistribution).

## Attribution

Native Java SDK rewrite of `vmbro/VCF-Operations-vCommunity` by Onur Yuzseven
(CC-licensed). This OS fork carries the guest-ops collectors
(`getWindowsServices.ps1`, `getWindowsOSInformation.ps1`,
`getWindowsEventLogs.ps1`) and the in-guest reading paths.
