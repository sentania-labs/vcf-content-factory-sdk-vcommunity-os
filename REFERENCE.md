# VCF Content Factory vCommunity OS — Reference

Windows guest-OS fork of the unified vCommunity Java SDK adapter (native rewrite
of `vmbro/VCF-Operations-vCommunity`, Onur Yuzseven, CC-licensed). Adapter kind
`vcfcf_vcommunity_os`. One of three paks the unified `vcfcf_vcommunity` adapter
was split into per `designs/managementpacks/vcommunity-three-adapter-split.md`.

> **KNOWN-OPEN BLOCKER (shelved):** in-guest collection returns zero rows on
> hardened Server 2025 DCs — leading theory non-interactive PowerShell execution
> blocked. This pak is built structurally, not debugged. See README and
> `context/investigations/vcommunity-windows-services-empty-2026-06-23.md`.

## Adapter

| Field | Value |
|---|---|
| Adapter Kind | `vcfcf_vcommunity_os` |
| Tier | 2 (Java SDK) |
| Monitoring Interval | 5 minutes |
| License Required | No |

### Credentials (ONE combined credential kind)

**vCenter Credential** (`vsphere_user`, required) — mirrors the prod original's
single `vsphere_user` credential type. An Ops adapter instance binds exactly ONE
credential; guest-ops runs THROUGH the vCenter session, so the vCenter and
Windows guest credentials live in the SAME kind.

| Field | Key | Type | Required |
|---|---|---|---|
| vCenter User Name | `user` | string | Yes |
| vCenter Password | `password` | string (masked) | Yes |
| Windows User Name | `winUser` | string | No |
| Windows Password | `winPass` | string (masked) | No |

The type=7 adapter instance binds this single kind via
`credentialKind="vsphere_user"`. Guest-ops runs only when the Windows fields are
populated (`VCommunityConfig.hasWindowsCredential()`).

### Connection Settings

| Field | Key | Default | Required |
|---|---|---|---|
| vCenter Server | `host` | — | Yes |
| Port | `port` | 443 | No |
| Windows Service Configuration File | `win_service_config_file` | windows_service_list | No |
| Windows Event Log Configuration File | `win_event_config_file` | windows_event_list | No |
| Guest OS Service Monitoring Status | `serviceMonitoring` | Disabled | No |
| Windows Event Log Monitoring Status | `winEventMonitoring` | Disabled | No |
| Allow Insecure SSL | `allowInsecure` | false | No |

`serviceMonitoring` and `winEventMonitoring` are independent `Enabled`/`Disabled`
toggles. `serviceMonitoring` gates both Windows services AND in-guest CSV OS-info
(they run together under one gate, as in the original). The two `win_*_config_file`
fields hold the NAME (no path, no `.xml`) of a check-list file in the VCF Ops
central configuration-file store under `SolutionConfig/`. The four vSphere config
files belong to the `vcommunity-vsphere` pak. The bundled defaults ship in
`content/files/solutionconfig/` and import into the central store at install;
everything in them is commented out by design, so each gated collector emits
nothing until an admin uncomments entries centrally.

---

## Declared Object Type

### vCommunity World (`vCommunityWorld`, type=1)

Synthetic INTERNAL collection anchor (operability only). **Identifier**:
`world_id`.

#### Summary

| Key | Type | Meaning |
|---|---|---|
| `vms_stitched` | metric | VMs matched + pushed guest-ops data this cycle |
| `guest_vms_attempted` | metric | Windows guests guest-ops was attempted on |
| `guest_vms_degraded` | metric | guests where ≥1 guest-ops collector returned no data |
| `events_as_properties` | metric | Windows events surfaced as properties (TOOLSET GAP #1) |
| `last_scan_timestamp` | property | ISO timestamp of the last cycle |
| `config_file_status` | property | per-file fetched/parsed check counts + degradation notices |
| `status` | property | `OK` / stitcher-unavailable notice |

The anchor also carries the build-9/10 guest-ops diagnostics as properties
(`Summary|guestops_ready`, `Summary|guestops_vms`, `Summary|guestops_skips`,
`Summary|guestops_last_error`) — the read-only window onto *why* in-guest
collection is empty (the SHELVED blocker).

---

## Foreign-resource keys (pushed via Suite API, NOT in describe.xml)

Every key below is pushed onto the *existing* VMWARE `VirtualMachine` resource
(owned by the VMWARE adapter) — intentionally not declared here, exactly as the
compliance adapter pushes onto VMWARE HostSystem. Stitch identity is scoped by
MOID + `VMEntityVCID` (the build-2 multi-vCenter fix, retained verbatim).

### VirtualMachine (guest-ops only)

- `vCommunity|Guest OS|Services:{displayName}|{Service Name, Service Status,
  Service Start Type}` — Windows services (gated by `serviceMonitoring`).
- `vCommunity|Guest OS|Operating System|{OS Name, OS Version, OS BuildNumber,
  OS Architecture, OS Last Boot Up Time, OS Release ID}` — in-guest CSV OS-info
  (gated by `serviceMonitoring`; this pak owns the CSV path, NOT the passive
  Tools path which belongs to `vcommunity-vsphere`).
- `vCommunity|Guest OS|Last Event|{n}|{Level, Criticality, Message}` — Windows
  events degraded to properties (gated by `winEventMonitoring`; TOOLSET GAP #1).
- `vCommunity|Guest OS|Collection Status` — DEGRADED notice when a guest-ops
  collector returned no data.

The vSphere-side VM keys (`Snapshot|Count`, `Options|*`, `Configuration|Advanced
Parameters|*`, `Configuration|SCSI Controllers*`) and the passive Tools-path
`Guest OS|Operating System|*` keys belong to the `vcommunity-vsphere` pak and
are NOT emitted here.

---

## TOOLSET GAP #1 — foreign-resource event push

The original emits Windows event-log entries as foreign-resource **events**. The
factory `SuiteApiStitcher` facade exposes only `pushProperties` / `pushStats` —
there is no foreign-resource event/alert push endpoint wired in the framework.
Per the design's accepted staged plan, these are degraded this release to
**alertable properties** (visible, symptom-/alert-able, never silently dropped);
the `vCommunityWorld` `events_as_properties` metric counts them. Real
foreign-resource events are a **v1.1** deliverable once a clean Suite API
event-push path is proven (route to `tooling` to add `SuiteApiStitcher.pushEvents`).
