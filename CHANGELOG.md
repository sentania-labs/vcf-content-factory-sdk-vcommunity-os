# Changelog

## build-1 — fork of unified vcommunity → vcommunity-os (2026-06-23)

`feat(adapter): fork the unified vCommunity adapter into the vcommunity-os pak`

STEP 1 of the vCommunity vsphere/os split
(`designs/managementpacks/vcommunity-three-adapter-split.md`). Forked the unified
`vcfcf_vcommunity` adapter (build 11) into this fresh-lineage `vcfcf_vcommunity_os`
pak, capturing the guest-ops code before it is stripped from the vSphere pak in a
later step. Fresh build numbering starts at 1.

**Kept (the OS pak's surface):**
- `GuestOpsClient.java` and the guest-ops branch of `VmCollector` — Windows
  services, in-guest CSV OS-info (`getWindowsOSInformation.ps1`), and Windows
  event logs via the vim25 GuestOperationsManager.
- The shared plumbing for its OWN vCenter session + stitch: `VCommunityVSphereClient`,
  `VCommunityStitcher`, `SolutionConfigStore`, the `SuiteApiStitcher` usage
  (deliberate duplication per design §2 — not shared with the vsphere pak).
- The Windows credential fields (`winUser`/`winPass`), the Windows Monitoring
  enums (`serviceMonitoring`/`winEventMonitoring`), and the vCenter credential
  (guest-ops runs THROUGH a vCenter session).
- The two Windows SolutionConfig XMLs (`windows_service_list.xml`,
  `windows_event_list.xml`).
- The Windows content: `Windows Service Down` symptom + alert, `Windows Services
  vCommunity` view.
- **The build-2 `VMEntityVCID` stitch-scoping fix — retained verbatim**
  (`lessons/stitch-moid-not-unique-across-vcenters.md`, design Risk #2).

**Stripped (vSphere-only — belongs to vcommunity-vsphere):**
- `ClusterCollector.java`, `HostCollector.java`, and the vSphere-side branch of
  `VmCollector` (snapshot count, VM options, advanced parameters, SCSI
  controllers, and the passive VMware-Tools `Guest OS|Operating System|*` path).
- The four vSphere config XMLs and their adapter-instance config-file fields.
- All 37 super metrics, 11 dashboards, and the vSphere views/symptom/alert.

**Re-identity:** adapter kind `vcfcf_vcommunity` → `vcfcf_vcommunity_os`; MP
display name → `VCF Content Factory vCommunity OS`; describe.xml, adapter.yaml,
icons.yaml, resources.properties, README/REFERENCE all updated.

## KNOWN-OPEN BLOCKER (shelved 2026-06-23) — guest-ops collection returns zero rows

This pak is built **structurally**; in-guest collection is a known-open blocker,
intentionally shelved, NOT debugged in this build.

- **Symptom:** Windows `Services:*`, in-guest CSV OS-info, and events return zero
  rows on both this Java port and Onur's prod Python, on hardened Server 2025 DCs.
- **Eliminated:** transport; SolutionConfig gate; service names; CSV format /
  BOM; credential identity AND privilege (domain-admin swap changed nothing).
- **Leading unconfirmed theory:** non-interactive, VMware-Tools-launched
  PowerShell execution blocked by machine policy (ExecutionPolicy
  Restricted/AllSigned or ConstrainedLanguage / AppLocker / WDAC).
- **When un-shelved:** check `Get-ExecutionPolicy -List` + LanguageMode on a DC;
  if confirmed, add `-ExecutionPolicy Bypass -NonInteractive` to
  `GuestOpsClient.runPowershell`, and surface the swallowed `StartProgram` fault.
- Full diagnosis:
  `context/investigations/vcommunity-windows-services-empty-2026-06-23.md`,
  `context/investigations/vcommunity-guestops-execution-divergence-2026-06-22.md`.

## Carried gaps (from the unified pak)

- **TOOLSET GAP #1 — foreign-resource event push.** Windows event logs ship as
  alertable properties, not real events (Suite API facade has no event endpoint).
  Real events → **v1.1**.
- **NIT 1 — positional `Last Event` keys** (`…|Last Event|{n}|…`) can churn
  ordering cycle-to-cycle. Stable event-id keys → **v1.1**.
- **Guest-ops scope/concurrency** — single-threaded, 120 s per-VM poll ceiling,
  all-Windows-VMs-in-scope when enabled. Per-VM scoping → **v2**.
