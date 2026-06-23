package com.vcfcf.adapters.vcommunity;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapters.vcommunity.VCommunityConfig.WindowsMonitoring;
import com.vcfcf.adapters.vcommunity.VCommunityVSphereClient.MoInfo;
import com.vcfcf.adapters.vcommunity.VCommunityVSphereClient.MoRef;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * VirtualMachine guest-ops collector (vcommunity-OS pak). When Windows
 * Monitoring is enabled and a Windows Guest Credential is present, reads
 * Windows services / in-guest OS info (CSV path) / event logs via
 * {@link GuestOpsClient}, running through the vCenter GuestOperationsManager.
 *
 * <p><b>Surface scope (vcommunity-os).</b> This pak owns ONLY the in-guest
 * guest-ops surface. The vSphere-side VM config reads (snapshot count, VM
 * options, advanced parameters, SCSI controllers) and the passive
 * VMware-Tools {@code Guest OS|Operating System|*} path
 * ({@code guest.detailedData}) are owned by the {@code vcommunity-vsphere}
 * pak and were stripped from this fork. The OS pak's {@code OS *} keys come
 * exclusively from the in-guest CSV path ({@code getWindowsOSInformation.ps1})
 * per the 2026-06-23 OPEN-A refinement.
 *
 * <p><b>Guest-ops crash-the-cycle isolation (binding — design Failure isolation
 * §, highest-risk regression).</b> Guest-ops is wrapped at TWO layers: every
 * {@link GuestOpsClient} call already catches and returns empty, and here each
 * VM's guest-ops block is additionally wrapped per-VM. A single unreachable or
 * mis-credentialed guest logs a degradation notice and the loop continues — it
 * never aborts the cycle or the property push for other VMs.
 *
 * <p><b>Windows events (TOOLSET GAP #1 degradation).</b> The original pushes each
 * matching Windows event as a foreign-resource EVENT. The factory Suite API
 * facade has no foreign-resource event push, so per the design's accepted staged
 * plan these events are degraded to a visible, alertable PROPERTY
 * representation ({@code vCommunity|Guest OS|Last Event|...}) rather than
 * silently dropped. The level→criticality mapping is preserved in the property
 * value. Real foreign-resource events are a v1.1 deliverable.
 */
final class VmCollector {

    static final class GuestScripts {
        final byte[] services;
        final byte[] osInfo;
        final byte[] events;
        GuestScripts(byte[] services, byte[] osInfo, byte[] events) {
            this.services = services;
            this.osInfo = osInfo;
            this.events = events;
        }
    }

    /** Guest-ops degradation notices collected this cycle (for the world anchor). */
    static final class Result {
        int stitched;
        int guestVmsAttempted;
        int guestVmsDegraded;
        int eventsAsProperties;

        // ---- build-9 readable guest-ops decision diagnostics (anchor only) ----
        // These are behavior-neutral observations of the existing decision path,
        // surfaced on the vCommunityWorld anchor so a single install + recon can
        // tell which leg blocks devel guest-ops collection (the appliance adapter
        // log is 404 via the Suite API).

        /** {@code guestOps.ready()} outcome this cycle, or why guest-ops did not run. */
        String guestopsReady = "not evaluated (guest-ops disabled or no credential)";
        /** Windows-candidate VMs reaching the per-VM gate this cycle. */
        int guestVmsConsidered;
        /** Of those considered, how many passed the toolsOk+windowsGuest gate. */
        int guestVmsPassed;
        /** Of those considered, how many were skipped at the gate. */
        int guestVmsSkipped;

        /** Bounded per-VM skip-reason summary (actual gate values read). */
        private final StringBuilder skips = new StringBuilder();
        private int skipsRecorded;
        private static final int MAX_SKIP_DETAIL = 10;

        /**
         * Record one skipped VM with the actual values read at the gate. Bounded
         * to {@link #MAX_SKIP_DETAIL} per-VM entries so the anchor property never
         * grows unbounded with VM count; the overflow is summarized as a count.
         */
        void recordSkip(String vmName, String toolsStatus, String guestFamily,
                String guestId) {
            if (skipsRecorded < MAX_SKIP_DETAIL) {
                if (skips.length() > 0) skips.append("; ");
                skips.append(nz(vmName)).append("[tools=").append(nz(toolsStatus))
                        .append(",family=").append(nz(guestFamily))
                        .append(",guestId=").append(nz(guestId)).append("]");
            }
            skipsRecorded++;
        }

        /** The bounded skip summary string for the anchor property. */
        String guestSkipsSummary() {
            if (skipsRecorded == 0) return "none";
            String s = skips.toString();
            if (skipsRecorded > MAX_SKIP_DETAIL) {
                s = s + "; (+" + (skipsRecorded - MAX_SKIP_DETAIL)
                        + " more skipped, detail capped)";
            }
            return s;
        }

        // ---- build-10 readable guest-ops fault diagnostics (anchor only) ----
        // The previously-swallowed SOAP fault from GuestOpsClient.post() — the
        // operation that faulted plus the vim25 fault class/message, per VM. This
        // is what identifies WHY in-guest collection returns zero rows on devel.
        // Bounded exactly like recordSkip so the anchor never floods; never
        // carries credential material (operation/fault-class/message only).

        private final StringBuilder faults = new StringBuilder();
        private int faultsRecorded;
        private static final int MAX_FAULT_DETAIL = 5;

        /**
         * Record one VM's last guest-ops SOAP fault for the anchor. {@code fault}
         * is GuestOpsClient's captured string ({@code "<op> -> <class> (<msg>)"});
         * a null fault (the VM faulted nowhere this cycle) is not recorded.
         * Bounded to {@link #MAX_FAULT_DETAIL}; overflow summarized as a count.
         */
        void recordFault(String vmName, String fault) {
            if (fault == null) return;
            if (faultsRecorded < MAX_FAULT_DETAIL) {
                if (faults.length() > 0) faults.append("; ");
                faults.append(nz(vmName)).append(": ").append(fault);
            }
            faultsRecorded++;
        }

        /** The bounded guest-ops fault summary for {@code guestops_last_error}. */
        String guestLastErrorSummary() {
            if (faultsRecorded == 0) return "none";
            String s = faults.toString();
            if (faultsRecorded > MAX_FAULT_DETAIL) {
                s = s + "; (+" + (faultsRecorded - MAX_FAULT_DETAIL)
                        + " more faulted, detail capped)";
            }
            return s;
        }
    }

    static Result collect(VCommunityVSphereClient vs, VCommunityStitcher stitcher,
            Logger log, VCommunityConfig cfg,
            List<String> winServices, boolean svcUsable, String winEventXml,
            GuestOpsClient guestOps, GuestScripts scripts, long ts)
            throws Exception {
        Result result = new Result();
        List<MoInfo> vms = vs.getVms();

        // Capture the guestOps.ready() outcome for the anchor diagnostics
        // (build 9). This records WHICH leg blocked when guest-ops does not run:
        // monitoring disabled, no Windows credential, no guest-ops client, or a
        // failing ready() precondition (the recon's prime suspect). Behavior-
        // neutral: the gate predicate below is unchanged.
        if (cfg.windowsMonitoring == WindowsMonitoring.DISABLED) {
            result.guestopsReady = "not evaluated (Windows Monitoring disabled)";
        } else if (!cfg.hasWindowsCredential()) {
            result.guestopsReady = "not evaluated (no Windows Guest Credential)";
        } else if (guestOps == null) {
            result.guestopsReady =
                    "false (guest-ops client unavailable: guestOperationsManager "
                    + "fileManager/processManager not resolved this cycle)";
        } else {
            result.guestopsReady = guestOps.readyReason();
        }

        boolean guestEnabled = cfg.windowsMonitoring != WindowsMonitoring.DISABLED
                && cfg.hasWindowsCredential()
                && guestOps != null && guestOps.ready();
        if (cfg.windowsMonitoring != WindowsMonitoring.DISABLED
                && !cfg.hasWindowsCredential()) {
            log.warn("VmCollector: Windows Monitoring='" + cfg.windowsMonitoring
                    + "' but no Windows Guest Credential set — guest-ops skipped "
                    + "(non-fatal). Set the Windows Guest Credential to enable.");
        }

        for (MoInfo v : vms) {
            try {
                VCommunityStitcher.Entry e = stitcher.matchVm(v.name, v.moid);
                if (e == null) continue;

                Map<String, String> props = new LinkedHashMap<>();

                // vcommunity-os pushes ONLY guest-ops data. A VM where guest-ops
                // is disabled or yields nothing produces no props and is NOT
                // counted as stitched — this pak has no passive vSphere surface
                // to fall back on (that is vcommunity-vsphere's).
                if (guestEnabled) {
                    collectGuest(vs, v, props, cfg, winServices, svcUsable,
                            winEventXml, guestOps, scripts, log, result);
                }

                if (!props.isEmpty()) {
                    stitcher.pushProperties(e.resourceId, props, ts);
                    result.stitched++;
                }
            } catch (Exception ex) {
                log.warn("VmCollector: '" + v.name + "' failed (isolated): "
                        + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
        }
        log.info("VmCollector: stitched " + result.stitched + "/" + vms.size()
                + " VM(s); guest-ops ready=" + result.guestopsReady
                + " considered=" + result.guestVmsConsidered
                + " passed=" + result.guestVmsPassed
                + " skipped=" + result.guestVmsSkipped
                + " attempted=" + result.guestVmsAttempted
                + " degraded=" + result.guestVmsDegraded);
        return result;
    }

    // ---- guest-ops (Windows) ----

    private static void collectGuest(VCommunityVSphereClient vs, MoInfo v,
            Map<String, String> props, VCommunityConfig cfg,
            List<String> winServices, boolean svcUsable, String winEventXml,
            GuestOpsClient guestOps, GuestScripts scripts, Logger log,
            Result result) {
        MoRef vm = v.moRef;
        // Every VM reaching the gate is "considered" for the anchor tally.
        result.guestVmsConsidered++;
        // Gate (vmService.py:131): toolsOk AND windowsGuest. Skip silently.
        String toolsStatus;
        String guestFamily;
        try {
            toolsStatus = vs.vmGuestToolsStatus(vm);
            guestFamily = vs.vmGuestFamily(vm);
        } catch (Exception ex) {
            log.warn("VmCollector: '" + v.name + "' guest gate read failed "
                    + "(isolated): " + ex.getMessage());
            result.guestVmsSkipped++;
            result.recordSkip(v.name, "READ_FAILED", "READ_FAILED", "READ_FAILED");
            return;
        }
        if (!"toolsOk".equals(toolsStatus)
                || !"windowsGuest".equals(guestFamily)) {
            // Not a manageable Windows guest. Diagnostics only (behavior-neutral):
            // log the actual gate values read so a wrongly-skipped Windows VM is
            // visible in the adapter log (currently our only ground-truth window),
            // and record the same values on the anchor skip summary (build 9) so a
            // recon can read them without appliance log access. The extra guestId
            // read happens only on the skip path — the happy path is untouched.
            String guestId;
            try { guestId = vs.vmGuestId(vm); }
            catch (Exception ex) { guestId = "READ_FAILED"; }
            log.warn("VmCollector: '" + v.name + "' skipped at guest-ops gate "
                    + "(toolsStatus=" + toolsStatus
                    + ", guestFamily=" + guestFamily
                    + ", guestId=" + guestId + ")");
            result.guestVmsSkipped++;
            result.recordSkip(v.name, toolsStatus, guestFamily, guestId);
            return;
        }

        result.guestVmsPassed++;
        result.guestVmsAttempted++;
        boolean degraded = false;
        // Build 10: reset the client's last-fault before this VM's guest-ops
        // calls so any captured fault is attributable to THIS VM this cycle.
        guestOps.clearLastFault();

        // Services
        if (cfg.windowsMonitoring.services() && svcUsable
                && !winServices.isEmpty() && scripts.services != null) {
            try {
                List<GuestOpsClient.ServiceRow> rows = guestOps.collectServices(
                        vm, v.name, scripts.services, winServices);
                if (rows.isEmpty()) {
                    degraded = true;
                }
                for (GuestOpsClient.ServiceRow r : rows) {
                    String base = "vCommunity|Guest OS|Services:"
                            + r.displayName + "|";
                    props.put(base + "Service Name", nz(r.name));
                    props.put(base + "Service Status", nz(r.status));
                    props.put(base + "Service Start Type", nz(r.startType));
                }
            } catch (Exception ex) {
                degraded = true;
                log.warn("VmCollector: '" + v.name + "' service guest-ops failed "
                        + "(isolated): " + ex.getMessage());
            }
        }

        // OS information — in the original this runs together with the service
        // collector under the same gate (collectVMData.py:69-72), so it is
        // bound to the Services enum value, not Event Logs.
        if (cfg.windowsMonitoring.services() && scripts.osInfo != null) {
            try {
                GuestOpsClient.OsInfoRow os = guestOps.collectOsInfo(
                        vm, v.name, scripts.osInfo);
                if (os == null) {
                    degraded = true;
                } else {
                    String base = "vCommunity|Guest OS|Operating System|";
                    props.put(base + "OS Name", nz(os.name));
                    props.put(base + "OS Version", nz(os.version));
                    props.put(base + "OS BuildNumber", nz(os.buildNumber));
                    props.put(base + "OS Architecture", nz(os.architecture));
                    props.put(base + "OS Last Boot Up Time", nz(os.lastBootUpTime));
                    props.put(base + "OS Release ID", nz(os.releaseId));
                }
            } catch (Exception ex) {
                degraded = true;
                log.warn("VmCollector: '" + v.name + "' OS-info guest-ops failed "
                        + "(isolated): " + ex.getMessage());
            }
        }

        // Event logs — degraded to alertable properties (TOOLSET GAP #1).
        if (cfg.windowsMonitoring.eventLogs() && winEventXml != null
                && scripts.events != null) {
            try {
                List<GuestOpsClient.EventRow> events = guestOps.collectEvents(
                        vm, v.name, scripts.events, winEventXml);
                int n = 0;
                for (GuestOpsClient.EventRow ev : events) {
                    n++;
                    // Property-degradation: criticality + message, alertable.
                    String crit = mapCriticality(ev.level);
                    props.put("vCommunity|Guest OS|Last Event|" + n + "|Level",
                            ev.level != null ? ev.level : "Unknown");
                    props.put("vCommunity|Guest OS|Last Event|" + n
                            + "|Criticality", crit);
                    props.put("vCommunity|Guest OS|Last Event|" + n + "|Message",
                            ev.message != null ? ev.message : "");
                    result.eventsAsProperties++;
                }
                if (n > 0) {
                    log.info("VmCollector: '" + v.name + "' surfaced " + n
                            + " Windows event(s) as properties "
                            + "(foreign-resource event push is TOOLSET GAP #1)");
                }
            } catch (Exception ex) {
                degraded = true;
                log.warn("VmCollector: '" + v.name + "' event-log guest-ops "
                        + "failed (isolated): " + ex.getMessage());
            }
        }

        if (degraded) {
            result.guestVmsDegraded++;
            props.put("vCommunity|Guest OS|Collection Status",
                    "DEGRADED — one or more guest-ops collectors returned no data "
                    + "this cycle (see adapter log)");
        }
        // Build 10 (observability-only): surface the previously-swallowed
        // guest-ops SOAP fault for THIS VM on the world anchor. Captured whether
        // or not it tripped `degraded` (an empty-but-non-faulting cycle records
        // nothing — recordFault ignores a null). No credential material: the
        // string is operation + vim25 fault class/message only.
        result.recordFault(v.name, guestOps.lastFault());
    }

    /** Original level→criticality mapping (collect_windows_event_logs.py:168). */
    private static String mapCriticality(String level) {
        if (level == null) return "INFO";
        switch (level.trim()) {
            case "Warning":  return "WARNING";
            case "Error":    return "IMMEDIATE";
            case "Critical": return "CRITICAL";
            case "Information":
            case "Verbose":
            default:         return "INFO";
        }
    }

    private static String nz(String v) { return v != null ? v : ""; }
}
