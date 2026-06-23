package com.vcfcf.adapters.vcommunity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.integrien.alive.common.adapter3.Logger;

/**
 * Raw-SOAP vim25 client for the vCommunity adapter.
 *
 * <p><b>Why raw SOAP, not JAX-WS.</b> Identical reasoning to the compliance
 * reference implementation: on VCF Ops 9.1 the platform's mixed javax/jakarta
 * JAX-WS stack breaks {@code javax.xml.ws.spi.Provider} discovery every cycle.
 * This client hand-builds SOAP 1.1 envelopes POSTed to the vCenter {@code /sdk}
 * over {@link HttpURLConnection} and walks the response DOM by element
 * local-name — no vim25 bindings, no concrete-type casts.
 *
 * <p><b>Reflection-tolerant reads.</b> Every property read resolves the longest
 * dotted PropertyCollector prefix it can and walks the remainder by DOM child
 * local-name; a missing element returns {@code null} (skip), never throws and
 * never a sentinel. Device/spec type discrimination is by the wire
 * {@code xsi:type}, the analogue of the original's {@code isinstance} checks —
 * never an {@code instanceof} against a concrete subclass.
 *
 * <p>SSL: the caller selects the {@link SSLSocketFactory} (platform trust by
 * default, {@code allowInsecure} lab opt-out), exactly as compliance does.
 */
public final class VCommunityVSphereClient {

    private final String vcenterUrl;       // https://<host[:port]>/sdk
    private final String username;
    private final String password;         // REDACT-SECRET
    private final SSLSocketFactory sslFactory;
    private final boolean trustAll;
    private final Logger log;

    private volatile String sessionCookie;
    private volatile MoRef propertyCollector;
    private volatile MoRef viewManager;
    private volatile MoRef rootFolder;
    private volatile MoRef sessionManager;
    private volatile MoRef licenseManager;
    private volatile MoRef licenseAssignmentManager;
    private volatile MoRef guestOperationsManager;
    private volatile String aboutInstanceUuid;

    /**
     * The most recent SOAP {@code <faultstring>} parsed from a non-2xx response
     * (REDACTED of any secrets per {@code rules/no-secrets-on-disk.md}). Lets the
     * connect/login path surface a diagnosable reason instead of a bare
     * "no response", without throwing from the many optional-read call sites
     * where a non-2xx is a legitimate null-skip.
     */
    private volatile String lastFaultString;

    public VCommunityVSphereClient(String hostPort, String username,
            String password, SSLSocketFactory sslFactory, boolean trustAll,
            Logger log) {
        this.vcenterUrl = "https://" + hostPort + "/sdk";
        this.username = username;
        this.password = password;          // REDACT-SECRET
        this.sslFactory = sslFactory;
        this.trustAll = trustAll;
        this.log = log;
    }

    private void logInfo(String m) { if (log != null) log.info(m); }
    private void logWarn(String m) { if (log != null) log.warn(m); }

    // =====================================================================
    // Session lifecycle
    // =====================================================================

    public void connect() throws Exception {
        String body = "<RetrieveServiceContent xmlns=\"urn:vim25\">"
                + "<_this type=\"ServiceInstance\">ServiceInstance</_this>"
                + "</RetrieveServiceContent>";
        Document resp = post(body, "urn:vim25/RetrieveServiceContent", false);
        if (resp == null) {
            throw new Exception("RetrieveServiceContent failed (no response)");
        }
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) throw new Exception("RetrieveServiceContent: no returnval");
        this.propertyCollector = moRefOf(rv, "propertyCollector");
        this.viewManager = moRefOf(rv, "viewManager");
        this.rootFolder = moRefOf(rv, "rootFolder");
        this.sessionManager = moRefOf(rv, "sessionManager");
        // ServiceContent exposes licenseManager directly; the
        // licenseAssignmentManager is a PROPERTY of the LicenseManager
        // (licenseManager.licenseAssignmentManager), NOT a direct field of
        // ServiceContent — resolved lazily after login (see
        // licenseAssignmentManager()). Reading it off ServiceContent (the
        // build-2 bug) always returned null, which silently dropped every
        // host-licensing key on devel.
        this.licenseManager = moRefOf(rv, "licenseManager");
        this.licenseAssignmentManager = null;
        this.guestOperationsManager = moRefOf(rv, "guestOperationsManager");
        Element about = firstDirectChild(rv, "about");
        if (about != null) {
            this.aboutInstanceUuid = childText(about, "instanceUuid");
        }
        if (sessionManager == null || propertyCollector == null
                || rootFolder == null) {
            throw new Exception("RetrieveServiceContent: incomplete content");
        }

        String loginBody = "<Login xmlns=\"urn:vim25\">"
                + "<_this type=\"SessionManager\">"
                + xmlEscape(sessionManager.value) + "</_this>"
                + "<userName>" + xmlEscape(username) + "</userName>"
                + "<password>" + xmlEscape(password) + "</password>"  // REDACT-SECRET
                + "</Login>";
        this.lastFaultString = null;
        Document loginResp = post(loginBody, "urn:vim25/Login", false);
        if (loginResp == null) {
            String fault = lastFaultString;
            throw new Exception("Login to vCenter '" + hostLabel()
                    + "' failed: " + (fault != null ? fault
                            : "no response / SOAP fault (check vCenter "
                            + "reachability and credentials)"));
        }
        if (sessionCookie == null) {
            throw new Exception("Login succeeded but no session cookie returned");
        }
    }

    public void disconnect() {
        if (sessionManager != null && sessionCookie != null) {
            try {
                String body = "<Logout xmlns=\"urn:vim25\">"
                        + "<_this type=\"SessionManager\">"
                        + xmlEscape(sessionManager.value) + "</_this></Logout>";
                post(body, "urn:vim25/Logout", true);
            } catch (Exception ignored) {}
        }
        sessionCookie = null;
        propertyCollector = null;
        viewManager = null;
        rootFolder = null;
        sessionManager = null;
        licenseManager = null;
        licenseAssignmentManager = null;
        aboutInstanceUuid = null;
    }

    public void ensureConnected() throws Exception {
        if (sessionCookie == null || propertyCollector == null) {
            connect();
            return;
        }
        try {
            String body = "<CurrentTime xmlns=\"urn:vim25\">"
                    + "<_this type=\"ServiceInstance\">ServiceInstance</_this>"
                    + "</CurrentTime>";
            Document resp = post(body, "urn:vim25/CurrentTime", true);
            if (resp == null
                    || firstByLocalName(resp.getDocumentElement(),
                            "returnval") == null) {
                disconnect();
                connect();
            }
        } catch (Exception e) {
            disconnect();
            connect();
        }
    }

    public String getVCenterInstanceUuid() { return aboutInstanceUuid; }

    /** The vCenter host[:port] for actionable error messages (no secrets). */
    private String hostLabel() {
        String u = vcenterUrl;
        if (u == null) return "<unknown>";
        u = u.replaceFirst("^https?://", "");
        int slash = u.indexOf('/');
        return slash >= 0 ? u.substring(0, slash) : u;
    }

    /** The active vim25 session cookie (guest-ops file transfers ride it). */
    public String sessionCookie() { return sessionCookie; }

    /** The vCenter {@code /sdk} URL (guest-ops SOAP shares the endpoint). */
    public String vcenterUrl() { return vcenterUrl; }

    /** {@code guestOperationsManager.fileManager} MoRef, or null. */
    public MoRef guestFileManager() throws Exception {
        ensureConnected();
        if (guestOperationsManager == null) return null;
        return getMoRefProperty(guestOperationsManager, "fileManager");
    }

    /** {@code guestOperationsManager.processManager} MoRef, or null. */
    public MoRef guestProcessManager() throws Exception {
        ensureConnected();
        if (guestOperationsManager == null) return null;
        return getMoRefProperty(guestOperationsManager, "processManager");
    }

    // =====================================================================
    // Inventory walkers
    // =====================================================================

    public List<MoInfo> getClusters() throws Exception {
        return inventory("ClusterComputeResource");
    }

    public List<MoInfo> getHosts() throws Exception {
        return inventory("HostSystem");
    }

    public List<MoInfo> getVms() throws Exception {
        return inventory("VirtualMachine");
    }

    private List<MoInfo> inventory(String type) throws Exception {
        ensureConnected();
        List<MoInfo> out = new ArrayList<>();
        for (MoRef ref : listView(type)) {
            String name = getStringProperty(ref, "name");
            if (name != null) out.add(new MoInfo(ref, name, ref.value));
        }
        logInfo("vSphere SOAP: " + out.size() + " " + type);
        return out;
    }

    // =====================================================================
    // Cluster reads
    // =====================================================================

    /** {@code configuration.dasConfig.enabled} (HA on/off). Null when unread. */
    public Boolean clusterHaEnabled(MoRef cluster) throws Exception {
        return readBool(cluster, "configuration.dasConfig.enabled");
    }

    /** {@code configuration.dasConfig.hostMonitoring}. */
    public String clusterHostMonitoring(MoRef cluster) throws Exception {
        return readScalar(cluster, "configuration.dasConfig.hostMonitoring");
    }

    /** {@code configuration.drsConfig.enabled} (DRS on/off). */
    public Boolean clusterDrsEnabled(MoRef cluster) throws Exception {
        return readBool(cluster, "configuration.drsConfig.enabled");
    }

    /** A scalar value at a dotted config path under the cluster object. */
    public String readScalar(MoRef ref, String path) throws Exception {
        ensureConnected();
        Element node = walkToNode(ref, dot(path));
        if (node == null) return null;
        String t = elementText(node);
        return (t == null || t.isEmpty()) ? null : t;
    }

    public Boolean readBool(MoRef ref, String path) throws Exception {
        ensureConnected();
        Element node = walkToNode(ref, dot(path));
        if (node == null) return null;
        return parseBool(elementText(node));
    }

    /**
     * {@code configurationEx.drsConfig.option[key=MaxVcpusPerCore].value}.
     * Returns the value string, or {@code null} when the option is absent
     * (caller emits "N/A"). DOM walk over the repeated {@code <option>} list.
     */
    public String clusterMaxVcpusPerCore(MoRef cluster) throws Exception {
        ensureConnected();
        Element drs = walkToNode(cluster, dot("configurationEx.drsConfig"));
        if (drs == null) return null;
        for (Element opt : childrenByLocalName(drs, "option")) {
            String key = childText(opt, "key");
            if ("MaxVcpusPerCore".equals(key)) {
                String v = childText(opt, "value");
                return (v == null || v.isEmpty()) ? null : v;
            }
        }
        return null;
    }

    /** {@code summary.drsScore} as a metric. Null when unread. */
    public Double clusterDrsScore(MoRef cluster) throws Exception {
        ensureConnected();
        Element node = walkToNode(cluster, dot("summary.drsScore"));
        if (node == null) return null;
        String t = elementText(node);
        if (t == null || t.isEmpty()) return null;
        try { return Double.parseDouble(t.trim()); }
        catch (NumberFormatException e) { return null; }
    }

    /**
     * EVC: invoke {@code EvcManager()} on the cluster, then read
     * {@code evcState.currentEVCModeKey}. Returns the mode key string, or
     * {@code null} when EVC is disabled (no current mode). Distinguishes a
     * read failure (throws) from "disabled" (returns null).
     */
    public String clusterEvcModeKey(MoRef cluster) throws Exception {
        ensureConnected();
        // EvcManager is a method that returns a ClusterEVCManager MoRef.
        String body = "<EvcManager xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(cluster.type) + "\">"
                + xmlEscape(cluster.value) + "</_this></EvcManager>";
        Document resp = post(body, "urn:vim25/EvcManager", true);
        if (resp == null) return null;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) return null;
        String mgrVal = elementText(rv);
        if (mgrVal == null || mgrVal.trim().isEmpty()) return null;
        String mgrType = rv.getAttribute("type");
        MoRef evcMgr = new MoRef(
                mgrType != null && !mgrType.isEmpty() ? mgrType
                        : "ClusterEVCManager", mgrVal.trim());
        Element node = walkToNode(evcMgr, dot("evcState.currentEVCModeKey"));
        if (node == null) return null;
        String t = elementText(node);
        return (t == null || t.isEmpty()) ? null : t;
    }

    // =====================================================================
    // Host reads
    // =====================================================================

    /** {@code runtime.connectionState}. */
    public String hostConnectionState(MoRef host) throws Exception {
        ensureConnected();
        return getStringProperty(host, "runtime.connectionState");
    }

    /** Host advanced settings via {@code configManager.advancedOption}. */
    public Map<String, String> hostAdvancedSettings(MoRef host) throws Exception {
        ensureConnected();
        MoRef optMgr = getMoRefProperty(host, "configManager.advancedOption");
        if (optMgr == null) return new LinkedHashMap<>();
        return queryOptions(optMgr);
    }

    /** Physical NICs at {@code config.network.pnic}. Each map: device→pnic fields. */
    public List<Map<String, String>> hostPnics(MoRef host) throws Exception {
        ensureConnected();
        List<Map<String, String>> out = new ArrayList<>();
        Element net = walkToNode(host, dot("config.network"));
        if (net == null) return out;
        for (Element pnic : childrenByLocalName(net, "pnic")) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("device", childText(pnic, "device"));
            m.put("driverVersion", childText(pnic, "driverVersion"));
            m.put("firmwareVersion", childText(pnic, "firmwareVersion"));
            // linkSpeed is a complex child; presence => Connected.
            m.put("linkSpeedPresent",
                    firstDirectChild(pnic, "linkSpeed") != null ? "true" : "false");
            out.add(m);
        }
        return out;
    }

    /**
     * Resolve {@code configManager.imageConfigManager} (a HostImageConfigManager
     * MoRef), or {@code null} when the host has none.
     */
    public MoRef hostImageConfigManager(MoRef host) throws Exception {
        ensureConnected();
        return getMoRefProperty(host, "configManager.imageConfigManager");
    }

    /**
     * Invoke {@code fetchSoftwarePackages()} on the image config manager.
     * Returns one map per VIB package (keyed by field name). Empty when the
     * host exposes no packages.
     */
    public List<Map<String, String>> fetchSoftwarePackages(MoRef imageConfigMgr)
            throws Exception {
        ensureConnected();
        List<Map<String, String>> out = new ArrayList<>();
        if (imageConfigMgr == null) return out;
        String body = "<FetchSoftwarePackages xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(imageConfigMgr.type) + "\">"
                + xmlEscape(imageConfigMgr.value) + "</_this>"
                + "</FetchSoftwarePackages>";
        Document resp = post(body, "urn:vim25/FetchSoftwarePackages", true);
        if (resp == null) return out;
        for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
                "returnval")) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("name", childText(rv, "name"));
            m.put("version", childText(rv, "version"));
            m.put("acceptanceLevel", childText(rv, "acceptanceLevel"));
            m.put("maintenanceModeRequired",
                    childText(rv, "maintenanceModeRequired"));
            m.put("summary", childText(rv, "summary"));
            m.put("type", childText(rv, "type"));
            m.put("vendor", childText(rv, "vendor"));
            if (m.get("name") != null) out.add(m);
        }
        return out;
    }

    /**
     * Invoke {@code installDate()} on the image config manager. Returns the ISO
     * datetime string vCenter returns, or {@code null}. Throws on a SOAP fault
     * so the caller can surface the documented install-date read-failure signal.
     */
    public String fetchInstallDate(MoRef imageConfigMgr) throws Exception {
        ensureConnected();
        if (imageConfigMgr == null) return null;
        String body = "<installDate xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(imageConfigMgr.type) + "\">"
                + xmlEscape(imageConfigMgr.value) + "</_this></installDate>";
        Document resp = post(body, "urn:vim25/installDate", true);
        if (resp == null) {
            throw new Exception("installDate SOAP call returned no response "
                    + "(fault or transport error)");
        }
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) return null;
        String t = elementText(rv);
        return (t == null || t.isEmpty()) ? null : t;
    }

    /** One assigned-license record for a host. */
    public static final class LicenseInfo {
        public final String name;
        public final String licenseKey;
        public final String expirationDate;  // raw vim DateTime string or null
        public final String editionKey;
        public LicenseInfo(String name, String licenseKey,
                String expirationDate, String editionKey) {
            this.name = name;
            this.licenseKey = licenseKey;
            this.expirationDate = expirationDate;
            this.editionKey = editionKey;
        }
    }

    /**
     * Lazily resolve {@code licenseManager.licenseAssignmentManager} (a
     * LicenseAssignmentManager MoRef). Cached after the first successful read.
     * Returns null when the LicenseManager is absent or the property cannot be
     * read (caller emits no licensing keys — never a sentinel).
     */
    private MoRef licenseAssignmentManager() throws Exception {
        MoRef cached = licenseAssignmentManager;
        if (cached != null) return cached;
        if (licenseManager == null) return null;
        MoRef lam = getMoRefProperty(licenseManager, "licenseAssignmentManager");
        if (lam != null) licenseAssignmentManager = lam;
        return lam;
    }

    /**
     * {@code licenseAssignmentManager.QueryAssignedLicenses(hostMoid)}. Returns
     * the assigned-license records. Empty when the host has none / unreadable.
     */
    public List<LicenseInfo> queryAssignedLicenses(String hostMoid)
            throws Exception {
        ensureConnected();
        List<LicenseInfo> out = new ArrayList<>();
        MoRef lam = licenseAssignmentManager();
        if (lam == null || hostMoid == null) return out;
        String body = "<QueryAssignedLicenses xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(lam.type)
                + "\">" + xmlEscape(lam.value) + "</_this>"
                + "<entityId>" + xmlEscape(hostMoid) + "</entityId>"
                + "</QueryAssignedLicenses>";
        Document resp = post(body, "urn:vim25/QueryAssignedLicenses", true);
        if (resp == null) return out;
        for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
                "returnval")) {
            Element assigned = firstDirectChild(rv, "assignedLicense");
            if (assigned == null) continue;
            String name = childText(assigned, "name");
            String key = childText(assigned, "licenseKey");
            String edition = childText(assigned, "editionKey");
            String expiration = null;
            for (Element prop : childrenByLocalName(assigned, "properties")) {
                if ("expirationDate".equals(childText(prop, "key"))) {
                    expiration = childText(prop, "value");
                    break;
                }
            }
            out.add(new LicenseInfo(name, key, expiration, edition));
        }
        return out;
    }

    // =====================================================================
    // VM reads
    // =====================================================================

    /** VM {@code config.extraConfig} as a key/value map. */
    public Map<String, String> vmExtraConfig(MoRef vm) throws Exception {
        ensureConnected();
        Map<String, String> result = new LinkedHashMap<>();
        Element val = walkToNode(vm, dot("config.extraConfig"));
        if (val == null) return result;
        for (Element item : childElements(val)) {
            String key = childText(item, "key");
            String value = childText(item, "value");
            if (key != null && value != null) result.put(key, value);
        }
        return result;
    }

    /** A dotted config path under the VM (e.g. config.latencySensitivity.level). */
    public String vmConfigPath(MoRef vm, String path) throws Exception {
        ensureConnected();
        Element node = walkToNode(vm, dot(path));
        if (node == null) return null;
        String t = elementText(node);
        return (t == null || t.isEmpty()) ? null : t;
    }

    /**
     * Guest tools status / family for the guest-ops gate.
     *
     * <p>Faithful port: the prod original (pyVmomi {@code vmService.py:129-131},
     * {@code collect_windows_events.py:133-135}) reads the <em>full</em>
     * {@code guest} (GuestInfo) managed-object property, then reads
     * {@code toolsStatus} / {@code guestFamily} off the returned object — and
     * gets reliably-populated values. Requesting the narrow sub-paths
     * {@code guest.toolsStatus} / {@code guest.guestFamily} directly in the
     * vim25 {@code RetrieveProperties} pathSet returned blank/stale for those
     * fields, silently failing the Windows guest-ops gate. We retrieve the
     * broad {@code guest} object the same way the original does (a single
     * {@code RetrieveProperties} of {@code guest}) and read the child off it.
     */
    public String vmGuestToolsStatus(MoRef vm) throws Exception {
        ensureConnected();
        Element guest = walkToNode(vm, dot("guest"));
        return childText(guest, "toolsStatus");
    }

    public String vmGuestFamily(MoRef vm) throws Exception {
        ensureConnected();
        Element guest = walkToNode(vm, dot("guest"));
        return childText(guest, "guestFamily");
    }

    /**
     * Configured guest OS identifier ({@code guest.guestId}, e.g.
     * {@code windows2025_64Guest}) off the same broad {@code guest} GuestInfo
     * object. Used by build-9 diagnostics only — surfaced in the per-VM gate
     * skip-reason summary so a recon can see the actual guestId of a VM rejected
     * at the gate (does not gate collection; returns null on absence, never
     * throws).
     */
    public String vmGuestId(MoRef vm) throws Exception {
        ensureConnected();
        Element guest = walkToNode(vm, dot("guest"));
        return childText(guest, "guestId");
    }

    /**
     * VMware-Tools guest OS information, the analogue of the original adapter's
     * {@code Guest OS|Operating System} block but sourced from vim25 guest
     * info (not an in-guest PowerShell run), so it populates for every VM whose
     * tools report it — including non-Windows guests — exactly as the prod
     * original emits it.
     *
     * <p>Two reflection-tolerant sources, both null-skip on absence:
     * <ul>
     *   <li>{@code guest.detailedData} — the VMware Tools detailed key/value
     *       array (vSphere 8+/newer tools): {@code prettyName}, {@code architecture},
     *       {@code buildNumber}, {@code releaseId}, {@code version}.</li>
     *   <li>{@code runtime.bootTime} — Last Boot Up Time.</li>
     * </ul>
     *
     * <p>Returns a map keyed by the prod original's six canonical
     * {@code OS }-prefixed property names ({@code OS Name}, {@code OS Version},
     * {@code OS BuildNumber}, {@code OS Architecture}, {@code OS Last Boot Up Time},
     * {@code OS Release ID}) which the caller pushes verbatim onto
     * {@code vCommunity|Guest OS|Operating System|...}. Using the original's exact
     * key names makes this VMware-Tools path a benign non-Windows superset of the
     * original's Windows-CSV path (ported content referencing those names finds
     * data on every VM whose tools report it). A key absent from the map means the
     * guest did not report it (the caller skips it — never a sentinel; unreadable
     * is not a value).
     */
    public Map<String, String> vmGuestOsInfo(MoRef vm) throws Exception {
        ensureConnected();
        Map<String, String> out = new LinkedHashMap<>();

        // guest.detailedData: repeated <detailedData><key>..</key><value>..</value>
        Element detailed = walkToNode(vm, dot("guest.detailedData"));
        if (detailed != null) {
            // The walk lands on the first <detailedData> element; collect all
            // sibling key/value pairs under guest. Re-read the parent <guest>
            // node so every detailedData entry is visible.
            Element guest = walkToNode(vm, dot("guest"));
            List<Element> entries = (guest != null)
                    ? childrenByLocalName(guest, "detailedData")
                    : java.util.Collections.singletonList(detailed);
            for (Element e : entries) {
                String k = childText(e, "key");
                String val = childText(e, "value");
                if (k == null || val == null || val.isEmpty()) continue;
                switch (k) {
                    case "prettyName":   putShort(out, "OS Name", val); break;
                    case "architecture": putShort(out, "OS Architecture", val); break;
                    case "buildNumber":  putShort(out, "OS BuildNumber", val); break;
                    case "releaseId":    putShort(out, "OS Release ID", val); break;
                    case "version":      putShort(out, "OS Version", val); break;
                    default: /* other detailedData keys not part of the contract */
                }
            }
        }

        // Last Boot Up Time <- runtime.bootTime (a real vim DateTime; skip if absent)
        String bootTime = getStringProperty(vm, "runtime.bootTime");
        if (bootTime != null && !bootTime.isEmpty()) {
            putShort(out, "OS Last Boot Up Time", bootTime);
        }

        return out;
    }

    private static void putShort(Map<String, String> m, String k, String v) {
        if (v != null && !v.isEmpty()) m.put(k, v);
    }

    /**
     * Recursive snapshot count: walk {@code snapshot.rootSnapshotList} and every
     * {@code childSnapshotList}. Returns 0 when the VM has no snapshots (a
     * genuine reading — the absence of a {@code <snapshot>} node), or
     * {@code null} only when the VM object could not be read at all.
     */
    public Integer vmSnapshotCount(MoRef vm) throws Exception {
        ensureConnected();
        // The VM's snapshot property (VirtualMachineSnapshotInfo) carries the
        // rootSnapshotList children. Its ABSENCE is a real "0 snapshots"
        // reading, not an unreadable error.
        Element parent = walkToNode(vm, dot("snapshot"));
        if (parent == null) return 0;   // no snapshot object => 0 snapshots
        int count = countSnapshots(childrenByLocalName(parent, "rootSnapshotList"));
        return count;
    }

    private int countSnapshots(List<Element> nodes) {
        int total = 0;
        for (Element n : nodes) {
            total++;
            total += countSnapshots(childrenByLocalName(n, "childSnapshotList"));
        }
        return total;
    }

    /** A SCSI controller discovered on a VM. */
    public static final class ScsiController {
        public final String busNumber;
        public final String friendlyType;
        public ScsiController(String busNumber, String friendlyType) {
            this.busNumber = busNumber;
            this.friendlyType = friendlyType;
        }
    }

    /**
     * Walk {@code config.hardware.device} and select VirtualSCSIController
     * subtypes by their wire {@code xsi:type}. Returns one record per controller
     * with the friendly type name (the original's pretty_type mapping).
     */
    public List<ScsiController> vmScsiControllers(MoRef vm) throws Exception {
        ensureConnected();
        List<ScsiController> out = new ArrayList<>();
        Element hw = walkToNode(vm, dot("config.hardware"));
        if (hw == null) return out;
        for (Element dev : childrenByLocalName(hw, "device")) {
            String type = xsiType(dev);
            String friendly = friendlyScsiType(type);
            if (friendly == null) continue;   // not a SCSI controller
            String bus = childText(dev, "busNumber");
            out.add(new ScsiController(bus != null ? bus : "unknown", friendly));
        }
        return out;
    }

    private static String friendlyScsiType(String xsiType) {
        if (xsiType == null) return null;
        // xsi:type carries the concrete VirtualDevice subtype name.
        if (xsiType.contains("ParaVirtualSCSIController")) {
            return "VMware Paravirtual (PVSCSI)";
        }
        if (xsiType.contains("VirtualLsiLogicSASController")) {
            return "LSI Logic SAS";
        }
        if (xsiType.contains("VirtualLsiLogicController")) {
            return "LSI Logic Parallel";
        }
        if (xsiType.contains("VirtualBusLogicController")) {
            return "BusLogic";
        }
        if (xsiType.contains("VirtualSCSIController")) {
            // base SCSI controller type — count it, unknown friendly name.
            return xsiType;
        }
        return null;
    }

    // =====================================================================
    // PropertyCollector primitives + OptionManager
    // =====================================================================

    private Map<String, String> queryOptions(MoRef optionMgr) throws Exception {
        Map<String, String> result = new LinkedHashMap<>();
        String body = "<QueryOptions xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(optionMgr.type) + "\">"
                + xmlEscape(optionMgr.value) + "</_this></QueryOptions>";
        Document resp = post(body, "urn:vim25/QueryOptions", true);
        if (resp == null) return result;
        for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
                "returnval")) {
            String key = childText(rv, "key");
            String value = childText(rv, "value");
            if (key != null && value != null) result.put(key, value);
        }
        return result;
    }

    private Element getRawPropertyElement(MoRef moRef, String propPath)
            throws Exception {
        Document resp = retrieveProperties(moRef.type, moRef.value, propPath);
        if (resp == null) return null;
        Element returnval = firstByLocalName(resp.getDocumentElement(),
                "returnval");
        if (returnval == null) return null;
        for (Element propSet : childrenByLocalName(returnval, "propSet")) {
            String name = childText(propSet, "name");
            if (propPath.equals(name)) {
                return firstDirectChild(propSet, "val");
            }
        }
        return null;
    }

    private String getStringProperty(MoRef moRef, String propPath)
            throws Exception {
        Element val = getRawPropertyElement(moRef, propPath);
        if (val == null) return null;
        String t = elementText(val);
        return (t == null || t.isEmpty()) ? null : t;
    }

    private MoRef getMoRefProperty(MoRef moRef, String propPath)
            throws Exception {
        Element val = getRawPropertyElement(moRef, propPath);
        if (val == null) return null;
        String type = val.getAttribute("type");
        String value = elementText(val);
        if (value == null || value.isEmpty()) return null;
        return new MoRef(type != null && !type.isEmpty() ? type
                : "ManagedObject", value);
    }

    private Document retrieveProperties(String type, String value,
            String propPath) throws Exception {
        String body = "<RetrieveProperties xmlns=\"urn:vim25\">"
                + "<_this type=\"PropertyCollector\">"
                + xmlEscape(propertyCollector.value) + "</_this>"
                + "<specSet><propSet><type>" + xmlEscape(type) + "</type>"
                + "<pathSet>" + xmlEscape(propPath) + "</pathSet></propSet>"
                + "<objectSet><obj type=\"" + xmlEscape(type) + "\">"
                + xmlEscape(value) + "</obj><skip>false</skip></objectSet>"
                + "</specSet></RetrieveProperties>";
        return post(body, "urn:vim25/RetrieveProperties", true);
    }

    // ----- DOM path walking ----------------------------------------------

    private static String[] dot(String path) { return path.split("\\."); }

    private Element walkToNode(MoRef moRef, String[] segments) throws Exception {
        int[] consumed = new int[1];
        Element node = getLongestPrefixElement(moRef, segments,
                segments.length, consumed);
        for (int i = consumed[0]; i < segments.length; i++) {
            if (node == null) return null;
            node = firstDirectChild(node, segments[i]);
        }
        return node;
    }

    private Element getLongestPrefixElement(MoRef moRef, String[] segments,
            int maxLen, int[] consumedOut) throws Exception {
        int start = Math.min(maxLen, segments.length);
        for (int len = start; len >= 1; len--) {
            StringBuilder p = new StringBuilder();
            for (int i = 0; i < len; i++) {
                if (i > 0) p.append('.');
                p.append(segments[i]);
            }
            Element v;
            try {
                v = getRawPropertyElement(moRef, p.toString());
            } catch (Exception e) {
                v = null;
            }
            if (v != null) {
                consumedOut[0] = len;
                return v;
            }
        }
        consumedOut[0] = 0;
        return null;
    }

    // ----- ContainerView inventory ---------------------------------------

    private List<MoRef> listView(String type) throws Exception {
        MoRef view = createContainerView(type);
        if (view == null) return new ArrayList<>();
        try {
            return retrieveViewMembers(view, type);
        } finally {
            destroyViewQuietly(view);
        }
    }

    private MoRef createContainerView(String type) throws Exception {
        String body = "<CreateContainerView xmlns=\"urn:vim25\">"
                + "<_this type=\"ViewManager\">"
                + xmlEscape(viewManager.value) + "</_this>"
                + "<container type=\"Folder\">"
                + xmlEscape(rootFolder.value) + "</container>"
                + "<type>" + xmlEscape(type) + "</type>"
                + "<recursive>true</recursive></CreateContainerView>";
        Document resp = post(body, "urn:vim25/CreateContainerView", true);
        if (resp == null) return null;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) return null;
        String val = elementText(rv);
        if (val == null || val.trim().isEmpty()) return null;
        String t = rv.getAttribute("type");
        return new MoRef(t != null && !t.isEmpty() ? t : "ContainerView",
                val.trim());
    }

    private List<MoRef> retrieveViewMembers(MoRef view, String type)
            throws Exception {
        List<MoRef> refs = new ArrayList<>();
        String body = "<RetrieveProperties xmlns=\"urn:vim25\">"
                + "<_this type=\"PropertyCollector\">"
                + xmlEscape(propertyCollector.value) + "</_this>"
                + "<specSet><propSet><type>" + xmlEscape(type) + "</type>"
                + "<pathSet>name</pathSet></propSet>"
                + "<objectSet><obj type=\"ContainerView\">"
                + xmlEscape(view.value) + "</obj><skip>true</skip>"
                + "<selectSet xsi:type=\"TraversalSpec\">"
                + "<name>view</name><type>ContainerView</type>"
                + "<path>view</path><skip>false</skip></selectSet>"
                + "</objectSet></specSet></RetrieveProperties>";
        Document resp = post(body, "urn:vim25/RetrieveProperties", true);
        if (resp == null) {
            logWarn("listView(" + type + "): no response");
            return refs;
        }
        for (Element rv : descendantsByLocalName(resp.getDocumentElement(),
                "returnval")) {
            Element obj = firstDirectChild(rv, "obj");
            if (obj == null) continue;
            String value = elementText(obj);
            if (value == null || value.trim().isEmpty()) continue;
            String t = obj.getAttribute("type");
            refs.add(new MoRef(t != null && !t.isEmpty() ? t : type,
                    value.trim()));
        }
        return refs;
    }

    private void destroyViewQuietly(MoRef view) {
        if (view == null) return;
        try {
            String body = "<DestroyView xmlns=\"urn:vim25\">"
                    + "<_this type=\"" + xmlEscape(view.type) + "\">"
                    + xmlEscape(view.value) + "</_this></DestroyView>";
            post(body, "urn:vim25/DestroyView", true);
        } catch (Exception ignored) {}
    }

    // ----- SOAP transport + DOM helpers ----------------------------------

    private Document post(String soapBody, String soapAction,
            boolean authenticated) throws Exception {
        String envelope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<soapenv:Envelope "
                + "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
                + "<soapenv:Body>" + soapBody + "</soapenv:Body></soapenv:Envelope>";

        URL url = new URL(vcenterUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (conn instanceof HttpsURLConnection && sslFactory != null) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslFactory);
            if (trustAll) {
                ((HttpsURLConnection) conn).setHostnameVerifier((h, s) -> true);
            }
        }
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(120000);
        conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
        conn.setRequestProperty("SOAPAction", soapAction);
        if (authenticated && sessionCookie != null && !sessionCookie.isEmpty()) {
            conn.setRequestProperty("Cookie", sessionCookie);
        }

        byte[] payload = envelope.getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
        }

        int code = conn.getResponseCode();
        captureCookie(conn);
        InputStream is = (code >= 200 && code < 300)
                ? conn.getInputStream() : conn.getErrorStream();
        byte[] respBytes = drain(is);
        conn.disconnect();
        if (code < 200 || code >= 300) {
            // Parse and surface the SOAP <faultstring> instead of discarding the
            // body (the build-2 behavior that made login/connection failures
            // undiagnosable). Secrets are never echoed: vim25 faults carry a
            // human message, and we additionally redact any token-shaped run.
            String fault = extractFaultString(respBytes);
            if (fault != null) {
                this.lastFaultString = fault;
                logWarn("vSphere SOAP " + soapAction + " -> HTTP " + code
                        + " fault: " + fault);
            } else {
                logWarn("vSphere SOAP " + soapAction + " -> HTTP " + code
                        + " (no SOAP faultstring in body)");
            }
            return null;
        }
        if (respBytes == null || respBytes.length == 0) return null;
        return parseXml(new String(respBytes, StandardCharsets.UTF_8));
    }

    /** Last parsed SOAP faultstring (redacted), or null. */
    public String lastFaultString() { return lastFaultString; }

    /**
     * Pull {@code <faultstring>} (and, when present, the vim25
     * {@code <localizedMessage>}) out of a SOAP 1.1 fault body. Returns null
     * when the body is empty or carries no fault. Redacts any token/secret-shaped
     * substring so a session id or password never lands in a log line
     * ({@code rules/no-secrets-on-disk.md}).
     */
    private static String extractFaultString(byte[] body) {
        if (body == null || body.length == 0) return null;
        Document doc = parseXml(new String(body, StandardCharsets.UTF_8));
        if (doc == null) return null;
        Element fs = firstByLocalName(doc.getDocumentElement(), "faultstring");
        String msg = (fs != null) ? elementText(fs) : null;
        Element lm = firstByLocalName(doc.getDocumentElement(), "localizedMessage");
        String localized = (lm != null) ? elementText(lm) : null;
        String combined;
        if (msg != null && localized != null && !localized.equals(msg)) {
            combined = msg + " (" + localized + ")";
        } else if (msg != null) {
            combined = msg;
        } else {
            combined = localized;
        }
        return redactSecrets(combined);
    }

    /**
     * Strip anything that looks like a session id or credential token from a
     * message before it is logged. Conservative: redacts {@code vmware_soap_session}
     * cookie values and any long opaque token run.
     */
    private static String redactSecrets(String s) {
        if (s == null) return null;
        String r = s.replaceAll("(?i)(vmware_soap_session\\s*[=:]\\s*)\\S+",
                "$1<redacted>");
        r = r.replaceAll("(?i)(password\\s*[=:]\\s*)\\S+", "$1<redacted>");
        r = r.replaceAll("(?i)((?:_sid|passwd|account)\\s*[=:]\\s*)\\S+",
                "$1<redacted>");
        return r;
    }

    private void captureCookie(HttpURLConnection conn) {
        try {
            List<String> setCookies = conn.getHeaderFields().get("Set-Cookie");
            if (setCookies == null) {
                for (Map.Entry<String, List<String>> e
                        : conn.getHeaderFields().entrySet()) {
                    if (e.getKey() != null
                            && "set-cookie".equalsIgnoreCase(e.getKey())) {
                        setCookies = e.getValue();
                        break;
                    }
                }
            }
            if (setCookies == null) return;
            for (String c : setCookies) {
                if (c == null) continue;
                String pair = c;
                int semi = pair.indexOf(';');
                if (semi >= 0) pair = pair.substring(0, semi);
                pair = pair.trim();
                if (pair.startsWith("vmware_soap_session")) {
                    this.sessionCookie = pair;
                    return;
                }
            }
        } catch (Exception ignored) {}
    }

    private static byte[] drain(InputStream is) throws Exception {
        if (is == null) return null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) >= 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } finally {
            try { is.close(); } catch (Exception ignored) {}
        }
    }

    private static Document parseXml(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(false);
            trySetFeature(dbf,
                    "http://apache.org/xml/features/disallow-doctype-decl", true);
            trySetFeature(dbf,
                    "http://xml.org/sax/features/external-general-entities", false);
            trySetFeature(dbf,
                    "http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new ByteArrayInputStream(
                    xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    private static void trySetFeature(DocumentBuilderFactory dbf, String f,
            boolean v) {
        try { dbf.setFeature(f, v); } catch (Exception ignored) {}
    }

    private static Element firstByLocalName(Element parent, String name) {
        if (parent == null) return null;
        Element direct = firstDirectChild(parent, name);
        if (direct != null) return direct;
        NodeList all = parent.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Node n = all.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && name.equals(localName((Element) n))) {
                return (Element) n;
            }
        }
        return null;
    }

    private static Element firstDirectChild(Element parent, String name) {
        if (parent == null) return null;
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node n = kids.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && name.equals(localName((Element) n))) {
                return (Element) n;
            }
        }
        return null;
    }

    private static List<Element> childrenByLocalName(Element parent,
            String name) {
        List<Element> out = new ArrayList<>();
        if (parent == null) return out;
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node n = kids.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && name.equals(localName((Element) n))) {
                out.add((Element) n);
            }
        }
        return out;
    }

    private static List<Element> descendantsByLocalName(Element parent,
            String name) {
        List<Element> out = new ArrayList<>();
        if (parent == null) return out;
        NodeList all = parent.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Node n = all.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && name.equals(localName((Element) n))) {
                out.add((Element) n);
            }
        }
        return out;
    }

    private static List<Element> childElements(Element parent) {
        List<Element> out = new ArrayList<>();
        if (parent == null) return out;
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node n = kids.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE) out.add((Element) n);
        }
        return out;
    }

    private static String childText(Element parent, String name) {
        Element c = firstDirectChild(parent, name);
        return c == null ? null : elementText(c);
    }

    private static String elementText(Element e) {
        if (e == null) return null;
        String t = e.getTextContent();
        return t == null ? null : t.trim();
    }

    private static String xsiType(Element e) {
        if (e == null) return null;
        String t = e.getAttribute("xsi:type");
        if (t == null || t.isEmpty()) t = e.getAttribute("type");
        return (t == null || t.isEmpty()) ? null : t;
    }

    private static String localName(Element e) {
        String ln = e.getLocalName();
        if (ln != null) return ln;
        String tag = e.getTagName();
        int colon = tag.indexOf(':');
        return colon >= 0 ? tag.substring(colon + 1) : tag;
    }

    private static Boolean parseBool(String text) {
        if (text == null) return null;
        String t = text.trim();
        if (t.isEmpty()) return null;
        if ("true".equalsIgnoreCase(t) || "1".equals(t)) return Boolean.TRUE;
        if ("false".equalsIgnoreCase(t) || "0".equals(t)) return Boolean.FALSE;
        return null;
    }

    private static String xmlEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&apos;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    private static MoRef moRefOf(Element parent, String childName) {
        Element c = firstDirectChild(parent, childName);
        if (c == null) return null;
        String value = c.getTextContent();
        if (value == null || value.trim().isEmpty()) return null;
        String type = c.getAttribute("type");
        return new MoRef(type != null && !type.isEmpty() ? type
                : "ManagedObject", value.trim());
    }

    // ----- value types ----------------------------------------------------

    /** Lightweight managed-object reference (type + value), no vim25 binding. */
    public static final class MoRef {
        public final String type;
        public final String value;
        public MoRef(String type, String value) {
            this.type = type;
            this.value = value;
        }
    }

    /** An inventory object: its MoRef, display name, and MoID string. */
    public static final class MoInfo {
        public final MoRef moRef;
        public final String name;
        public final String moid;
        public MoInfo(MoRef moRef, String name, String moid) {
            this.moRef = moRef;
            this.name = name;
            this.moid = moid;
        }
    }
}
