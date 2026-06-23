package com.vcfcf.adapters.vcommunity;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapters.vcommunity.VCommunityVSphereClient.MoRef;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Windows guest-ops over vim25 {@code GuestOperationsManager} — native Java port
 * of the original three guest collectors ({@code vmService.py},
 * {@code vmOSInformation.py}, {@code collect_windows_event_logs.py}).
 *
 * <p>Mechanism (mirrors the original step-for-step):
 * <ol>
 *   <li>{@code CreateTemporaryDirectory} under {@code C:\Windows\Temp}.</li>
 *   <li>{@code InitiateFileTransferToGuest} → HTTP PUT the {@code .ps1} bytes
 *       (and, for events, the central event-list XML body verbatim).</li>
 *   <li>{@code StartProgram} powershell with the per-collector command, then
 *       poll {@code ListProcessesInGuest} until {@code exitCode != null}.</li>
 *   <li>{@code InitiateFileTransferFromGuest} → HTTP GET the CSV output.</li>
 *   <li>{@code finally} {@code DeleteDirectoryInGuest(recursive)}.</li>
 * </ol>
 *
 * <p><b>Crash-the-cycle isolation (binding — design Failure isolation §).</b>
 * Every public collector method is wrapped so any exception (timeout, auth
 * failure, tools absent, PUT/GET failure) is caught, logged at WARN, and an
 * empty result returned. A single unreachable or mis-credentialed guest must
 * NEVER abort the collection cycle or the push for other VMs/hosts/clusters —
 * that isolation is enforced here AND again per-VM in {@link VmCollector}.
 *
 * <p>HTTP transfers use the SOAP {@link SSLSocketFactory} the adapter selected
 * (platform trust by default; {@code allowInsecure} lab opt-out) — the vCenter
 * file-transfer URL presents the same cert the SOAP endpoint does.
 */
public final class GuestOpsClient {

    private static final String SYSTEM_ROOT = "C:\\Windows";
    private static final String TEMP_DIR = SYSTEM_ROOT + "\\Temp";
    private static final String POWERSHELL =
            SYSTEM_ROOT + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    private static final String DIR_PREFIX = "VCFOperationsvCommunity-";

    private final String vcenterUrl;        // https://<host[:port]>/sdk
    private final String sessionCookie;     // active vim25 session cookie
    private final SSLSocketFactory sslFactory;
    private final boolean trustAll;
    private final String winUser;
    private final String winPassword;       // REDACT-SECRET
    private final Logger log;

    private volatile MoRef guestFileManager;
    private volatile MoRef guestProcessManager;

    /**
     * Last guest-ops SOAP fault captured this client's lifetime (build 10).
     * Set whenever {@link #post} sees a non-2xx response carrying a SOAP
     * {@code <faultstring>}; shaped {@code "<operation> -> <faultClass> (<msg>)"}.
     * Diagnostic-only — never read by the collection logic, only surfaced on the
     * world anchor by {@link VmCollector}. Cleared per-VM via {@link #clearLastFault}
     * so each VM's recorded error reflects that VM's own cycle.
     */
    private volatile String lastFault;

    /**
     * Name of the VM whose guest-ops calls are currently in flight, for fault
     * attribution in {@link #post} (build 10). Set by each public collector
     * entry point; diagnostic-only.
     */
    private volatile String currentVmName;

    public GuestOpsClient(String vcenterUrl, String sessionCookie,
            SSLSocketFactory sslFactory, boolean trustAll,
            MoRef guestFileManager, MoRef guestProcessManager,
            String winUser, String winPassword, Logger log) {
        this.vcenterUrl = vcenterUrl;
        this.sessionCookie = sessionCookie;
        this.sslFactory = sslFactory;
        this.trustAll = trustAll;
        this.guestFileManager = guestFileManager;
        this.guestProcessManager = guestProcessManager;
        this.winUser = winUser;
        this.winPassword = winPassword;     // REDACT-SECRET
        this.log = log;
    }

    private void logInfo(String m) { if (log != null) log.info(m); }
    private void logWarn(String m) { if (log != null) log.warn(m); }

    public boolean ready() {
        return guestFileManager != null && guestProcessManager != null
                && winUser != null && !winUser.isEmpty();
    }

    /**
     * Human-readable {@link #ready()} outcome for the world-anchor diagnostics
     * (build 9). Returns {@code "true"} when ready, else
     * {@code "false (<first failing precondition>)"} naming the exact leg that
     * blocked — guestFileManager null / guestProcessManager null / winUser empty.
     * Behavior-neutral: pure observation of the same predicate {@link #ready()}
     * evaluates, evaluated in the same order.
     */
    public String readyReason() {
        if (guestFileManager == null) return "false (guestFileManager=null)";
        if (guestProcessManager == null) return "false (guestProcessManager=null)";
        if (winUser == null || winUser.isEmpty()) return "false (winUser=empty)";
        return "true";
    }

    /**
     * Last guest-ops SOAP fault captured (build 10), or {@code null} if no fault
     * was seen since the last {@link #clearLastFault}. Shaped
     * {@code "<operation> -> <faultClass> (<message>)"} — operation/fault-class/
     * message only, never any credential material. Diagnostic-only; the
     * collection path never branches on it.
     */
    public String lastFault() { return lastFault; }

    /** Reset the captured fault before a VM's guest-ops calls (build 10). */
    public void clearLastFault() { this.lastFault = null; }

    // =====================================================================
    // Service collector
    // =====================================================================

    /** One Windows service row from the guest CSV. */
    public static final class ServiceRow {
        public final String name, displayName, status, startType;
        public ServiceRow(String name, String displayName, String status,
                String startType) {
            this.name = name;
            this.displayName = displayName;
            this.status = status;
            this.startType = startType;
        }
    }

    /**
     * Run {@code getWindowsServices.ps1} with the configured service names and
     * parse the CSV. Returns an empty list (never throws) on any failure.
     */
    public List<ServiceRow> collectServices(MoRef vm, String vmName,
            byte[] scriptBytes, List<String> serviceNames) {
        List<ServiceRow> out = new ArrayList<>();
        String tempDir = null;
        this.currentVmName = vmName;
        try {
            tempDir = createTempDir(vm, "-Services-TEMP");
            if (tempDir == null) return out;
            String script = "getWindowsServices.ps1";
            if (!putFile(vm, tempDir + "\\" + script, scriptBytes)) return out;

            StringBuilder list = new StringBuilder("@(");
            for (int i = 0; i < serviceNames.size(); i++) {
                if (i > 0) list.append(", ");
                list.append("'").append(psEscape(serviceNames.get(i))).append("'");
            }
            list.append(")");
            String command = "& '" + tempDir + "\\" + script + "' " + list
                    + " | Export-Csv -Path '" + tempDir
                    + "\\Services.csv' -NoTypeInformation -Encoding UTF8";
            if (!runPowershell(vm, vmName, command)) return out;

            String csv = getFile(vm, tempDir + "\\Services.csv");
            if (csv == null || csv.trim().isEmpty()) return out;

            List<String[]> rows = parseCsv(csv);
            if (rows.isEmpty()) return out;
            String[] header = rows.get(0);
            int ni = idx(header, "Name");
            int di = idx(header, "DisplayName");
            int si = idx(header, "Status");
            int ti = idx(header, "StartType");
            if (ni < 0 || di < 0 || si < 0 || ti < 0) return out;
            for (int r = 1; r < rows.size(); r++) {
                String[] c = rows.get(r);
                if (max4(ni, di, si, ti) >= c.length) continue;
                out.add(new ServiceRow(c[ni], c[di], c[si], c[ti]));
            }
        } catch (Exception e) {
            logWarn("guest-ops services on '" + vmName + "' failed (isolated, "
                    + "cycle continues): " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        } finally {
            deleteDirQuietly(vm, tempDir);
        }
        return out;
    }

    // =====================================================================
    // OS information collector
    // =====================================================================

    /** OS info row from the guest CSV. */
    public static final class OsInfoRow {
        public final String name, version, buildNumber, architecture,
                lastBootUpTime, releaseId;
        public OsInfoRow(String name, String version, String buildNumber,
                String architecture, String lastBootUpTime, String releaseId) {
            this.name = name;
            this.version = version;
            this.buildNumber = buildNumber;
            this.architecture = architecture;
            this.lastBootUpTime = lastBootUpTime;
            this.releaseId = releaseId;
        }
    }

    /** Run {@code getWindowsOSInformation.ps1}. Empty on any failure. */
    public OsInfoRow collectOsInfo(MoRef vm, String vmName, byte[] scriptBytes) {
        String tempDir = null;
        this.currentVmName = vmName;
        try {
            tempDir = createTempDir(vm, "-OSInfo-TEMP");
            if (tempDir == null) return null;
            String script = "getWindowsOSInformation.ps1";
            if (!putFile(vm, tempDir + "\\" + script, scriptBytes)) return null;
            String command = "& '" + tempDir + "\\" + script
                    + "' | Export-Csv -Path '" + tempDir
                    + "\\OSInfo.csv' -NoTypeInformation -Encoding UTF8";
            if (!runPowershell(vm, vmName, command)) return null;
            String csv = getFile(vm, tempDir + "\\OSInfo.csv");
            if (csv == null || csv.trim().isEmpty()) return null;
            List<String[]> rows = parseCsv(csv);
            if (rows.size() < 2) return null;
            String[] h = rows.get(0);
            String[] c = rows.get(1);
            return new OsInfoRow(
                    cell(c, idx(h, "Name")),
                    cell(c, idx(h, "Version")),
                    cell(c, idx(h, "BuildNumber")),
                    cell(c, idx(h, "OSArchitecture")),
                    cell(c, idx(h, "LastBootUpTime")),
                    cell(c, idx(h, "ReleaseId")));
        } catch (Exception e) {
            logWarn("guest-ops OS-info on '" + vmName + "' failed (isolated): "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            return null;
        } finally {
            deleteDirQuietly(vm, tempDir);
        }
    }

    // =====================================================================
    // Event-log collector
    // =====================================================================

    /** One Windows event from the guest CSV. */
    public static final class EventRow {
        public final String level, message;
        public EventRow(String level, String message) {
            this.level = level;
            this.message = message;
        }
    }

    /**
     * Run {@code getWindowsEventLogs.ps1} with the central event-list XML body.
     * The XML is written verbatim into the guest as a temp file and passed to
     * the script (it parses {@code <Events><Log>} itself). Empty on any failure.
     */
    public List<EventRow> collectEvents(MoRef vm, String vmName,
            byte[] scriptBytes, String eventListXml) {
        List<EventRow> out = new ArrayList<>();
        String tempDir = null;
        this.currentVmName = vmName;
        try {
            tempDir = createTempDir(vm, "-EventLog-TEMP");
            if (tempDir == null) return out;
            String xmlPath = tempDir + "\\events.xml";
            if (!putFile(vm, xmlPath,
                    eventListXml.getBytes(StandardCharsets.UTF_8))) {
                return out;
            }
            String script = "getWindowsEventLogs.ps1";
            if (!putFile(vm, tempDir + "\\" + script, scriptBytes)) return out;
            String command = "& '" + tempDir + "\\" + script + "' '" + xmlPath
                    + "' | Export-Csv -Path '" + tempDir
                    + "\\Event_Log.csv' -NoTypeInformation -Encoding UTF8";
            if (!runPowershell(vm, vmName, command)) return out;
            String csv = getFile(vm, tempDir + "\\Event_Log.csv");
            if (csv == null || csv.trim().isEmpty()) return out;
            List<String[]> rows = parseCsv(csv);
            if (rows.isEmpty()) return out;
            String[] h = rows.get(0);
            int li = idx(h, "Level");
            int ei = idx(h, "Event");
            if (li < 0 || ei < 0) return out;
            for (int r = 1; r < rows.size(); r++) {
                String[] c = rows.get(r);
                if (Math.max(li, ei) >= c.length) continue;
                out.add(new EventRow(c[li], c[ei]));
            }
        } catch (Exception e) {
            logWarn("guest-ops event-log on '" + vmName + "' failed (isolated): "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            deleteDirQuietly(vm, tempDir);
        }
        return out;
    }

    // =====================================================================
    // vim25 guest-ops SOAP primitives
    // =====================================================================

    private String createTempDir(MoRef vm, String suffix) throws Exception {
        String body = "<CreateTemporaryDirectoryInGuest xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(guestFileManager.type) + "\">"
                + xmlEscape(guestFileManager.value) + "</_this>"
                + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                + xmlEscape(vm.value) + "</vm>"
                + auth()
                + "<prefix>" + xmlEscape(DIR_PREFIX) + "</prefix>"
                + "<suffix>" + xmlEscape(suffix) + "</suffix>"
                + "<directoryPath>" + xmlEscape(TEMP_DIR) + "</directoryPath>"
                + "</CreateTemporaryDirectoryInGuest>";
        Document resp = post(body, "urn:vim25/CreateTemporaryDirectoryInGuest");
        if (resp == null) return null;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        return rv == null ? null : elementText(rv);
    }

    private boolean putFile(MoRef vm, String guestPath, byte[] data)
            throws Exception {
        String body = "<InitiateFileTransferToGuest xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(guestFileManager.type) + "\">"
                + xmlEscape(guestFileManager.value) + "</_this>"
                + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                + xmlEscape(vm.value) + "</vm>"
                + auth()
                + "<guestFilePath>" + xmlEscape(guestPath) + "</guestFilePath>"
                + "<fileAttributes></fileAttributes>"
                + "<fileSize>" + data.length + "</fileSize>"
                + "<overwrite>true</overwrite>"
                + "</InitiateFileTransferToGuest>";
        Document resp = post(body, "urn:vim25/InitiateFileTransferToGuest");
        if (resp == null) return false;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        String url = rv == null ? null : elementText(rv);
        if (url == null || url.isEmpty()) return false;
        return httpPut(url, data);
    }

    private String getFile(MoRef vm, String guestPath) throws Exception {
        String body = "<InitiateFileTransferFromGuest xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(guestFileManager.type) + "\">"
                + xmlEscape(guestFileManager.value) + "</_this>"
                + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                + xmlEscape(vm.value) + "</vm>"
                + auth()
                + "<guestFilePath>" + xmlEscape(guestPath) + "</guestFilePath>"
                + "</InitiateFileTransferFromGuest>";
        Document resp = post(body, "urn:vim25/InitiateFileTransferFromGuest");
        if (resp == null) return null;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) return null;
        String url = childText(rv, "url");
        if (url == null || url.isEmpty()) return null;
        return httpGet(url);
    }

    private boolean runPowershell(MoRef vm, String vmName, String command)
            throws Exception {
        String args = "-Command \"" + command + "\"";
        String body = "<StartProgramInGuest xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(guestProcessManager.type) + "\">"
                + xmlEscape(guestProcessManager.value) + "</_this>"
                + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                + xmlEscape(vm.value) + "</vm>"
                + auth()
                + "<spec>"
                + "<programPath>" + xmlEscape(POWERSHELL) + "</programPath>"
                + "<arguments>" + xmlEscape(args) + "</arguments>"
                + "</spec></StartProgramInGuest>";
        Document resp = post(body, "urn:vim25/StartProgramInGuest");
        if (resp == null) return false;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        String pidStr = rv == null ? null : elementText(rv);
        if (pidStr == null) return false;
        long pid;
        try { pid = Long.parseLong(pidStr.trim()); }
        catch (NumberFormatException e) { return false; }
        if (pid <= 0) return false;
        logInfo("guest-ops: started PID " + pid + " on '" + vmName + "'");

        // Poll ListProcessesInGuest until exitCode is present (bounded).
        for (int attempt = 0; attempt < 60; attempt++) {
            Integer exit = processExitCode(vm, pid);
            if (exit != null) {
                logInfo("guest-ops: PID " + pid + " on '" + vmName
                        + "' exited " + exit);
                return true;
            }
            Thread.sleep(2000);
        }
        logWarn("guest-ops: PID " + pid + " on '" + vmName + "' did not exit "
                + "within timeout — skipping output");
        return false;
    }

    private Integer processExitCode(MoRef vm, long pid) throws Exception {
        String body = "<ListProcessesInGuest xmlns=\"urn:vim25\">"
                + "<_this type=\"" + xmlEscape(guestProcessManager.type) + "\">"
                + xmlEscape(guestProcessManager.value) + "</_this>"
                + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                + xmlEscape(vm.value) + "</vm>"
                + auth()
                + "<pids>" + pid + "</pids>"
                + "</ListProcessesInGuest>";
        Document resp = post(body, "urn:vim25/ListProcessesInGuest");
        if (resp == null) return null;
        Element rv = firstByLocalName(resp.getDocumentElement(), "returnval");
        if (rv == null) return null;
        String exit = childText(rv, "exitCode");
        if (exit == null || exit.isEmpty()) return null;
        try { return Integer.parseInt(exit.trim()); }
        catch (NumberFormatException e) { return null; }
    }

    private void deleteDirQuietly(MoRef vm, String dir) {
        if (dir == null || guestFileManager == null) return;
        try {
            String body = "<DeleteDirectoryInGuest xmlns=\"urn:vim25\">"
                    + "<_this type=\"" + xmlEscape(guestFileManager.type) + "\">"
                    + xmlEscape(guestFileManager.value) + "</_this>"
                    + "<vm type=\"" + xmlEscape(vm.type) + "\">"
                    + xmlEscape(vm.value) + "</vm>"
                    + auth()
                    + "<directoryPath>" + xmlEscape(dir) + "</directoryPath>"
                    + "<recursive>true</recursive>"
                    + "</DeleteDirectoryInGuest>";
            post(body, "urn:vim25/DeleteDirectoryInGuest");
        } catch (Exception ignored) {}
    }

    private String auth() {
        // NamePasswordAuthentication, xsi:type-tagged. interactiveSession=false.
        return "<auth xsi:type=\"NamePasswordAuthentication\">"
                + "<interactiveSession>false</interactiveSession>"
                + "<username>" + xmlEscape(winUser) + "</username>"
                + "<password>" + xmlEscape(winPassword) + "</password>"  // REDACT-SECRET
                + "</auth>";
    }

    // =====================================================================
    // SOAP + HTTP transport
    // =====================================================================

    private Document post(String soapBody, String soapAction) throws Exception {
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
        if (sessionCookie != null && !sessionCookie.isEmpty()) {
            conn.setRequestProperty("Cookie", sessionCookie);
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(envelope.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300)
                ? conn.getInputStream() : conn.getErrorStream();
        byte[] resp = drain(is);
        conn.disconnect();
        if (code < 200 || code >= 300) {
            // Build 10 (observability-only): a guest-ops fault comes back as
            // HTTP 500 + a SOAP fault body. Prior builds discarded it silently
            // (`return null`), so the fault was logged NOWHERE — the collector
            // returned empty and the per-VM catch never fired (nothing threw).
            // Mirror VCommunityVSphereClient.post()'s faultstring extraction so
            // the exact vim25 fault is named at WARN and captured for the world
            // anchor. Return value is UNCHANGED (still null): collection
            // behavior is identical — this only makes the swallowed fault visible.
            String op = operationName(soapAction);
            String fault = extractFaultString(resp);
            String vm = currentVmName != null ? currentVmName : "?";
            if (fault != null) {
                this.lastFault = op + " -> " + fault;
                logWarn("guest-ops SOAP " + op + " on '" + vm + "' -> HTTP "
                        + code + " fault: " + fault);
            } else {
                this.lastFault = op + " -> HTTP " + code
                        + " (no SOAP faultstring in body)";
                logWarn("guest-ops SOAP " + op + " on '" + vm + "' -> HTTP "
                        + code + " (no SOAP faultstring in body)");
            }
            return null;
        }
        if (resp == null || resp.length == 0) return null;
        return parseXml(new String(resp, StandardCharsets.UTF_8));
    }

    /** {@code "urn:vim25/StartProgramInGuest"} -> {@code "StartProgramInGuest"}. */
    private static String operationName(String soapAction) {
        if (soapAction == null) return "?";
        int slash = soapAction.lastIndexOf('/');
        return slash >= 0 ? soapAction.substring(slash + 1) : soapAction;
    }

    /**
     * Pull the SOAP 1.1 {@code <faultstring>} (and, when present, the vim25 fault
     * subtype via {@code <localizedMessage>}) out of a fault body (build 10).
     * Mirrors {@link VCommunityVSphereClient}'s extractor. Returns null when the
     * body is empty or carries no fault. Redacts any credential/token-shaped run
     * so a session id or password never lands in a log line or anchor property.
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
     * Strip anything resembling a session id or credential token before it is
     * logged or surfaced on the anchor (build 10). Conservative, mirrors
     * {@link VCommunityVSphereClient}. The fault message carries operation/
     * fault-class text only; this is belt-and-braces so no secret can leak.
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

    private boolean httpPut(String urlStr, byte[] data) throws Exception {
        HttpURLConnection conn = openTransfer(urlStr, "PUT");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setFixedLengthStreamingMode(data.length);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(data);
        }
        int code = conn.getResponseCode();
        conn.disconnect();
        return code >= 200 && code < 300;
    }

    private String httpGet(String urlStr) throws Exception {
        HttpURLConnection conn = openTransfer(urlStr, "GET");
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300)
                ? conn.getInputStream() : conn.getErrorStream();
        byte[] body = drain(is);
        conn.disconnect();
        if (code < 200 || code >= 300) return null;
        return body == null ? null : new String(body, StandardCharsets.UTF_8);
    }

    private HttpURLConnection openTransfer(String urlStr, String method)
            throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (conn instanceof HttpsURLConnection && sslFactory != null) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslFactory);
            if (trustAll) {
                ((HttpsURLConnection) conn).setHostnameVerifier((h, s) -> true);
            }
        }
        conn.setRequestMethod(method);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(120000);
        return conn;
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

    // =====================================================================
    // CSV + DOM helpers
    // =====================================================================

    /**
     * Minimal RFC-4180-ish CSV parser: handles double-quoted fields with
     * embedded commas and "" escapes. The PowerShell {@code Export-Csv} output
     * is quoted, so this strips quotes correctly.
     */
    static List<String[]> parseCsv(String csv) {
        List<String[]> rows = new ArrayList<>();
        for (String line : csv.split("\r\n|\n|\r")) {
            if (line.isEmpty()) continue;
            List<String> fields = new ArrayList<>();
            StringBuilder cur = new StringBuilder();
            boolean inQuotes = false;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (inQuotes) {
                    if (c == '"') {
                        if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                            cur.append('"');
                            i++;
                        } else {
                            inQuotes = false;
                        }
                    } else {
                        cur.append(c);
                    }
                } else {
                    if (c == '"') {
                        inQuotes = true;
                    } else if (c == ',') {
                        fields.add(cur.toString());
                        cur.setLength(0);
                    } else {
                        cur.append(c);
                    }
                }
            }
            fields.add(cur.toString());
            rows.add(fields.toArray(new String[0]));
        }
        return rows;
    }

    private static int idx(String[] header, String name) {
        for (int i = 0; i < header.length; i++) {
            if (name.equals(header[i].trim())) return i;
        }
        return -1;
    }

    private static String cell(String[] row, int i) {
        return (i >= 0 && i < row.length) ? row[i] : null;
    }

    private static int max4(int a, int b, int c, int d) {
        return Math.max(Math.max(a, b), Math.max(c, d));
    }

    private static String psEscape(String s) {
        // single-quoted PowerShell string: double any single quote.
        return s == null ? "" : s.replace("'", "''");
    }

    private static Document parseXml(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(false);
            try { dbf.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl",
                    true); } catch (Exception ignored) {}
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new ByteArrayInputStream(
                    xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    private static Element firstByLocalName(Element parent, String name) {
        if (parent == null) return null;
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

    private static String childText(Element parent, String name) {
        if (parent == null) return null;
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node n = kids.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && name.equals(localName((Element) n))) {
                return elementText((Element) n);
            }
        }
        return null;
    }

    private static String elementText(Element e) {
        if (e == null) return null;
        String t = e.getTextContent();
        return t == null ? null : t.trim();
    }

    private static String localName(Element e) {
        String ln = e.getLocalName();
        if (ln != null) return ln;
        String tag = e.getTagName();
        int colon = tag.indexOf(':');
        return colon >= 0 ? tag.substring(colon + 1) : tag;
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
}
