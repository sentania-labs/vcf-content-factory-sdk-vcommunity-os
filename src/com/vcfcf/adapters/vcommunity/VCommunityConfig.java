package com.vcfcf.adapters.vcommunity;

/**
 * Typed configuration POJO for the vCommunity adapter — a native Java SDK
 * rewrite of {@code vmbro/VCF-Operations-vCommunity} (Onur Yuzseven,
 * CC-licensed).
 *
 * <p>Populated from the adapter-instance {@code ResourceConfig} in
 * {@link VCommunityAdapter#configureAdapter}. Immutable: every field is
 * {@code final} and set once.
 *
 * <p><b>Credential redaction.</b> {@link #password} and {@link #winPassword}
 * are secrets. They are read here and consumed only by the vim25 SOAP login
 * ({@link VCommunityVSphereClient}) and the guest-ops authentication
 * ({@link GuestOpsClient}). They MUST NOT appear in any log line, exception
 * message, or URL. Search this repo for {@code // REDACT-SECRET}.
 *
 * <p>The two {@code win*ConfigFile} fields hold the NAMES (no path, no
 * {@code .xml}) of the Windows check-list files in the VCF Ops central
 * configuration-file store under {@code SolutionConfig/}. Defaults match the
 * bundled file base names — see {@link SolutionConfigStore} and design §4.
 */
public final class VCommunityConfig {

    /** Windows guest-ops monitoring mode (adapter-instance enum). */
    public enum WindowsMonitoring {
        DISABLED, SERVICES, EVENT_LOGS, SERVICES_AND_EVENT_LOGS;

        /**
         * Derive the mode from the prod original's TWO separate describe.xml
         * enums — "Guest OS Service Monitoring Status" ({@code serviceMonitoring})
         * and "Windows Event Log Monitoring Status" ({@code winEventMonitoring}),
         * each the verbatim "Enabled"/"Disabled" display string. Only the literal
         * "Enabled" (case-insensitive) turns a gate on; anything else — Disabled,
         * null, blank, or garbage — leaves it off. An unreadable value is never
         * folded into "on".
         */
        static WindowsMonitoring from(String serviceMonitoringRaw,
                                      String winEventMonitoringRaw) {
            boolean services = isEnabled(serviceMonitoringRaw);
            boolean eventLogs = isEnabled(winEventMonitoringRaw);
            if (services && eventLogs) return SERVICES_AND_EVENT_LOGS;
            if (services)             return SERVICES;
            if (eventLogs)            return EVENT_LOGS;
            return DISABLED;
        }

        private static boolean isEnabled(String raw) {
            return raw != null && "Enabled".equalsIgnoreCase(raw.trim());
        }

        public boolean services() {
            return this == SERVICES || this == SERVICES_AND_EVENT_LOGS;
        }

        public boolean eventLogs() {
            return this == EVENT_LOGS || this == SERVICES_AND_EVENT_LOGS;
        }
    }

    public final String vcenterHost;
    public final int port;
    public final String username;
    public final String password;          // REDACT-SECRET
    public final String winUser;
    public final String winPassword;       // REDACT-SECRET
    public final WindowsMonitoring windowsMonitoring;
    public final boolean allowInsecure;

    // Central config-store file NAMES (no path / no extension). The OS pak ships
    // and fetches only the two Windows check-lists; the four vSphere config
    // files belong to the vcommunity-vsphere pak (design §4).
    public final String winServiceConfigFile;
    public final String winEventConfigFile;

    public VCommunityConfig(
            String vcenterHost, String port, String username, String password,
            String winUser, String winPassword,
            String serviceMonitoring, String winEventMonitoring,
            String allowInsecure,
            String winServiceConfigFile, String winEventConfigFile) {
        this.vcenterHost = nonBlank(vcenterHost, "localhost");
        this.port = parsePort(port);
        this.username = username != null ? username : "";
        this.password = password != null ? password : "";   // REDACT-SECRET
        this.winUser = winUser != null ? winUser.trim() : "";
        this.winPassword = winPassword != null ? winPassword : ""; // REDACT-SECRET
        this.windowsMonitoring =
                WindowsMonitoring.from(serviceMonitoring, winEventMonitoring);
        // Strict-by-default: only the literal "true" opts into trust-all.
        this.allowInsecure = "true".equalsIgnoreCase(allowInsecure);

        this.winServiceConfigFile =
                nonBlank(winServiceConfigFile, "windows_service_list");
        this.winEventConfigFile =
                nonBlank(winEventConfigFile, "windows_event_list");
    }

    /** Whether a Windows Guest Credential is present (guest-ops can run). */
    public boolean hasWindowsCredential() {
        return winUser != null && !winUser.isEmpty();
    }

    /** vCenter /sdk endpoint host (port carried separately for the URL). */
    public String soapHostPort() {
        return port == 443 ? vcenterHost : vcenterHost + ":" + port;
    }

    private static String nonBlank(String s, String dflt) {
        return (s != null && !s.trim().isEmpty()) ? s.trim() : dflt;
    }

    private static int parsePort(String p) {
        if (p == null || p.trim().isEmpty()) return 443;
        try {
            int v = Integer.parseInt(p.trim());
            return (v > 0 && v <= 65535) ? v : 443;
        } catch (NumberFormatException e) {
            return 443;
        }
    }
}
