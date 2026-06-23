package com.vcfcf.adapters.vcommunity;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Central configuration-file store reader — the pure-rewrite of the original
 * {@code get_config_file_data} path (adapter.py ~line 261).
 *
 * <p>The original stores the six check-list XMLs CENTRALLY in the VCF Ops
 * configuration-file store and fetches each by name via the Suite API every
 * collection cycle:
 * {@code GET api/configurations/files?path=SolutionConfig/<name>.xml}. The
 * adapter-instance identifiers hold file NAMES only. This class reproduces that
 * exactly, fetching through the framework's existing Suite API channel
 * ({@link SuiteApiStitcher#get}) — the same authenticated, SDK-injected
 * connection {@link VCommunityStitcher} uses, so it works from a remote
 * collector / cloud proxy with no localhost assumption.
 *
 * <p><b>Cardinal correctness rule (design Config §, "never silently collect
 * with empty check lists").</b> A transient fetch failure (or the first-cycle
 * null Suite API client) degrades to the PREVIOUS cycle's last-good parsed list
 * — never to an empty list that would silently zero a gated collector. On the
 * very first cycle with no cached value and an unreachable store, the gated
 * collection is SKIPPED for that cycle (the caller checks
 * {@link FetchResult#usable}); the next cycle catches up. Every fetch failure
 * is logged at WARN and recorded so {@code test()} and the
 * {@code vCommunityWorld} anchor can surface it as a degradation notice.
 *
 * <p>The XML parse mirrors the original: the root element's text is split on
 * commas and each entry trimmed. Comments are ignored by the DOM parser, so a
 * shipped default file with everything commented out yields an empty list BY
 * DESIGN — that is an empty list from a successfully-read file (usable=true),
 * distinct from a failed fetch (usable=false).
 *
 * <p>The Windows event-log file is special: the {@code .ps1} consumes the XML
 * body verbatim (it parses {@code <Events><Log>} itself in-guest), so
 * {@link #fetchRawXml(SuiteApiStitcher, String)} returns the unparsed text.
 */
public final class SolutionConfigStore {

    private final Logger log;

    // Last-good parsed check lists, keyed by file NAME. Survives across cycles
    // within one collector process; lost on restart (honest first-cycle skip).
    private final Map<String, List<String>> lastGoodLists =
            new LinkedHashMap<>();
    // Last-good raw XML bodies (windows event file), keyed by file NAME.
    private final Map<String, String> lastGoodRaw = new LinkedHashMap<>();

    // Per-cycle diagnostics, rebuilt each refresh: NAME -> human status string.
    private final Map<String, String> lastStatus = new LinkedHashMap<>();

    public SolutionConfigStore(Logger log) {
        this.log = log;
    }

    /** Result of one check-list fetch+parse. */
    public static final class FetchResult {
        /** True when a usable list is available (fresh read OR last-good cache). */
        public final boolean usable;
        /** True when the list came from cache (previous cycle), not this cycle. */
        public final boolean stale;
        public final List<String> items;
        public final String status;   // diagnostic for test()/world anchor

        FetchResult(boolean usable, boolean stale, List<String> items,
                String status) {
            this.usable = usable;
            this.stale = stale;
            this.items = items != null ? items : Collections.emptyList();
            this.status = status;
        }
    }

    /**
     * Fetch and parse a named check-list file (comma-delimited body).
     *
     * @param stitcher the Suite API channel (may be null on first cycle)
     * @param fileName central-store file NAME (no path, no {@code .xml})
     */
    public FetchResult fetchList(SuiteApiStitcher stitcher, String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return new FetchResult(false, false, null,
                    fileName + ": no file name configured");
        }
        if (stitcher == null) {
            return degradeList(fileName,
                    "Suite API client unavailable (first cycle / no maintenance "
                    + "credentials)");
        }
        String body;
        try {
            body = stitcher.get("/api/configurations/files?path=SolutionConfig/"
                    + enc(fileName) + ".xml");
        } catch (Exception e) {
            return degradeList(fileName,
                    "fetch failed: " + e.getClass().getSimpleName() + ": "
                    + e.getMessage());
        }
        if (body == null || body.trim().isEmpty()) {
            return degradeList(fileName, "central store returned empty/absent file");
        }
        List<String> parsed;
        try {
            parsed = parseCommaList(body);
        } catch (Exception e) {
            return degradeList(fileName,
                    "XML parse failed: " + e.getMessage());
        }
        // Successful read (even an all-commented-out file → empty list = usable).
        lastGoodLists.put(fileName, parsed);
        String status = fileName + ": " + parsed.size() + " check(s)";
        lastStatus.put(fileName, status);
        return new FetchResult(true, false, parsed, status);
    }

    /**
     * Fetch the raw XML body of a named file (windows event list — consumed
     * verbatim by the guest {@code .ps1}). Same degradation discipline.
     *
     * @return the raw XML text, or {@code null} when neither a fresh read nor a
     *         last-good cache is available (caller skips event collection).
     */
    public String fetchRawXml(SuiteApiStitcher stitcher, String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            lastStatus.put("" + fileName, fileName + ": no file name configured");
            return null;
        }
        if (stitcher == null) {
            return degradeRaw(fileName,
                    "Suite API client unavailable (first cycle)");
        }
        String body;
        try {
            body = stitcher.get("/api/configurations/files?path=SolutionConfig/"
                    + enc(fileName) + ".xml");
        } catch (Exception e) {
            return degradeRaw(fileName,
                    "fetch failed: " + e.getClass().getSimpleName());
        }
        if (body == null || body.trim().isEmpty()) {
            return degradeRaw(fileName, "central store returned empty/absent file");
        }
        lastGoodRaw.put(fileName, body);
        lastStatus.put(fileName, fileName + ": fetched (" + body.length()
                + " bytes)");
        return body;
    }

    private FetchResult degradeList(String fileName, String reason) {
        List<String> cached = lastGoodLists.get(fileName);
        if (cached != null) {
            String status = fileName + ": " + reason
                    + " — using last-good (" + cached.size() + " check(s))";
            warn(status);
            lastStatus.put(fileName, status);
            return new FetchResult(true, true, cached, status);
        }
        String status = fileName + ": " + reason
                + " — no last-good cache; SKIPPING gated collection this cycle";
        warn(status);
        lastStatus.put(fileName, status);
        return new FetchResult(false, false, null, status);
    }

    private String degradeRaw(String fileName, String reason) {
        String cached = lastGoodRaw.get(fileName);
        if (cached != null) {
            String status = fileName + ": " + reason + " — using last-good XML";
            warn(status);
            lastStatus.put(fileName, status);
            return cached;
        }
        String status = fileName + ": " + reason
                + " — no last-good; SKIPPING event collection this cycle";
        warn(status);
        lastStatus.put(fileName, status);
        return null;
    }

    /** Per-cycle per-file diagnostics for the {@code vCommunityWorld} anchor. */
    public Map<String, String> lastStatus() {
        return new LinkedHashMap<>(lastStatus);
    }

    // -- parsing -----------------------------------------------------------

    /**
     * Parse the root element's text content, split on commas, trim. Mirrors
     * the original {@code parsedResponse.text.strip().split(',')} +
     * {@code line.strip()} loop. Empty / whitespace-only entries are dropped.
     */
    static List<String> parseCommaList(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        trySetFeature(dbf,
                "http://apache.org/xml/features/disallow-doctype-decl", true);
        trySetFeature(dbf,
                "http://xml.org/sax/features/external-general-entities", false);
        trySetFeature(dbf,
                "http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(
                xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getDocumentElement();
        String text = root == null ? "" : root.getTextContent();
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        for (String part : text.split(",")) {
            String t = part.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private static void trySetFeature(DocumentBuilderFactory dbf, String f,
            boolean v) {
        try { dbf.setFeature(f, v); } catch (Exception ignored) {}
    }

    private static String enc(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private void warn(String msg) {
        if (log != null) log.warn("SolutionConfigStore: " + msg);
    }
}
