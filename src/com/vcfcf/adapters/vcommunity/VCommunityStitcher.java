package com.vcfcf.adapters.vcommunity;

import com.integrien.alive.common.adapter3.Logger;
import com.vcfcf.adapter.json.SimpleJson;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves foreign VMWARE resource UUIDs via the framework
 * {@link SuiteApiStitcher} and pushes {@code vCommunity|...} properties / stats
 * onto them. This is the same proven mechanism the compliance adapter uses
 * (the reference implementation); scoped here to the three kinds vCommunity
 * stitches onto: {@code ClusterComputeResource} / {@code HostSystem} /
 * {@code VirtualMachine}.
 *
 * <p><b>Identity rule (the MOID trap — vCenter-scoped).</b> Every vim25-backed
 * VMWARE kind resolves by {@code VMEntityObjectID} (the vim {@code _moId} — the
 * original join key {@code hosts_by_uuid[host._moId]}) then {@code VMEntityName}
 * with dot-prefix FQDN/shortname tolerance. <b>But a bare MOID like
 * {@code host-12} is NOT unique across vCenters</b> — in a multi-vCenter VCF Ops
 * the {@code /api/resources} load returns every vCenter's {@code host-12}. The
 * original Python avoided this by scoping its query to the single vCenter it
 * monitored ({@code collectHostData.py:40}, by adapterInstanceId); the
 * bare-MOID matcher inherited from the compliance reference dropped that scope
 * (a known corpus-wide item — sdk-adapter-reviewer, vcommunity build 1). This
 * stitcher restores it: every loaded foreign resource is filtered to the OWNING
 * vCenter by its {@code VMEntityVCID} (vCenter Instance UUID) when that UUID is
 * known, so a MOID/name match can only land on a resource belonging to the
 * vCenter this adapter instance monitors. When the owning UUID is unknown (not
 * yet resolved, or a row with no {@code VMEntityVCID}) the resource is still
 * indexed — degrade to the unscoped behaviour rather than drop it. Single-vCenter
 * deployments are unaffected either way.
 *
 * <p><b>Foreign topology is never touched</b> ({@code setrelationships-foreign
 * -adapter-scoped}). The adapter pushes only properties/stats; it emits no
 * relationships onto VMWARE resources.
 */
public final class VCommunityStitcher {

    private final SuiteApiStitcher stitcher;
    private final Logger logger;

    private final Map<String, Map<String, Entry>> byName = new HashMap<>();
    private final Map<String, Map<String, Entry>> byMoid = new HashMap<>();

    // The vCenter Instance UUID this adapter instance monitors. When set, the
    // loaders keep only foreign resources whose VMEntityVCID matches it, so a
    // bare MOID can never resolve to a same-MOID resource in another vCenter.
    private volatile String owningVcUuid;

    public VCommunityStitcher(SuiteApiStitcher stitcher, Logger logger) {
        this.stitcher = stitcher;
        this.logger = logger;
    }

    /**
     * Pin the owning vCenter Instance UUID (from
     * {@code VCommunityVSphereClient.getVCenterInstanceUuid()}). Call once per
     * cycle BEFORE the {@code load*} calls. A null/blank value disables scoping
     * (degrades to the unscoped matcher — single-vCenter safe).
     */
    public void setOwningVcUuid(String vcUuid) {
        this.owningVcUuid = (vcUuid != null && !vcUuid.isEmpty()) ? vcUuid : null;
    }

    public void loadClusterResources() { load("ClusterComputeResource"); }
    public void loadHostResources()    { load("HostSystem"); }
    public void loadVmResources()      { load("VirtualMachine"); }

    public Entry matchCluster(String name, String moid) {
        return match("ClusterComputeResource", name, moid);
    }
    public Entry matchHost(String name, String moid) {
        return match("HostSystem", name, moid);
    }
    public Entry matchVm(String name, String moid) {
        return match("VirtualMachine", name, moid);
    }

    public int countOfKind(String kind) {
        Map<String, Entry> m = byName.get(kind);
        return m == null ? 0 : m.size();
    }

    public void pushProperties(String resourceId,
            Map<String, String> properties, long ts) {
        if (properties == null || properties.isEmpty()) return;
        stitcher.pushProperties(resourceId, properties, ts);
    }

    public void pushStats(String resourceId,
            Map<String, Double> stats, long ts) {
        if (stats == null || stats.isEmpty()) return;
        stitcher.pushStats(resourceId, stats, ts);
    }

    // -- loading -----------------------------------------------------------

    private void load(String resourceKind) {
        Map<String, Entry> name = new HashMap<>();
        Map<String, Entry> moid = new HashMap<>();
        byName.put(resourceKind, name);
        byMoid.put(resourceKind, moid);

        List<SimpleJson> resources = fetchResources(resourceKind);
        if (resources.isEmpty()) {
            logger.warn("VCommunityStitcher: /api/resources(" + resourceKind
                    + ") returned 0 results — this resource kind may not be "
                    + "present in inventory");
            return;
        }
        int skippedForeignVc = 0;
        for (SimpleJson r : resources) {
            String uuid = findUuid(r);
            SimpleJson key = r.get("resourceKey");
            String n = getIdValue(key, "VMEntityName");
            String m = getIdValue(key, "VMEntityObjectID");
            String vcUuid = getIdValue(key, "VMEntityVCID");

            // vCenter scoping (the MOID-trap fix): when this instance's owning
            // vCenter UUID is known AND the resource carries a VMEntityVCID that
            // does NOT match it, the resource belongs to a DIFFERENT vCenter —
            // skip it so a bare MOID cannot resolve across vCenters. A resource
            // with no VMEntityVCID is kept (degrade to unscoped — never drop a
            // resource we cannot disambiguate).
            if (owningVcUuid != null && vcUuid != null && !vcUuid.isEmpty()
                    && !owningVcUuid.equals(vcUuid)) {
                skippedForeignVc++;
                continue;
            }

            String resourceId = uuid != null ? uuid : n;
            if (resourceId == null) continue;
            Entry e = new Entry(resourceId, n, m);
            if (n != null && !n.isEmpty()) name.put(n, e);
            if (m != null && !m.isEmpty()) moid.put(m, e);
        }
        logger.info("VCommunityStitcher: loaded " + name.size() + " "
                + resourceKind + " by name, " + moid.size() + " by MOID"
                + (owningVcUuid != null
                        ? " (scoped to vCenter " + owningVcUuid + "; skipped "
                          + skippedForeignVc + " from other vCenters)"
                        : " (unscoped — owning vCenter UUID unknown)"));
    }

    private List<SimpleJson> fetchResources(String resourceKind) {
        java.util.List<SimpleJson> out = new java.util.ArrayList<>();
        try {
            String enc = java.net.URLEncoder.encode(resourceKind, "UTF-8");
            String body = stitcher.get(
                    "/api/resources?adapterKind=VMWARE&resourceKind=" + enc
                    + "&pageSize=10000");
            SimpleJson parsed = SimpleJson.parse(body);
            if (parsed == null || parsed.isNull()) return out;
            SimpleJson list = parsed.get("resourceList");
            if (list == null || !list.isList()) return out;
            for (SimpleJson r : list.asList()) {
                if (r != null && !r.isNull()) out.add(r);
            }
        } catch (Exception e) {
            logger.warn("VCommunityStitcher: fetchResources(" + resourceKind
                    + ") failed: " + e.getClass().getName() + ": "
                    + e.getMessage());
        }
        return out;
    }

    private Entry match(String resourceKind, String name, String moid) {
        Map<String, Entry> bm = byMoid.get(resourceKind);
        Map<String, Entry> bn = byName.get(resourceKind);

        // moid first (authoritative — the original join key).
        if (moid != null && bm != null) {
            Entry m = bm.get(moid);
            if (m != null) return m;
        }
        if (name != null && bn != null) {
            Entry n = bn.get(name);
            if (n != null) return n;
            for (Map.Entry<String, Entry> e : bn.entrySet()) {
                String reg = e.getKey();
                if (reg.startsWith(name + ".") || name.startsWith(reg + ".")) {
                    return e.getValue();
                }
            }
        }
        logger.warn("VCommunityStitcher: no " + resourceKind + " match for "
                + name + " (moid=" + moid + ")");
        return null;
    }

    private String findUuid(SimpleJson resource) {
        if (resource == null) return null;
        String s = resource.get("identifier").asString(null);
        return (s == null || s.isEmpty()) ? null : s;
    }

    private static String getIdValue(SimpleJson key, String name) {
        if (key == null || key.isNull()) return null;
        SimpleJson ids = key.get("resourceIdentifiers");
        if (ids == null || !ids.isList()) return null;
        for (SimpleJson id : ids.asList()) {
            String idName = id.get("identifierType").get("name").asString(null);
            if (name.equals(idName)) {
                return id.get("value").asString(null);
            }
        }
        return null;
    }

    /** Resolved foreign-resource handle: UUID push target + diagnostic name/moid. */
    public static final class Entry {
        public final String resourceId;
        public final String name;
        public final String moid;

        public Entry(String resourceId, String name, String moid) {
            this.resourceId = resourceId;
            this.name = name;
            this.moid = moid;
        }
    }
}
