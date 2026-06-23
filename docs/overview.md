# Overview — VCF Content Factory Example Adapter

> **TEMPLATE** — this is the curated prose page of the standard SDK docset.
> It is generated once as a scaffold and then hand-curated; the generator
> never overwrites it again. When you instantiate a pak, **replace the
> placeholder prose below** with real content for your target system. The
> guidance in each section tells you what to write. Keep the section
> structure — it matches the curated overviews shipped by the production
> adapters (`compliance`, `synology`, `unifi`).

## What's in the Pack

> Describe, in a sentence or two: what system this pack monitors, how the
> adapter reaches it (which API / protocol / port), and what an operator
> gets in VCF Operations. Keep it factual — no marketing.

VCF Content Factory Example Adapter is a Tier 2 (Java SDK) management pack
skeleton. It discovers one `ExampleResource` kind under a `World` traversal
anchor via collect-path discovery and pushes one metric and one property
per resource. Replace this paragraph — and the resource kinds, endpoints,
and metric keys it describes — with your target system.

### Resource kinds

> List the resource kinds this pack owns, with their keys and a one-line
> purpose each. The table below is a worked example; regenerate
> `inventory-tree.md` for the authoritative kinds + identifying keys.

| Kind | Key | What it represents |
|------|-----|--------------------|
| Example World | `World` | Aggregation root (singleton per instance). |
| Example Resource | `ExampleResource` | The one example object kind — replace with yours. |

### Metrics scope

> Summarize the metric/property surface (a count and the highlights).
> Point to `REFERENCE.md` for the authoritative, generated list — do not
> hand-maintain the full table here.

See `REFERENCE.md` for the authoritative metric and property list.

## Cross-Adapter Behavior

> If your adapter stitches onto resources owned by another adapter,
> document it here. Otherwise delete this section. Be specific about:
> the foreign adapter kind and resource kind, how you resolve the foreign
> resource (identity key — never a guessed MOID), the transport (ambient
> Suite API), and the failure posture (skip-and-WARN when the Suite API is
> unavailable; collection never fails over an optional cross-link).
>
> Worked examples from the production adapters:
> - **compliance** — ARIA_OPS-style push onto VMWARE HostSystem (by MOID)
>   and the vCenter object (by `VCURL` / `VMEntityVCID`), over the ambient
>   Suite API.
> - **synology** — informational cross-link making iSCSI LUNs / NFS exports
>   children of the VMWARE Datastore they back, resolved by path identity.
> - **unifi** — optional LLDP cross-link attaching switch ports to the
>   VMWARE HostSystem on the other end of the link.

The example adapter has no cross-adapter stitching.

## Notable Behaviors

> Call out behaviors an operator should understand before relying on the
> pack. At minimum, document the load-bearing framework idioms this pack
> inherits:
>
> - **Unreadable is never flattered.** A value the adapter could not read
>   is surfaced as ERROR / no-data, never published as a `0.0` or sentinel
>   that masquerades as healthy. This is the cardinal correctness rule.
> - **Secrets are redacted** from all logs and error messages
>   (session tokens, passwords, credential-bearing URLs).
> - **Fresh-instance discovery works on VCF Ops 9.0.2.** The adapter
>   enumerates on the collect path (`discoverOnCollect()`), so a freshly
>   created instance populates on its first collection cycle rather than
>   waiting on an `onDiscover()` the platform may never call.

## Known Limitations

> List real gaps, caveats, and out-of-scope items (e.g. read-only, no
> remediation; features that require an optional API or component).

- This is a skeleton, not a working integration.
