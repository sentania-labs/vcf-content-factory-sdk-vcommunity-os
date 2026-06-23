# Installing & Configuring — VCF Content Factory Example Adapter

> **TEMPLATE** — this is the curated prose page of the standard SDK docset.
> It is generated once as a scaffold and then hand-curated; the generator
> never overwrites it again. When you instantiate a pak, **replace the
> placeholder prose below** with the real prerequisites, permissions,
> ports, and TLS guidance for your target system. Keep the **Configuration
> Fields** table — it is regenerated from `describe.xml` and should reflect
> your real config fields. Keep the section structure.

## Prerequisites

> List what must be true before install: the supported VCF Operations
> versions, the target-system version/edition, network reachability (which
> host/port), and the account the adapter authenticates with.

- VCF Operations 8.x or 9.x (collect-path discovery is validated on
  9.0.2).
- Reachability from the VCF Operations collector to the target system on
  its API port.
- An account on the target system with read access to the data this pack
  collects.

## Permissions Required

> State the minimum privileges the adapter credential account needs.
> Prefer least-privilege: the adapter should read only. Name the specific
> API areas / roles required.

The example adapter requires only read access to its (fictional) API.

## Network Requirements

> One row per outbound flow the collector must be able to make. Replace the
> port/purpose with your real endpoint(s).

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 443  | HTTPS    | Collector → target system | API reads |

> If your adapter stitches over the ambient local Suite API, note that it
> requires no additional outbound configuration.

## TLS — certificate trust

> Document how the adapter handles the target certificate: strict
> validation against the platform trust store by default, with
> `allowInsecure=true` as the documented opt-out. Tell the operator their
> two options (import the cert, or set `allowInsecure=true`). If your target
> commonly ships a self-signed cert, say so.

By default the adapter validates the target certificate against the
platform trust store. Set `allowInsecure=true` to disable validation, or
import the target certificate into the trust store.

## Configuration Fields

When adding a new adapter instance in VCF Operations, you will be prompted
for the fields below. This table is generated from `describe.xml` — keep it
in sync with your real config fields (regenerate the docset after changing
`describe.xml`), and add prose notes per field.

| Field | Key | Required | Default | Notes |
|-------|-----|----------|---------|-------|
| Host / IP Address | `host` | Yes | — | Target hostname or IP. |
| Port (HTTPS) | `port` | No | — | API port. |
| Allow Insecure SSL | `allowInsecure` | No | — | `true` disables certificate validation. |

## Step-by-Step Installation

1. Install the `.pak` file via **Administration > Solutions > Add**.
2. After installation, navigate to **Data Sources > Integrations > Accounts**.
3. Click **Add Account** and select **VCF Content Factory Example Adapter**.
4. Fill in the configuration fields above.
5. Click **Validate Connection**, then **Add**.
6. The adapter discovers resources and begins collecting on the next cycle.

## Troubleshooting

> List the common, expected failure modes and their remedies (TLS trust,
> auth/session, no-data ERROR semantics, optional cross-link omission).

- **Test Connection fails on TLS** — the target certificate is untrusted.
  Set `allowInsecure=true` or import the certificate.
