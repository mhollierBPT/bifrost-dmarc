# Live data contract

This matrix is the architectural delivery contract for Bifrost DMARC UI state. A workflow may perform a mutation, but a successful mutation must not require a broad dashboard query to make table-backed state current.

| Product surface | UI source of truth | Mutation boundary | Update behavior |
| --- | --- | --- | --- |
| Domain inventory, mappings, lifecycle, DNS posture | `dmarc_domains` live subscription | Workflows for Cloudflare sync, manual creation, mapping propagation, archive/restore, and guarded DNS writes | Table insert/update/delete events update every subscribing page |
| Organization counts and coverage | Bifrost Organization directory plus live `dmarc_domains` rows | Mapping workflows | Counts are derived in the client from current domain rows |
| Overview metrics and sending sources | `dmarc_daily_metrics` live subscription | Resend/synthetic ingestion workflows | Trends, totals, rates, and source rankings are derived from the selected live date window |
| Aggregate Reports | `dmarc_reports` live subscription | Resend/synthetic ingestion workflows | New provider reports appear without a manual refresh |
| Authentication issues and report drilldown | `dmarc_records` live subscription | Resend/synthetic ingestion workflows | Aggregate result combinations appear and update live |
| Inbound health and shell status | `dmarc_ingest_events` live subscription | Resend inbound workflow | Accepted, ignored, and failed deliveries update live |
| Email Investigation | `dmarc_investigations` live subscription | Investigation issue/upload/inbound workflows | Waiting, processing, completed, failed, and expired states update live |
| SPF migration inventory | `dmarc_spf_sources` live subscription | Import and future guarded source-management workflows | Sender inventory changes update Migration immediately |
| DNS change history | `dmarc_dns_changes` live subscription | Guarded Cloudflare write workflow | Pending/completed/failed audit state updates live |
| Reporting-domain and signing-secret status | Thin `get_app_context` workflow | Encrypted configuration workflow | Explicit context refresh only after configuration changes |
| Bifrost Organization directory | Thin `get_app_context` workflow | Bifrost platform organization management | Loaded as non-table context; no DMARC table payload is duplicated |

## Mutation rules

- Use direct Tables subscriptions for all table-backed reads.
- Keep workflows for external integrations, secrets, security validation, and multi-table coordination.
- Do not call `get_dashboard` or reload the route after a table-backed mutation.
- Use one bulk workflow request for a multi-row operator action; do not loop workflow calls in the browser.
- Derive page summaries from the same subscribed rows used by their detail views, avoiding stale summary/detail splits.
- Surface table subscription failures separately from mutation failures; reconnects restore the loaded table window.

## Coverage limits

The app drains the paged Tables SDK into a subscribed in-memory window in 1,000-row pages. Date-bounded metrics, reports, and result combinations are filtered at the table query before paging. The live model preserves the previous 5,000-report and 10,000-record display caps after sorting so the existing product contract remains bounded.
