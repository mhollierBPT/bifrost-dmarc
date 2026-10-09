# Bifrost DMARC

Bifrost DMARC is a distributable Bifrost Solution for multi-organization DMARC reporting, Email Investigation, and guarded DMARC/SPF management through Cloudflare.

## What is included

- Overview dashboard with policy posture, DNS coverage, message-volume/compliance trends, top sending sources, and ingest health.
- Searchable Bifrost Organizations mapped to a cached Cloudflare domain inventory, including explicit unmapped state and manual Cloudflare-account overrides. Table-backed changes appear live without reloading the inventory.
- Real-time Resend inbound handling for aggregate reports and time-limited investigation addresses.
- Safe XML, gzip, and single-report zip parsing; report and event deduplication; provider-level aggregate storage.
- Aggregate, authentication-issue, and inbound-activity reports with search, source filters, nested sending-source drilldown, and CSV export.
- Email Investigation using a generated 24-hour address or an uploaded EML.
- Plain-language DMARC and SPF builders with live Cloudflare checks, validation, duplicate-record refusal, guarded writeback, manual-DNS fallback, and audit history.
- A nightly Cloudflare inventory review that refreshes each domain's last-checked state.
- Nightly 60-day retention for detailed report, investigation, event, and DNS-audit data.

The full replacement contract and intentional exclusions are in [docs/feature-parity.md](docs/feature-parity.md).

## Storage model

DMARC aggregate XML already groups messages by a result combination. Bifrost stores one provider report row plus its aggregate `record` elements; it does not insert one row per email. Message volume is the sum of each record's `count`. The included fixture represents 6,000 messages with two aggregate rows.

The parser rejects XML entities and document types, limits decompressed reports to 20 MB, and accepts XML, gzip, or a zip containing exactly one XML report. Email Investigation returns authentication metadata and findings, not message content.

## Live data architecture

The app reads DMARC domains, daily metrics, reports, aggregate result combinations, inbound events, investigations, SPF sources, and DNS audit history through live Bifrost Tables subscriptions. Pages derive their current summaries from those rows, so a workflow mutation does not trigger a full dashboard reload.

Workflows remain the mutation boundary when an operation validates business rules, touches Cloudflare or Resend, uses encrypted configuration, or coordinates several tables. Their table writes are the events that update the subscribed UI. The only workflow query used as page context returns non-table setup state and the visible Bifrost Organization directory; it is refreshed explicitly only after non-table configuration changes.

Bulk archive is one workflow invocation for the selected IDs, not one request per row. The workflow retains per-domain validation and result reporting while each resulting table update appears live.

The complete read/mutation contract is documented in [docs/live-data-contract.md](docs/live-data-contract.md).

## Install and connect

Select the intended Bifrost instance and organization, then install from Git so Bifrost retains the repository as the Solution source:

```bash
bifrost solution install-repo https://github.com/gobifrost/bifrost-dmarc.git --ref main
```

The selected instance must support the trusted webhook `raw_body_base64` handoff added by [Bifrost PR #945](https://github.com/gobifrost/bifrost/pull/945). Existing instances need that platform update before enabling signed ingestion.

1. Install or deploy the Solution.
2. Add intended operators to the **DMARC Users** role. The app, every workflow, the agent, and table access all require this role.
3. Set `dmarc_reporting_domain` to the installation's Resend inbound domain, such as `dmarc.example.com`.
4. Configure the Solution's `CloudFlare` and `Resend` connections with their required secret `api_key` values.
5. Configure inbound email for that domain in Resend.
6. Open the Solution-managed **DMARC Inbound** event source and copy its callback URL.
7. Create a Resend webhook for `email.received` using that callback URL.
8. In Settings, choose **Import signing secret from Resend**. The workflow finds the enabled `email.received` Bifrost webhook and stores its `whsec_…` value encrypted without displaying it. The secret can also be entered manually as `resend_signing_secret`.
9. In the app, upload the included aggregate fixture, create an Email Investigation, and use the Cloudflare refresh action in Domains.

### Access customization

The default **DMARC Users** role keeps every interactive surface aligned. Add intended operators to that role before use. To customize the role, replace its name consistently in the app, workflow, and agent `role_names` fields and in the `has_role` table-policy expressions, then deploy the Solution. Platform administrators retain the explicit table-policy bypass.

Resend accepts any recipient at a configured inbound domain. The workflow retrieves the supplied email ID through the authenticated Resend connection and then routes only:

- `rua@<dmarc_reporting_domain>` for aggregate reports; or
- an unexpired `investigate+<token>@<dmarc_reporting_domain>` issued by the app.

Everything else is recorded as ignored. Event/email IDs are deduplicated.

## Webhook signature boundary

Resend/Svix signs `message-id.timestamp.raw-body`. Bifrost DMARC verifies the signature against the trusted `raw_body_base64` handoff, evaluates the five-minute timestamp window against the trusted webhook receipt time, compares signatures in constant time, and deduplicates events. Re-serializing parsed JSON is intentionally refused because even harmless formatting changes invalidate the signature.

`resend_signing_secret` is optional during initial setup. Once configured, every inbound event must include a valid trusted raw-body handoff and signature; missing or invalid bytes are rejected before any table or Resend API call. Recipient allow-listing, authenticated Resend email retrieval, attachment validation, rate limiting, and deduplication remain defense in depth.

## Reporting-domain authorization

For `dmarc.example.com`, publish this record in the `example.com` zone:

```text
*._report._dmarc.dmarc.example.com TXT "v=DMARC1;"
```

The wildcard authorizes other domains to send aggregate reports to the external destination. The Settings page derives the exact name from `dmarc_reporting_domain`.

## Managed DNS safeguards

The Domains page can create or update the single DMARC TXT record and the single apex SPF TXT record for a cached Cloudflare zone. It will not proceed when duplicate DMARC or SPF records exist. Every managed value is automatically compared with live Cloudflare state before writeback; the domain comes from the selected inventory row rather than user input. Previous/new values and outcomes are written to the DNS audit table. A nightly review refreshes every accessible zone, while opening a domain refreshes only that domain's comparison. The inventory prefers canonical Cloudflare account-to-Bifrost Organization mappings from the integration, then matches primary domains and punctuation-insensitive unique account names. Operators can override either one domain or every cached domain in a Cloudflare account; explicit overrides remain authoritative.

A Cloudflare refresh does not delete domains that disappear from the accessible zone inventory. It clears the stale zone link and flags the retained row as orphaned so an operator can review it. The Domains page can filter mapped, unmapped, orphaned, and archived inventory; active rows support multi-selection for bulk archive. Archive removes a domain from active dashboards without deleting retained reports, SPF sources, or DNS audit history, and archived domains can be restored later.

The same inventory refresh runs public DNS-provider discovery and authoritative registration checks for domains outside accessible Cloudflare accounts. Missing nameservers alone never trigger archive. Bifrost selects the domain's registry through IANA's RDAP bootstrap data and automatically archives only an exact domain that the authoritative registry confirms is not registered. Registered domains without DNS, subdomains of registered parents, unsupported registries, rate limits, and lookup failures remain visible review states. Auto-archived rows are labeled **Unregistered**, retain their history, and can be reviewed or restored from the Domains page.

If a domain is not linked to Cloudflare, the same builders validate and show the exact TXT value, provide a copy action, and explain that Cloudflare must be linked for one-click updates. If the live record is already identical, the comparison says **DNS Is Up to Date** and offers no update action.

`reconcile_cloudflare_integration_mappings` can promote cached matches into the Cloudflare integration. It defaults to dry-run and only proposes an account when every cached zone in that account maps to the same organization, the organization maps to exactly one Cloudflare account, and no existing integration mapping disagrees.

The SPF builder presents common sender types in plain language, counts direct DNS-triggering terms, and refuses more than 10. Nested `include` records can add lookups that static analysis cannot see, so Bifrost does not falsely claim to flatten provider records. It manages the customer's Cloudflare TXT record directly and does not operate an authoritative hosted SPF-flattening/CNAME service.

## Migration ledger

The Migration page is an exception-first cutover workspace. Imported domains and SPF sources are stored as ordinary rows in `dmarc_domains` and `dmarc_spf_sources`; the deployed Solution contains no EasyDMARC client, session capture, or vendor-specific runtime migration path. The ledger reconciles those rows against live Cloudflare zones and Bifrost Organizations, then identifies domains that are ready, unmapped, missing from accessible Cloudflare accounts, or missing approved sender inventory.

Selecting a domain shows the imported sender mechanisms, observed message volume, capability notes, and automatic DMARC/SPF comparisons. Linked zones can be updated through the existing guarded Cloudflare write path. Missing zones receive copyable manual records until the account is connected or the domain is removed from scope. The tables update live through the Bifrost SDK; Cloudflare reconciliation remains an explicit or scheduled workflow because it reads external state.

## Local verification

```bash
python3 -m pytest -q
cd apps/bifrost-dmarc
npm run typecheck
npm test -- --run
npm run build
```
