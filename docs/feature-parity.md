# Bifrost DMARC feature parity

This matrix is the delivery contract for replacing the EasyDMARC capabilities discussed during discovery. A row is only marked complete after current-run evidence exists against the deployed Solution.

| Capability | EasyDMARC reference | Bifrost DMARC target | Status |
|---|---|---|---|
| Real-time aggregate ingestion | Aggregate Reports | Resend `email.received` event, attachment retrieval, safe XML/gzip/zip parsing, deduplication | Implemented; live integration proven |
| Inbound routing and abuse controls | Managed report mailbox | Accept only `rua@<reporting-domain>` and issued investigation addresses; validate the Resend email ID through the API; record ignored/failed deliveries | Implemented; unit-tested and real RUA path proven |
| Webhook signature verification | Vendor-managed | Verify Resend/Svix signature over the exact raw HTTP body | Implemented with trusted adapter raw-body and receipt-time handoff |
| Retention | Vendor retention | Scheduled deletion of detailed report, metric, ingest, investigation, and audit data after 60 days | Implemented; destructive live expiry test reserved for acceptance |
| Overview dashboard | Dashboard screenshot | Policy distribution, DNS state, volume/compliance trend, top sources, ingest health | Implemented and live-verified |
| Organizations and domains | Domains and Groups screenshot | Searchable, clickable Organization/domain inventory; canonical mappings plus manual per-domain or whole-account overrides; explicit unmapped domains | Implemented, tested, and live-verified with the Van Rooy Restoration override |
| Aggregate report detail | Aggregate Reports screenshot | Provider report list plus nested sending-source/result-combination drilldown, SPF/DKIM, source IP, disposition | Implemented; live data contract and rendered drawer verified |
| Failure visibility | Failure Reports screenshot | Aggregate non-compliant combinations with honest message counts | Implemented and live-verified; these are not individual messages |
| Forensic/RUF reports | Failure Reports screenshot with From/To/Subject | Optional ARF/RUF ingestion if a receiver sends it | Not promised: RUF is uncommon, privacy-sensitive, and cannot be reconstructed from RUA data |
| Email Investigation: inbound test | Email Investigation screenshot | Issue a time-limited address, receive through Resend, analyze receiver authentication headers | Address issuance live-verified; real-message completion awaits acceptance send |
| Email Investigation: EML upload | Email Investigation screenshot | Upload and analyze an EML without treating header claims as a fresh cryptographic verification | Implemented and live-verified |
| DMARC builder | Managed DMARC | Validate settings, preserve safe tags, ensure Bifrost RUA destination, automatically compare the exact TXT value | Implemented and live-verified |
| DMARC Cloudflare writeback | Managed DMARC | Guarded create/update of the single `_dmarc` TXT record plus audit history and cache refresh | Implemented; mutation safety tests pass, live write reserved for acceptance |
| SPF source builder | EasySPF screenshot | Plain-language sender builder, validate syntax and the static DNS-lookup budget, automatic comparison with clear no-change/manual states | Implemented and tested |
| SPF Cloudflare writeback | EasySPF screenshot | Guarded create/update of the single apex SPF TXT record plus audit history and cache refresh | Implemented; mutation safety tests pass, live write reserved for acceptance |
| Hosted SPF flattening/CNAME | EasySPF hosted record | Direct Cloudflare record management instead of operating an authoritative hosted-flattening service | Replaced by a safer Solution-owned capability |
| Geolocation | Aggregate Reports by Geolocation | Map source IPs to geography | Excluded until an IP-intelligence integration and its data-retention terms are selected |
| CSV export and filters | Report toolbar | Searchable organization/domain/report inventories, domain/source drilldown filters, inbound activity, and client-side CSV export | Implemented and frontend-tested |
| TLS, BIMI, reputation monitoring | Other EasyDMARC modules | Separate products, not required for the requested DMARC/SPF replacement | Excluded |

## Acceptance criteria

- A real report to `rua@<reporting-domain>` is visible in the dashboard once and only once.
- Mail to an unrecognized recipient is recorded as ignored and never parsed as a DMARC report.
- A generated investigation address transitions from waiting to analyzed after a real message is received.
- An EML upload produces a clear header-based authentication analysis and limitations notice.
- Cloudflare inventory shows mapped and unmapped domains from the cached table.
- DMARC/SPF changes use an automatic live comparison and explicit apply action, reject duplicate records, and create an audit row.
- Report filters and CSV export operate on provider-aggregated rows; every displayed count is labeled as messages rather than emails stored.
- Retention removes expired detailed data without deleting domain mappings or DNS inventory.
