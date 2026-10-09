# Bifrost DMARC cutover

## Ready before switching domains

- Install Bifrost DMARC, configure `dmarc_reporting_domain`, and import `resend_signing_secret` from the connected Resend webhook in Settings.
- Connect Resend and Cloudflare using least-privilege credentials.
- Point the Resend `email.received` webhook at the Solution-managed **DMARC Inbound** callback.
- Confirm the reporting-domain MX and wildcard external-report authorization TXT record resolve publicly.
- Run Cloudflare sync and review automatic primary-domain/account-name matches plus the remaining unmapped list.
- Upload the sample aggregate report twice: the first run must add its message counts and the replay must add zero.
- Create an Email Investigation address and complete one real inbound test.

## Pilot cutover

- Select one monitored domain and keep its existing enforcement policy unchanged.
- Add `mailto:rua@<dmarc_reporting_domain>` as a second `rua` destination while retaining the existing EasyDMARC destination. Keep EasyDMARC first during the comparison window. Until the Bifrost builder has an explicit overlap mode, make this pilot change directly in Cloudflare; its current managed preview intentionally replaces the `rua` value.
- Wait up to 48 hours for the first aggregate report; the Overview shows reporting-domain count and each domain's last report time.
- Compare total message volume, compliance, sources, and failure combinations with EasyDMARC for the same UTC report window.
- After at least seven days of matching coverage, remove only the EasyDMARC `rua` destination. Preserve `p`, `sp`, `adkim`, `aspf`, and other policy tags.

## Remove EasySPF dependencies before cancellation

- Inventory every SPF record containing `_d.easydmarc.pro`; these records depend on EasyDMARC continuing to publish the hosted SPF target.
- For each sending domain, identify the durable provider-owned includes or IP ranges behind its configured EasySPF sources. Do not replace a dynamic hosted record with a one-time flattened IP snapshot unless an owner accepts the maintenance risk.
- Build the replacement in Bifrost, review the automatic DNS comparison, preserve the existing terminal policy (`~all` or `-all`), and confirm the effective SPF lookup count stays within the protocol limit.
- Migrate low-risk domains in small batches, verify real sending sources continue to pass, and retain a before/after record in the DNS audit history.
- Do not cancel the EasyDMARC service until no production SPF record refers to `easydmarc.pro` and DNS has propagated.

## Expand and retire EasyDMARC

- Migrate DMARC destinations in batches while preserving `p`, `sp`, `adkim`, `aspf`, and any intentionally retained DMARC tags.
- Do not remove an EasyDMARC destination until Bifrost has received reports for that domain across the agreed comparison window.
- Run retention in dry-run mode, review candidate counts, then leave the nightly 60-day schedule enabled.
- Export EasyDMARC CSV/PDF history required for audit or reference before cancellation. Keep it as an archive by default; build a separately provenance-marked API backfill only if continuous historical charts are required.

## Inbound signature verification

The generic Bifrost adapter supplies the exact received bytes as trusted
`raw_body_base64` together with its receipt time. After configuring
`resend_signing_secret`, Bifrost DMARC rejects inbound events that lack that
handoff or fail Resend/Svix verification before any table or Resend API call.
Review rejected-webhook monitoring before enabling production inbound traffic.
