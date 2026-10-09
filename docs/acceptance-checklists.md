# Bifrost DMARC acceptance checklist

Use this checklist for each installation. Record environment-specific URLs,
install identifiers, credentials, and release evidence in the installation's
private runbook, not this portable repository.

## Administrator setup

- [ ] Install the Solution into a non-production organization first.
- [ ] Add intended operators to the **DMARC Users** role.
- [ ] Set `dmarc_reporting_domain` and configure the required secret `api_key`
  for both CloudFlare and Resend connections.
- [ ] Configure the Resend `email.received` webhook with the Solution-managed
  **DMARC Inbound** callback URL.
- [ ] Confirm an operator with **DMARC Users** can open the app, invoke its
  workflows, use the agent, and read and update the required tables.
- [ ] Confirm a signed-in user without **DMARC Users** is denied those surfaces.

## Functional acceptance

- [ ] Refresh Cloudflare inventory and review mapped, unmapped, orphaned, and
  archived domains.
- [ ] Upload `fixtures/sample-report.xml`; replay it and confirm deduplication
  leaves message volume unchanged.
- [ ] Create an Email Investigation and verify that the resulting analysis does
  not expose the original message body.
- [ ] Compare and apply a no-risk DMARC or SPF change in a disposable zone;
  confirm Cloudflare readback and the DNS audit history agree.
- [ ] Change the test record outside Bifrost after comparison; confirm Apply
  aborts without overwriting the newer DNS value.
- [ ] Test loading, empty, error, and permission-denied states in the app.

## Promotion

- [ ] Review the current webhook-signature capability and its deployment
  guidance before enabling production inbound traffic.
- [ ] Record the approved version, installation scope, validation evidence, and
  rollback procedure in the environment's private runbook.
