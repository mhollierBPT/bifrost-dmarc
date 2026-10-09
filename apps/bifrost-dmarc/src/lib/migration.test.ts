import { describe, expect, it } from "vitest";

import type { DomainSummary } from "../types";
import { classifyDomainMigration, summarizeMissingDmarcReadiness } from "./migration";

const base: DomainSummary = {
  id: "domain-1",
  domain: "example.com",
  organization_id: "org-1",
  organization_name: "Example",
  mapping_status: "mapped",
  mapping_source: "manual",
  cloudflare_zone_id: "zone-1",
  dmarc_policy: "none",
  dmarc_record: "v=DMARC1; p=none; pct=100; adkim=r; aspf=r;",
  dmarc_pct: 100,
  rua: "mailto:old@example.net",
  has_dmarc: true,
  dmarc_verification_status: "verified_present",
  spf_status: "valid",
  spf_record: "v=spf1 -all",
  cached_at: "2026-08-23T12:00:00Z",
  lifecycle_status: "active",
};

describe("classifyDomainMigration", () => {
  it("uses the same Move Reporting action shown by the filter", () => {
    const state = classifyDomainMigration({ ...base, reports_to_bifrost: false, compliance: 100, volume: 1000 });
    expect(state.action).toBe("move_reporting");
    expect(state.actionLabel).toBe("Move Reporting");
    expect(state.reportingEligible).toBe(true);
  });

  it("classifies missing DMARC as No DMARC with a Set Up DNS action", () => {
    const state = classifyDomainMigration({ ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent" });
    expect(state.policyBucket).toBe("missing");
    expect(state.action).toBe("setup_dns");
    expect(state.monitorEligible).toBe(true);
  });

  it("offers direct reject only when no email use is confirmed", () => {
    const state = classifyDomainMigration({ ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent", mx_status: "null_mx", email_usage_override: "no_email" });
    expect(state.action).toBe("publish_reject");
    expect(state.rejectNoMailEligible).toBe(true);
    expect(state.rejectNoMailCandidate).toBe(true);
    expect(state.monitorEligible).toBe(false);
  });

  it("asks for email-use review when inbound routing is absent but outbound use is unknown", () => {
    const state = classifyDomainMigration({ ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent", spf_record: "", mx_status: "no_route" });
    expect(state.action).toBe("review_mail_use");
    expect(state.rejectNoMailEligible).toBe(false);
    expect(state.rejectNoMailCandidate).toBe(true);
  });

  it("asks for email-use review when SMTP would only use implicit address fallback", () => {
    const state = classifyDomainMigration({ ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent", spf_record: "", mx_status: "implicit" });
    expect(state.action).toBe("review_mail_use");
    expect(state.monitorEligible).toBe(false);
    expect(state.rejectNoMailCandidate).toBe(true);
  });

  it("allows monitor-only setup after an operator confirms email use", () => {
    const state = classifyDomainMigration({ ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent", spf_record: "", mx_status: "implicit", email_usage_override: "uses_email" });
    expect(state.action).toBe("setup_dns");
    expect(state.monitorEligible).toBe(true);
  });

  it("keeps manual DNS domains in the guided path without claiming bulk eligibility", () => {
    const state = classifyDomainMigration({ ...base, cloudflare_zone_id: "", has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent", mx_status: "present" });
    expect(state.action).toBe("setup_dns");
    expect(state.actionDetail).toMatch(/authoritative DNS provider/i);
    expect(state.monitorEligible).toBe(false);
  });

  it("partitions every missing domain into one readiness explanation", () => {
    const missing = { ...base, has_dmarc: false, dmarc_policy: "missing", dmarc_record: "", dmarc_verification_status: "verified_absent" as const };
    const summary = summarizeMissingDmarcReadiness([
      { ...missing, id: "ready", mx_status: "present" },
      { ...missing, id: "review", mx_status: "implicit" },
      { ...missing, id: "manual", cloudflare_zone_id: "", mx_status: "present" },
    ]);

    expect(summary).toEqual({
      total: 3,
      ready: 1,
      reviewEmailUse: 1,
      directReject: 0,
      manualDns: 1,
      blocked: 0,
    });
  });

  it("makes current high-compliance monitoring eligible for quarantine", () => {
    const state = classifyDomainMigration({ ...base, reports_to_bifrost: true, reporting_status: "current", compliance: 99.5, volume: 500 });
    expect(state.policyBucket).toBe("monitor");
    expect(state.action).toBe("enforce");
    expect(state.quarantineEligible).toBe(true);
  });

  it("makes quarantine with strong evidence eligible for strict enforcement", () => {
    const state = classifyDomainMigration({ ...base, reports_to_bifrost: true, reporting_status: "current", compliance: 99.5, volume: 500, dmarc_policy: "quarantine", dmarc_record: "v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r;" });
    expect(state.policyBucket).toBe("quarantine");
    expect(state.action).toBe("tighten_policy");
    expect(state.strictEligible).toBe(true);
  });

  it("recognizes reject with strict alignment as complete", () => {
    const state = classifyDomainMigration({ ...base, reports_to_bifrost: true, reporting_status: "current", dmarc_policy: "reject", dmarc_record: "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s;" });
    expect(state.policyBucket).toBe("strict");
    expect(state.action).toBe("complete");
  });
});
