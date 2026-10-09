import { describe, expect, it } from "vitest";

import type { AppContext, DailyMetric, DomainSummary } from "../types";
import { buildLiveDashboardData, liveStartDate } from "./liveDashboard";

const now = new Date("2026-08-23T12:00:00.000Z");
const context: AppContext = {
  setup: {
    reporting_domain: "dmarc.example.test",
    inbound_address: "rua@dmarc.example.test",
    authorization_record: "*._report._dmarc.dmarc.example.test",
    signing_secret_configured: true,
    signature_verification: "raw_body_required",
  },
  organizations: [
    { id: "org-1", name: "Organization One", domain: "one.example" },
    { id: "org-2", name: "Organization Two", domain: "two.example" },
  ],
};

function domain(overrides: Partial<DomainSummary> = {}): DomainSummary {
  return {
    id: "domain-1",
    domain: "one.example",
    organization_id: "org-1",
    organization_name: "Organization One",
    mapping_status: "mapped",
    mapping_source: "manual",
    dmarc_policy: "reject",
    dmarc_record: "v=DMARC1; p=reject; rua=mailto:rua@dmarc.example.test",
    rua: "mailto:rua@dmarc.example.test",
    has_dmarc: true,
    spf_status: "valid",
    spf_record: "v=spf1 -all",
    cached_at: "2026-08-23T10:00:00.000Z",
    lifecycle_status: "active",
    management_mode: "manual",
    ...overrides,
  };
}

function metric(overrides: Partial<DailyMetric> = {}): DailyMetric {
  return {
    id: "metric-1",
    date: "2026-08-23",
    domain: "one.example",
    organization_id: "org-1",
    total: 100,
    compliant: 95,
    non_compliant: 5,
    forwarded: 0,
    threat_unknown: 0,
    dkim_pass: 96,
    spf_pass: 97,
    sources: { Outlook: 80, Mailchimp: 20 },
    ...overrides,
  };
}

function build(overrides: Partial<Parameters<typeof buildLiveDashboardData>[0]> = {}) {
  return buildLiveDashboardData({
    context,
    domains: [domain()],
    dailyMetrics: [metric()],
    reports: [],
    records: [],
    ingestEvents: [],
    investigations: [],
    dnsChanges: [],
    days: 30,
    now,
    ...overrides,
  });
}

describe("buildLiveDashboardData", () => {
  it("normalizes sparse historical domain rows before deriving reporting state", () => {
    const sparse = {
      ...domain(),
      rua: undefined,
      dmarc_policy: undefined,
      spf_status: undefined,
      organization_name: undefined,
    } as unknown as DomainSummary;

    expect(() => build({ domains: [sparse] })).not.toThrow();
    expect(build({ domains: [sparse] }).domains[0]).toMatchObject({
      rua: "",
      dmarc_policy: "not_checked",
      spf_status: "not_checked",
      organization_name: "",
      reporting_status: "not_configured",
    });
  });

  it("uses the live domain row as the canonical mapping and lifecycle state", () => {
    const data = build({
      domains: [domain({ organization_id: "org-2", organization_name: "Organization Two", lifecycle_status: "archived", registration_status: "unregistered", archive_source: "automatic_registration_scan" })],
    });

    expect(data.domains).toEqual([]);
    expect(data.archived_domains?.[0]).toMatchObject({
      organization_id: "org-2",
      organization_name: "Organization Two",
      lifecycle_status: "archived",
    });
    expect(data.summary.archived).toBe(1);
    expect(data.summary.auto_archived).toBe(1);
    expect(data.summary.unregistered).toBe(1);
    expect(data.organizations.find((item) => item.id === "org-2")?.archived_domain_count).toBe(1);
  });

  it("keeps historical reports and result combinations for archived domains out of default reporting views", () => {
    const data = build({
      domains: [
        domain(),
        domain({
          id: "domain-2",
          domain: "archived.example",
          lifecycle_status: "archived",
        }),
      ],
      reports: [
        { id: "active-report", reporter: "Google", domain: "one.example", organization_name: "Organization One", date_end: "2026-08-23T09:00:00.000Z", message_count: 10, record_count: 1 },
        { id: "archived-report", reporter: "Google", domain: "archived.example", organization_name: "Organization One", date_end: "2026-08-23T09:00:00.000Z", message_count: 20, record_count: 1 },
      ],
      records: [
        { id: "active-record", report_key: "active-report", date: "2026-08-23", domain: "one.example", organization_name: "Organization One", source_ip: "192.0.2.1", count: 10, sending_source: "Google", disposition: "none", dkim: "pass", spf: "pass", classification: "compliant" },
        { id: "archived-record", report_key: "archived-report", date: "2026-08-23", domain: "archived.example", organization_name: "Organization One", source_ip: "192.0.2.2", count: 20, sending_source: "Google", disposition: "none", dkim: "pass", spf: "pass", classification: "compliant" },
      ],
    });

    expect(data.reports.map((report) => report.id)).toEqual(["active-report"]);
    expect((data.records ?? []).map((record) => record.id)).toEqual(["active-record"]);
  });

  it("derives overview metrics, trends, sources, and authentication rates from live daily rows", () => {
    const data = build({
      dailyMetrics: [metric(), metric({ id: "metric-2", date: "2026-08-22", total: 50, compliant: 40, spf_pass: 45, dkim_pass: 42, sources: { Outlook: 50 } })],
    });

    expect(data.summary).toMatchObject({ messages: 150, compliance: 90, protected: 1, domain_count: 1 });
    expect(data.trend.map((point) => point.date)).toEqual(["2026-08-22", "2026-08-23"]);
    expect(data.sources[0]).toEqual({ name: "Outlook", messages: 130 });
    expect(data.domains[0]).toMatchObject({ volume: 150, compliance: 90, spf_pass_rate: 94.67, dkim_pass_rate: 92 });
  });

  it("limits attention to domains with a concrete operator action", () => {
    const data = build({
      domains: [
        domain({ dmarc_verification_status: "verified_present", dmarc_record: "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@dmarc.example.test" }),
        domain({ id: "domain-2", domain: "unmapped.example", organization_id: "", organization_name: "", mapping_status: "unmapped", rua: "" }),
      ],
      reports: [{ id: "report-1", reporter: "google.com", domain: "one.example", organization_name: "Organization One", date_end: "2026-08-23T09:00:00.000Z", message_count: 100, record_count: 1 }],
    });

    expect(data.attention.map((item) => item.domain)).toEqual(["unmapped.example"]);
  });

  it("reflects live report, issue, inbound, investigation, and DNS audit rows without a dashboard refresh", () => {
    const data = build({
      reports: [{ id: "report-1", reporter: "google.com", domain: "one.example", organization_name: "Organization One", date_end: "2026-08-23T09:00:00.000Z", message_count: 10, record_count: 1 }],
      records: [{ id: "record-1", date: "2026-08-23", domain: "one.example", organization_name: "Organization One", source_ip: "192.0.2.1", count: 2, sending_source: "Unknown", disposition: "none", dkim: "fail", spf: "pass", classification: "non_compliant" }],
      ingestEvents: [{ id: "ingest-1", status: "completed", completed_at: "2026-08-23T10:00:00.000Z", report_count: 1, message_count: 10, signature_status: "verified" }],
      investigations: [{ id: "investigation-1", address: "test@dmarc.example.test", status: "waiting", source: "resend", created_at: "2026-08-23T10:00:00.000Z", expires_at: "2026-08-24T10:00:00.000Z" }],
      dnsChanges: [{ id: "change-1", domain: "one.example", kind: "dmarc", action: "update", status: "completed", created_at: "2026-08-23T10:00:00.000Z" }],
    });

    expect(data.reports).toHaveLength(1);
    expect(data.failures).toHaveLength(1);
    expect(data.ingest?.id).toBe("ingest-1");
    expect(data.investigations?.[0].id).toBe("investigation-1");
    expect(data.dns_changes?.[0].id).toBe("change-1");
    expect(data.domains[0]).toMatchObject({ reporting_status: "current", last_report_at: "2026-08-23T09:00:00.000Z" });
  });

  it("applies the organization selection consistently to table-backed analytics", () => {
    const data = build({
      domains: [domain(), domain({ id: "domain-2", domain: "two.example", organization_id: "org-2", organization_name: "Organization Two" })],
      dailyMetrics: [metric(), metric({ id: "metric-2", domain: "two.example", organization_id: "org-2", total: 900, compliant: 900 })],
      organizationId: "org-1",
    });

    expect(data.domains.map((item) => item.domain)).toEqual(["one.example"]);
    expect(data.summary.messages).toBe(100);
    expect(data.organizations).toHaveLength(2);
  });
});

describe("liveStartDate", () => {
  it("uses an inclusive UTC window and caps it at 90 days", () => {
    expect(liveStartDate(30, now)).toBe("2026-07-25");
    expect(liveStartDate(999, now)).toBe("2026-05-26");
  });
});
