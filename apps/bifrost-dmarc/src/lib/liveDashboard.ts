import type {
  AggregateReport,
  AppContext,
  DailyMetric,
  DashboardData,
  DnsChange,
  DomainSummary,
  FailureRecord,
  IngestStatus,
  Investigation,
  OrganizationSummary,
} from "../types";
import { ACTION_ORDER, classifyDomainMigration, domainNeedsAttention } from "./migration";

const DAY_MS = 24 * 60 * 60 * 1000;

function stringValue(value: unknown) {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

export function normalizeDomainSummary(domain: Partial<DomainSummary>): DomainSummary {
  return {
    ...domain,
    id: stringValue(domain.id),
    domain: stringValue(domain.domain),
    organization_id: stringValue(domain.organization_id),
    organization_name: stringValue(domain.organization_name),
    mapping_status: domain.mapping_status === "mapped" ? "mapped" : "unmapped",
    mapping_source: stringValue(domain.mapping_source) || "unmapped",
    dmarc_policy: stringValue(domain.dmarc_policy) || "not_checked",
    dmarc_record: stringValue(domain.dmarc_record),
    dmarc_record_type: domain.dmarc_record_type || "",
    dmarc_cname_target: stringValue(domain.dmarc_cname_target),
    dmarc_managed_provider: stringValue(domain.dmarc_managed_provider),
    dmarc_verification_status: domain.dmarc_verification_status || "not_checked",
    dmarc_verification_error: stringValue(domain.dmarc_verification_error),
    dmarc_verified_at: stringValue(domain.dmarc_verified_at),
    rua: stringValue(domain.rua),
    has_dmarc: Boolean(domain.has_dmarc),
    spf_status: stringValue(domain.spf_status) || "not_checked",
    spf_record: stringValue(domain.spf_record),
    mx_records: Array.isArray(domain.mx_records) ? domain.mx_records : [],
    mx_provider: stringValue(domain.mx_provider),
    mx_status: domain.mx_status || "not_checked",
    mx_lookup_error: stringValue(domain.mx_lookup_error),
    mx_checked_at: stringValue(domain.mx_checked_at),
    email_usage_override: domain.email_usage_override || "",
    cached_at: stringValue(domain.cached_at),
    lifecycle_status: domain.lifecycle_status === "archived" ? "archived" : "active",
    registration_status: domain.registration_status || "not_checked",
    registration_source: stringValue(domain.registration_source),
    registration_error: stringValue(domain.registration_error),
    registration_checked_at: stringValue(domain.registration_checked_at),
    archive_source: domain.archive_source || "",
    auto_archived_at: stringValue(domain.auto_archived_at),
  };
}

interface LiveDashboardInput {
  context?: AppContext;
  domains: DomainSummary[];
  dailyMetrics: DailyMetric[];
  reports: AggregateReport[];
  records: FailureRecord[];
  ingestEvents: IngestStatus[];
  investigations: Investigation[];
  dnsChanges: DnsChange[];
  organizationId?: string;
  days: number;
  now?: Date;
}

interface DomainTotals {
  total: number;
  compliant: number;
  non_compliant: number;
  forwarded: number;
  threat_unknown: number;
  dkim_pass: number;
  spf_pass: number;
}

const emptyTotals = (): DomainTotals => ({
  total: 0,
  compliant: 0,
  non_compliant: 0,
  forwarded: 0,
  threat_unknown: 0,
  dkim_pass: 0,
  spf_pass: 0,
});

function addMetric(target: DomainTotals, row: DailyMetric) {
  target.total += Number(row.total || 0);
  target.compliant += Number(row.compliant || 0);
  target.non_compliant += Number(row.non_compliant || 0);
  target.forwarded += Number(row.forwarded || 0);
  target.threat_unknown += Number(row.threat_unknown || 0);
  target.dkim_pass += Number(row.dkim_pass || 0);
  target.spf_pass += Number(row.spf_pass || 0);
}

function percentage(numerator: number, denominator: number) {
  return denominator ? Math.round((numerator / denominator) * 10_000) / 100 : 0;
}

function timestamp(value?: string) {
  const parsed = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function ruaDestinations(value: string) {
  return new Set(value.split(",").map((item) => item.trim().toLowerCase().split("!", 1)[0]).filter(Boolean));
}

function orphanStatus(domain: DomainSummary, visibleOrganizationIds: Set<string>) {
  let mode = domain.management_mode;
  if (!mode) {
    if (domain.cloudflare_zone_id || domain.cloudflare_account_id) mode = "cloudflare";
    else if (domain.source_inventory_origin) mode = "external";
    else if (domain.mapping_source === "report") mode = "report";
    else mode = "manual";
  }
  const cloudflareMissing = ["cloudflare", "external"].includes(mode) && !domain.cloudflare_zone_id;
  const organizationMissing = Boolean(domain.organization_id) && !visibleOrganizationIds.has(domain.organization_id);
  if (cloudflareMissing && organizationMissing) return "cloudflare_and_organization_missing";
  if (cloudflareMissing) return "cloudflare_missing";
  if (organizationMissing) return "organization_missing";
  return "";
}

function sortDescending<T>(rows: T[], accessor: (row: T) => string | undefined) {
  return [...rows].sort((left, right) => timestamp(accessor(right)) - timestamp(accessor(left)));
}

export function liveStartDate(days: number, now = new Date()) {
  const normalizedDays = Math.min(Math.max(Math.trunc(days || 30), 1), 90);
  const start = new Date(now);
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (normalizedDays - 1));
  return start.toISOString().slice(0, 10);
}

export function buildLiveDashboardData({
  context,
  domains,
  dailyMetrics,
  reports,
  records,
  ingestEvents,
  investigations,
  dnsChanges,
  organizationId = "",
  days,
  now = new Date(),
}: LiveDashboardInput): DashboardData {
  const normalizedDays = Math.min(Math.max(Math.trunc(days || 30), 1), 90);
  const startDate = liveStartDate(normalizedDays, now);
  const directory = (context?.organizations ?? []).map((organization) => ({
    id: stringValue(organization.id),
    name: stringValue(organization.name),
    domain: stringValue(organization.domain),
  }));
  const visibleOrganizationIds = new Set(directory.map((organization) => organization.id));
  const normalizedDomains = domains.map(normalizeDomainSummary);
  const activeDomains = normalizedDomains.filter((domain) => domain.lifecycle_status !== "archived");
  const archivedDomains = normalizedDomains.filter((domain) => domain.lifecycle_status === "archived");
  const visibleDomains = organizationId
    ? activeDomains.filter((domain) => domain.organization_id === organizationId)
    : activeDomains;
  const visibleDomainNames = new Set(visibleDomains.map((domain) => domain.domain));
  const visibleMetrics = dailyMetrics.filter((row) =>
    row.date >= startDate
    && (!organizationId || row.organization_id === organizationId)
    && visibleDomainNames.has(row.domain),
  );
  const visibleReports = sortDescending(
    reports.filter((report) =>
      (!report.date_end || stringValue(report.date_end).slice(0, 10) >= startDate)
      && visibleDomainNames.has(report.domain),
    ),
    (report) => report.date_end || report.ingested_at,
  ).slice(0, 5000);
  const visibleRecords = sortDescending(
    records.filter((record) =>
      (!record.date || stringValue(record.date).slice(0, 10) >= startDate)
      && visibleDomainNames.has(record.domain),
    ),
    (record) => record.date,
  ).slice(0, 10_000);

  const totals = emptyTotals();
  const totalsByDomain = new Map<string, DomainTotals>();
  const totalsByDate = new Map<string, DomainTotals>();
  const sourceTotals = new Map<string, number>();
  for (const row of visibleMetrics) {
    addMetric(totals, row);
    const domainTotals = totalsByDomain.get(row.domain) ?? emptyTotals();
    addMetric(domainTotals, row);
    totalsByDomain.set(row.domain, domainTotals);
    const dateTotals = totalsByDate.get(row.date) ?? emptyTotals();
    addMetric(dateTotals, row);
    totalsByDate.set(row.date, dateTotals);
    for (const [source, count] of Object.entries(row.sources ?? {})) {
      sourceTotals.set(source, (sourceTotals.get(source) ?? 0) + Number(count || 0));
    }
  }

  const lastReportByDomain = new Map<string, string>();
  for (const report of visibleReports) {
    if (!lastReportByDomain.has(report.domain)) {
      lastReportByDomain.set(report.domain, report.date_end || report.ingested_at || "");
    }
  }
  const reportingDomain = stringValue(context?.setup?.reporting_domain).toLowerCase();
  const enrichDomain = (domain: DomainSummary): DomainSummary => {
    const domainTotals = totalsByDomain.get(domain.domain) ?? emptyTotals();
    const lastReportAt = lastReportByDomain.get(domain.domain) ?? "";
    const reportsToBifrost = Boolean(reportingDomain)
      && ruaDestinations(domain.rua).has(`mailto:rua@${reportingDomain}`);
    let reportingStatus: DomainSummary["reporting_status"] = "not_configured";
    if (reportsToBifrost && !lastReportAt) reportingStatus = "awaiting";
    if (reportsToBifrost && lastReportAt) {
      const age = now.getTime() - timestamp(lastReportAt);
      reportingStatus = timestamp(lastReportAt) === 0 ? "needs_review" : age <= 3 * DAY_MS ? "current" : "stale";
    }
    return {
      ...domain,
      orphan_status: orphanStatus(domain, visibleOrganizationIds),
      volume: domainTotals.total,
      compliance: percentage(domainTotals.compliant, domainTotals.total),
      spf_pass_rate: percentage(domainTotals.spf_pass, domainTotals.total),
      dkim_pass_rate: percentage(domainTotals.dkim_pass, domainTotals.total),
      last_report_at: lastReportAt,
      reports_to_bifrost: reportsToBifrost,
      reporting_status: reportingStatus,
    };
  };
  const enrichedDomains = visibleDomains.map(enrichDomain);
  const enrichedArchivedDomains = archivedDomains.map((domain) => ({
    ...enrichDomain(domain),
    volume: 0,
    compliance: 0,
    spf_pass_rate: 0,
    dkim_pass_rate: 0,
    last_report_at: "",
    reports_to_bifrost: false,
    reporting_status: "not_monitored" as const,
  }));
  const attention = enrichedDomains.filter(domainNeedsAttention).sort((left, right) => {
    const leftAction = classifyDomainMigration(left).action;
    const rightAction = classifyDomainMigration(right).action;
    const actionDifference = ACTION_ORDER.indexOf(leftAction) - ACTION_ORDER.indexOf(rightAction);
    if (actionDifference) return actionDifference;
    const leftRank = [
      left.mapping_status !== "unmapped",
      Boolean(left.last_report_at),
      !["missing", "none", "unknown", "not_checked", "lookup_failed"].includes(left.dmarc_policy),
      left.compliance ?? 0,
    ];
    const rightRank = [
      right.mapping_status !== "unmapped",
      Boolean(right.last_report_at),
      !["missing", "none", "unknown", "not_checked", "lookup_failed"].includes(right.dmarc_policy),
      right.compliance ?? 0,
    ];
    for (let index = 0; index < leftRank.length; index += 1) {
      if (leftRank[index] === rightRank[index]) continue;
      return Number(leftRank[index]) - Number(rightRank[index]);
    }
    return left.domain.localeCompare(right.domain);
  });

  const organizations: OrganizationSummary[] = directory
    .map((organization) => {
      const organizationDomains = activeDomains.filter((domain) => domain.organization_id === organization.id);
      return {
        ...organization,
        domain_count: organizationDomains.length,
        protected_count: organizationDomains.filter((domain) => domain.has_dmarc).length,
        archived_domain_count: archivedDomains.filter((domain) => domain.organization_id === organization.id).length,
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
  const recentIngest = sortDescending(
    ingestEvents,
    (event) => event.completed_at || event.started_at,
  ).slice(0, 25);
  const recentDnsChanges = sortDescending(dnsChanges, (change) => change.created_at).slice(0, 25);
  const recentInvestigations = sortDescending(investigations, (investigation) => investigation.created_at).slice(0, 25);

  return {
    setup: context?.setup,
    summary: {
      messages: totals.total,
      compliance: percentage(totals.compliant, totals.total),
      protected: enrichedDomains.filter((domain) => domain.has_dmarc).length,
      domain_count: enrichedDomains.length,
      unmapped: enrichedDomains.filter((domain) => domain.mapping_status === "unmapped").length,
      reporting: enrichedDomains.filter((domain) => Boolean(domain.last_report_at)).length,
      orphaned: enrichedDomains.filter((domain) => Boolean(domain.orphan_status)).length,
      archived: archivedDomains.length,
      auto_archived: archivedDomains.filter((domain) => domain.archive_source === "automatic_registration_scan").length,
      unregistered: normalizedDomains.filter((domain) => domain.registration_status === "unregistered").length,
    },
    trend: [...totalsByDate.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([date, dateTotals]) => ({ date, ...dateTotals })),
    sources: [...sourceTotals.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 8)
      .map(([name, messages]) => ({ name, messages })),
    attention,
    organizations,
    domains: enrichedDomains,
    archived_domains: enrichedArchivedDomains,
    reports: visibleReports,
    records: visibleRecords,
    failures: visibleRecords.filter((record) => record.classification !== "compliant").slice(0, 5000),
    ingest_events: recentIngest,
    investigations: recentInvestigations,
    dns_changes: recentDnsChanges,
    ingest: recentIngest[0] ?? null,
    health: {
      recent_ingest_failures: recentIngest.filter((event) => event.status === "failed").length,
      recent_ingest_events: recentIngest.length,
      signature_verified_events: recentIngest.filter((event) => event.signature_status === "verified").length,
      reporting_current: enrichedDomains.filter((domain) => domain.reporting_status === "current").length,
      reporting_awaiting: enrichedDomains.filter((domain) => domain.reporting_status === "awaiting").length,
      reporting_stale: enrichedDomains.filter((domain) => domain.reporting_status === "stale").length,
    },
  };
}
