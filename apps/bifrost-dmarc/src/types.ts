export interface OrganizationSummary {
  id: string;
  name: string;
  domain: string;
  domain_count: number;
  protected_count: number;
  archived_domain_count?: number;
}

export interface AppContext {
  setup: {
    reporting_domain: string;
    inbound_address: string;
    authorization_record: string;
    signing_secret_configured?: boolean;
    signature_verification?: string;
  };
  organizations: Array<Pick<OrganizationSummary, "id" | "name" | "domain">>;
}

export interface DomainSummary {
  id: string;
  domain: string;
  organization_id: string;
  organization_name: string;
  mapping_status: "mapped" | "unmapped";
  mapping_source: string;
  cloudflare_account_id?: string;
  cloudflare_account_name?: string;
  cloudflare_zone_id?: string;
  dmarc_policy: string;
  dmarc_record: string;
  dmarc_status?: string;
  dmarc_record_count?: number;
  dmarc_record_type?: "TXT" | "CNAME" | "";
  dmarc_cname_target?: string;
  dmarc_managed_provider?: string;
  dmarc_verification_status?: "verified_present" | "verified_absent" | "mismatch" | "invalid_cname" | "lookup_failed" | "not_checked" | "";
  dmarc_verification_error?: string;
  dmarc_verified_at?: string;
  dmarc_subdomain_policy?: string;
  dmarc_pct?: number;
  rua: string;
  has_dmarc: boolean;
  spf_status: string;
  spf_record: string;
  spf_record_count?: number;
  spf_terms?: string[];
  mx_records?: Array<{ priority: number; exchange: string }>;
  mx_provider?: string;
  mx_status?: "present" | "null_mx" | "implicit" | "no_route" | "invalid" | "lookup_failed" | "not_checked" | "";
  mx_lookup_error?: string;
  mx_checked_at?: string;
  email_usage_override?: "" | "uses_email" | "no_email";
  dns_lookup_status?: "current" | "not_checked" | "lookup_failed";
  dns_lookup_source?: "cloudflare" | "public_dns" | "";
  dns_lookup_error?: string;
  nameservers?: string[];
  soa_nameserver?: string;
  dns_provider?: string;
  dns_provider_source?: "cloudflare_integration" | "domain_connect" | "ns_fingerprint" | "soa_fingerprint" | "nameserver" | "unidentified" | "legacy_cache" | "";
  dns_provider_confidence?: "confirmed" | "high" | "medium" | "unknown" | "";
  domain_connect_provider_id?: string;
  domain_connect_endpoint?: string;
  dns_management_url?: string;
  dns_provider_checked_at?: string;
  registration_status?: "delegated" | "registered_undelegated" | "subdomain" | "unregistered" | "lookup_failed" | "unsupported" | "not_checked" | "";
  registration_source?: string;
  registration_error?: string;
  registration_checked_at?: string;
  cached_at: string;
  last_report_at?: string;
  volume?: number;
  compliance?: number;
  spf_pass_rate?: number;
  dkim_pass_rate?: number;
  reports_to_bifrost?: boolean;
  reporting_status?: "current" | "awaiting" | "stale" | "not_configured" | "needs_review" | "not_monitored";
  source_inventory_origin?: string;
  source_inventory_status?: "managed" | "detected" | "not_found";
  source_inventory_verified?: boolean;
  source_inventory_imported_at?: string;
  source_inventory_count?: number;
  cloudflare_inventory_status?: "linked" | "missing" | "not_connected";
  inventory_status?: "ready" | "review_sources" | "organization_unmapped" | "cloudflare_missing" | "no_sources" | "not_imported" | "archived";
  management_mode?: "cloudflare" | "manual" | "external" | "report";
  lifecycle_status?: "active" | "archived";
  orphan_status?: "" | "cloudflare_missing" | "organization_missing" | "cloudflare_and_organization_missing";
  orphaned_at?: string;
  archived_at?: string;
  archive_reason?: string;
  archive_source?: "manual" | "automatic_registration_scan" | "";
  auto_archived_at?: string;
  cloudflare_last_seen_at?: string;
}

export interface SpfSource {
  id: string;
  domain: string;
  source_name: string;
  spf_part: string;
  spf_type?: string;
  spf_value?: string;
  spf_capability?: "capable" | "non-capable" | "unknown";
  enabled: boolean;
  notes?: string;
  volume?: number;
  ordering?: number;
  source_origin?: string;
  provider?: Record<string, unknown>;
  configuration?: Record<string, unknown>;
  imported_at?: string;
}

export interface TrendPoint {
  date: string;
  total?: number;
  compliant?: number;
  non_compliant?: number;
  forwarded?: number;
  threat_unknown?: number;
}

export interface DailyMetric extends TrendPoint {
  id: string;
  domain: string;
  organization_id?: string;
  organization_name?: string;
  dkim_pass?: number;
  spf_pass?: number;
  sources?: Record<string, number>;
  updated_at?: string;
}

export interface AggregateReport {
  id: string;
  report_id?: string;
  reporter: string;
  reporter_email?: string;
  domain: string;
  organization_name: string;
  date_begin?: string;
  date_end: string;
  message_count: number;
  record_count: number;
  filename?: string;
  email_id?: string;
  ingested_at?: string;
}

export interface FailureRecord {
  id: string;
  report_key?: string;
  report_id?: string;
  date: string;
  domain: string;
  organization_name: string;
  source_ip: string;
  count: number;
  sending_source: string;
  disposition: string;
  dkim: string;
  spf: string;
  classification: string;
  header_from?: string;
  envelope_from?: string;
  envelope_to?: string;
  reasons?: unknown[];
  auth_results?: unknown[];
}

export interface IngestStatus {
  id?: string;
  status: string;
  completed_at?: string;
  message_count?: number;
  report_count?: number;
  error?: string;
  route?: string;
  recipients?: string[];
  ignore_reason?: string;
  signature_status?: string;
  started_at?: string;
}

export interface Investigation {
  id: string;
  address: string;
  status: "waiting" | "processing" | "completed" | "failed" | "expired";
  source: "resend" | "upload";
  subject?: string;
  created_at: string;
  expires_at: string;
  completed_at?: string;
  error?: string;
  analysis?: {
    from: string[];
    to: string[];
    return_path: string[];
    results?: { dmarc?: string; dkim?: string; spf?: string };
    dkim_domains?: string[];
    received_hops?: number;
    findings?: Array<{ severity: string; title: string; detail: string }>;
    limitations?: string;
  };
}

export interface DnsComparison {
  kind: "dmarc" | "spf";
  domain_id: string;
  domain: string;
  name: string;
  previous: string;
  record: string;
  action: "create" | "update" | "none" | "manual";
  cloudflare_connected?: boolean;
  current_record_type?: "TXT" | "CNAME" | "";
  current_cname_target?: string;
  current_managed_provider?: string;
  checked_at?: string;
  lookup_count?: number;
  warnings: string[];
}

export interface DnsChange {
  id: string;
  organization_name?: string;
  domain: string;
  kind: string;
  action: string;
  status: string;
  created_at: string;
  error?: string;
}

export interface MigrationRun {
  id: string;
  operation: "reporting" | "monitor" | "reject_no_mail" | "quarantine" | "strict";
  status: "queued" | "processing" | "completed" | "completed_with_errors" | "failed";
  requested: number;
  completed: number;
  skipped: number;
  failed: number;
  execution_id?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export interface MigrationTask {
  id: string;
  run_id: string;
  domain_id: string;
  domain: string;
  organization_id?: string;
  organization_name?: string;
  operation: "reporting" | "monitor" | "reject_no_mail" | "quarantine" | "strict";
  status: "queued" | "processing" | "completed" | "skipped" | "failed";
  ordering?: number;
  action?: string;
  previous_value?: string;
  new_value?: string;
  error?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface DashboardData {
  setup?: {
    reporting_domain: string;
    inbound_address: string;
    authorization_record: string;
    signing_secret_configured?: boolean;
    signature_verification?: string;
  };
  summary: {
    messages: number;
    compliance: number;
    protected: number;
    domain_count: number;
    unmapped: number;
    reporting?: number;
    orphaned?: number;
    archived?: number;
    auto_archived?: number;
    unregistered?: number;
  };
  trend: TrendPoint[];
  sources: Array<{ name: string; messages: number }>;
  attention: DomainSummary[];
  organizations: OrganizationSummary[];
  domains: DomainSummary[];
  archived_domains?: DomainSummary[];
  reports: AggregateReport[];
  records?: FailureRecord[];
  failures: FailureRecord[];
  ingest_events?: IngestStatus[];
  investigations?: Investigation[];
  dns_changes?: DnsChange[];
  ingest: IngestStatus | null;
  health?: {
    recent_ingest_failures: number;
    recent_ingest_events: number;
    signature_verified_events: number;
    reporting_current?: number;
    reporting_awaiting?: number;
    reporting_stale?: number;
  };
}
