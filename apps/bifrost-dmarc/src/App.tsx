import { useMemo, useState } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { tables, useWorkflowMutation, useWorkflowQuery } from "bifrost";

import { AppShell } from "./components/AppShell";
import { DomainsPage } from "./components/DomainsPage";
import { MigrationPage } from "./components/MigrationPage";
import { OrganizationsPage } from "./components/OrganizationsPage";
import { OverviewPage } from "./components/OverviewPage";
import { ReportsPage } from "./components/ReportsPage";
import { SettingsPage } from "./components/SettingsPage";
import { BfButton } from "./components/bifrost/BfButton";
import { useCompleteTable } from "./hooks/useCompleteTable";
import { useWorkflowDispatch } from "./hooks/useWorkflowDispatch";
import { buildLiveDashboardData, liveStartDate, normalizeDomainSummary } from "./lib/liveDashboard";
import type { BulkMigrationOperation } from "./lib/migration";
import type {
  AggregateReport,
  AppContext,
  DailyMetric,
  DnsChange,
  DnsComparison,
  DomainSummary,
  FailureRecord,
  IngestStatus,
  Investigation,
  MigrationRun,
  MigrationTask,
  SpfSource,
} from "./types";

const APP_CONTEXT_WORKFLOW = "functions/dmarc.py::get_app_context";
const SYNC_WORKFLOW = "functions/dmarc.py::sync_cloudflare_domains";
const REFRESH_PUBLIC_DNS_WORKFLOW = "functions/dmarc.py::refresh_public_dns_domains";
const MAP_WORKFLOW = "functions/dmarc.py::map_domain";
const MAP_ACCOUNT_WORKFLOW = "functions/dmarc.py::map_cloudflare_account";
const CREATE_MANUAL_DOMAIN_WORKFLOW = "functions/dmarc.py::create_manual_domain";
const SET_DOMAIN_LIFECYCLE_WORKFLOW = "functions/dmarc.py::set_domain_lifecycle";
const BULK_DOMAIN_LIFECYCLE_WORKFLOW = "functions/dmarc.py::bulk_domain_lifecycle";
const SYNTHETIC_WORKFLOW = "functions/dmarc.py::ingest_synthetic_report";
const CREATE_INVESTIGATION_WORKFLOW = "functions/dmarc.py::create_email_investigation";
const ANALYZE_EML_WORKFLOW = "functions/dmarc.py::analyze_eml_upload";
const COMPARE_DNS_WORKFLOW = "functions/dmarc.py::compare_dns_record";
const APPLY_DNS_WORKFLOW = "functions/dmarc.py::apply_dns_record";
const CONFIGURE_RESEND_SECRET_WORKFLOW = "functions/dmarc.py::configure_resend_signing_secret";
const PROCESS_DMARC_MIGRATION_WORKFLOW = "functions/dmarc.py::process_dmarc_migration";

interface BulkLifecycleResult {
  requested: number;
  updated: number;
  failed: number;
  results: Array<{ id: string; ok: boolean; error?: string }>;
}

export default function App() {
  const navigate = useNavigate();
  const [organizationId, setOrganizationId] = useState("");
  const [days, setDays] = useState(30);
  const [overviewDomainId, setOverviewDomainId] = useState("");
  const [operationError, setOperationError] = useState("");
  const [emailUsageUpdating, setEmailUsageUpdating] = useState(false);
  const tableStartDate = useMemo(() => liveStartDate(90), []);
  const analyticsWhere = useMemo<Record<string, unknown>>(
    () => ({ date: { gte: tableStartDate } }),
    [tableStartDate],
  );
  const reportWhere = useMemo<Record<string, unknown>>(
    () => ({ date_end: { gte: tableStartDate } }),
    [tableStartDate],
  );

  // Only configuration and the Bifrost organization directory come from a
  // workflow. Every DMARC data set below is a live Tables subscription.
  const context = useWorkflowQuery<AppContext>(APP_CONTEXT_WORKFLOW);
  const domainInventory = useCompleteTable<DomainSummary>("dmarc_domains", {
    pageSize: 1000,
    order_by: "domain",
    order_dir: "asc",
  });
  const sourceInventory = useCompleteTable<SpfSource>("dmarc_spf_sources", {
    pageSize: 1000,
    order_by: "domain",
    order_dir: "asc",
  });
  const dailyMetrics = useCompleteTable<DailyMetric>("dmarc_daily_metrics", {
    where: analyticsWhere,
    pageSize: 1000,
    order_by: "date",
    order_dir: "asc",
  });
  const reports = useCompleteTable<AggregateReport>("dmarc_reports", {
    where: reportWhere,
    pageSize: 1000,
    order_by: "date_end",
    order_dir: "desc",
  });
  const records = useCompleteTable<FailureRecord>("dmarc_records", {
    where: analyticsWhere,
    pageSize: 1000,
    order_by: "date",
    order_dir: "desc",
  });
  const ingestEvents = useCompleteTable<IngestStatus>("dmarc_ingest_events", {
    pageSize: 1000,
    order_by: "completed_at",
    order_dir: "desc",
  });
  const investigations = useCompleteTable<Investigation>("dmarc_investigations", {
    pageSize: 1000,
    order_by: "created_at",
    order_dir: "desc",
  });
  const dnsChanges = useCompleteTable<DnsChange>("dmarc_dns_changes", {
    pageSize: 1000,
    order_by: "created_at",
    order_dir: "desc",
  });
  const migrationRuns = useCompleteTable<MigrationRun>("dmarc_migration_runs", {
    pageSize: 100,
    order_by: "created_at",
    order_dir: "desc",
  });
  const migrationTasks = useCompleteTable<MigrationTask>("dmarc_migration_tasks", {
    pageSize: 1000,
    order_by: "created_at",
    order_dir: "desc",
  });
  const normalizedDomains = useMemo(
    () => domainInventory.rows.map(normalizeDomainSummary),
    [domainInventory.rows],
  );

  const data = useMemo(() => buildLiveDashboardData({
    context: context.data,
    domains: normalizedDomains,
    dailyMetrics: dailyMetrics.rows,
    reports: reports.rows,
    records: records.rows,
    ingestEvents: ingestEvents.rows,
    investigations: investigations.rows,
    dnsChanges: dnsChanges.rows,
    organizationId: "",
    days: 30,
  }), [
    context.data,
    dailyMetrics.rows,
    dnsChanges.rows,
    ingestEvents.rows,
    investigations.rows,
    normalizedDomains,
    records.rows,
    reports.rows,
  ]);

  const overviewData = useMemo(() => buildLiveDashboardData({
    context: context.data,
    domains: normalizedDomains,
    dailyMetrics: dailyMetrics.rows,
    reports: reports.rows,
    records: records.rows,
    ingestEvents: ingestEvents.rows,
    investigations: investigations.rows,
    dnsChanges: dnsChanges.rows,
    organizationId,
    days,
  }), [
    context.data,
    dailyMetrics.rows,
    days,
    dnsChanges.rows,
    ingestEvents.rows,
    investigations.rows,
    normalizedDomains,
    organizationId,
    records.rows,
    reports.rows,
  ]);

  const sync = useWorkflowMutation<{ zones: number; mapped: number; unmapped: number }>(SYNC_WORKFLOW);
  const refreshPublicDns = useWorkflowMutation<{ checked: number; refreshed: number; failed: number; auto_archived: number }>(REFRESH_PUBLIC_DNS_WORKFLOW);
  const map = useWorkflowMutation<DomainSummary>(MAP_WORKFLOW);
  const mapAccount = useWorkflowMutation<{ domain_count: number; domains: string[] }>(MAP_ACCOUNT_WORKFLOW);
  const createManualDomain = useWorkflowMutation<DomainSummary>(CREATE_MANUAL_DOMAIN_WORKFLOW);
  const setDomainLifecycle = useWorkflowMutation<DomainSummary>(SET_DOMAIN_LIFECYCLE_WORKFLOW);
  const bulkDomainLifecycle = useWorkflowMutation<BulkLifecycleResult>(BULK_DOMAIN_LIFECYCLE_WORKFLOW);
  const synthetic = useWorkflowMutation<{ reports: number; records: number; messages: number }>(SYNTHETIC_WORKFLOW);
  const createInvestigation = useWorkflowMutation<Investigation>(CREATE_INVESTIGATION_WORKFLOW);
  const analyzeEml = useWorkflowMutation<Investigation>(ANALYZE_EML_WORKFLOW);
  const compareDns = useWorkflowMutation<DnsComparison>(COMPARE_DNS_WORKFLOW);
  const applyDns = useWorkflowMutation<DnsComparison>(APPLY_DNS_WORKFLOW);
  const configureResendSecret = useWorkflowMutation<{ configured: boolean; webhook_id: string; endpoint: string }>(CONFIGURE_RESEND_SECRET_WORKFLOW);
  const processDmarcMigration = useWorkflowDispatch(PROCESS_DMARC_MIGRATION_WORKFLOW);

  const syncDomains = async () => {
    setOperationError("");
    let cloudflareError: unknown;
    try {
      await sync.mutate({});
    } catch (error) {
      cloudflareError = error;
    }
    await refreshPublicDns.mutate({});
    if (cloudflareError) throw cloudflareError;
  };
  const mapDomain = async (domainId: string, mappedOrganizationId: string) => {
    setOperationError("");
    await map.mutate({ domain_id: domainId, organization_id: mappedOrganizationId });
  };
  const mapCloudflareAccount = async (accountId: string, mappedOrganizationId: string) => {
    setOperationError("");
    await mapAccount.mutate({ cloudflare_account_id: accountId, organization_id: mappedOrganizationId });
  };
  const addManualDomain = async (domain: string, mappedOrganizationId: string) => {
    setOperationError("");
    return createManualDomain.mutate({ domain, organization_id: mappedOrganizationId });
  };
  const changeDomainLifecycle = async (domainId: string, action: "archive" | "restore", reason = "") => {
    setOperationError("");
    return setDomainLifecycle.mutate({ domain_id: domainId, action, reason });
  };
  const archiveDomains = async (domainIds: string[]) => {
    setOperationError("");
    const result = await bulkDomainLifecycle.mutate({
      domain_ids: domainIds,
      action: "archive",
      reason: "Archived during domain inventory maintenance",
    });
    if (result.failed) {
      const message = result.results.find((item) => !item.ok)?.error || "Some selected domains could not be archived.";
      setOperationError(message);
      throw new Error(message);
    }
  };
  const setEmailUsage = async (domainId: string, value: "" | "uses_email" | "no_email") => {
    setOperationError("");
    setEmailUsageUpdating(true);
    try {
      await tables.update("dmarc_domains", domainId, { email_usage_override: value });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Email use could not be updated.";
      setOperationError(message);
      throw error;
    } finally {
      setEmailUsageUpdating(false);
    }
  };
  const uploadSynthetic = async (filename: string, contentBase64: string) => {
    await synthetic.mutate({ filename, content_base64: contentBase64 });
  };
  const issueInvestigation = () => createInvestigation.mutate({});
  const uploadEml = (filename: string, contentBase64: string) => analyzeEml.mutate({ filename, content_base64: contentBase64 });
  const compareDnsRecord = (domainId: string, kind: "dmarc" | "spf", settings: Record<string, unknown>) =>
    compareDns.mutate({ domain_id: domainId, kind, settings });
  const applyDnsRecord = (domainId: string, kind: "dmarc" | "spf", confirmDomain: string, expectedRecord: string, settings: Record<string, unknown>) =>
    applyDns.mutate({ domain_id: domainId, kind, confirm_domain: confirmDomain, expected_record: expectedRecord, settings });
  const importResendSecret = async () => {
    const result = await configureResendSecret.mutate({});
    await context.refresh();
    return result;
  };
  const startMigration = async (operation: BulkMigrationOperation, domainIds: string[], confirmNoEmail?: boolean) => {
    await processDmarcMigration.dispatch({ operation, domain_ids: domainIds, confirm_no_email: confirmNoEmail ?? false });
  };
  const openOrganizationDomains = (selectedOrganizationId: string) => {
    navigate(`/domains?organization=${encodeURIComponent(selectedOrganizationId)}`);
  };

  const tableErrors = [
    domainInventory.error,
    sourceInventory.error,
    dailyMetrics.error,
    reports.error,
    records.error,
    ingestEvents.error,
    investigations.error,
    dnsChanges.error,
  ].filter((error): error is Error => Boolean(error));
  const loadError = context.error ?? tableErrors[0];
  const overviewLoading = context.loading || domainInventory.loading || dailyMetrics.loading || reports.loading;
  const domainsLoading = domainInventory.loading;
  const reportsLoading = domainInventory.loading || reports.loading || records.loading || ingestEvents.loading;
  const mutationError = operationError
    || map.error?.message
    || mapAccount.error?.message
    || createManualDomain.error?.message
    || setDomainLifecycle.error?.message
    || bulkDomainLifecycle.error?.message
    || sync.error?.message
    || refreshPublicDns.error?.message;
  const domainPageProps = {
    data,
    loading: domainsLoading,
    syncing: sync.loading || refreshPublicDns.loading,
    mapping: map.loading || mapAccount.loading,
    onSync: syncDomains,
    onMap: mapDomain,
    onMapAccount: mapCloudflareAccount,
    creating: createManualDomain.loading,
    lifecycleChanging: setDomainLifecycle.loading || bulkDomainLifecycle.loading,
    mutationError,
    onCreateDomain: addManualDomain,
    onSetLifecycle: changeDomainLifecycle,
    onBulkArchive: archiveDomains,
    emailUsageUpdating,
    onSetEmailUsage: setEmailUsage,
    comparing: compareDns.loading,
    applying: applyDns.loading,
    dnsError: compareDns.error?.message || applyDns.error?.message,
    onCompareDns: compareDnsRecord,
    onApplyDns: applyDnsRecord,
  };

  return (
    <div className="dmarc-app">
      <AppShell ingest={data.ingest} loading={ingestEvents.loading}>
        {loadError ? (
          <div className="error-banner" role="alert">
            <strong>DMARC data could not be loaded.</strong>
            <span>{loadError.message}</span>
            <BfButton variant="secondary" size="compact" onClick={() => window.location.reload()}>Try Again</BfButton>
          </div>
        ) : null}
        <Routes>
          <Route path="/" element={<><OverviewPage data={overviewData} loading={overviewLoading} organizationId={organizationId} days={days} onOrganizationChange={setOrganizationId} onDaysChange={setDays} onOpenDomain={setOverviewDomainId} /><DomainsPage {...domainPageProps} managerOnly requestedDomainId={overviewDomainId} onManagerClose={() => setOverviewDomainId("")} /></>} />
          <Route path="/organizations" element={<OrganizationsPage data={data} loading={context.loading || domainInventory.loading} onSelect={openOrganizationDomains} />} />
          <Route path="/domains" element={<DomainsPage {...domainPageProps} />} />
          <Route path="/reports" element={<ReportsPage data={data} loading={reportsLoading} />} />
          <Route path="/migration" element={<MigrationPage domains={data.domains} sources={sourceInventory.rows} organizations={data.organizations} runs={migrationRuns.rows} tasks={migrationTasks.rows} loading={domainInventory.loading || sourceInventory.loading || migrationRuns.loading || migrationTasks.loading} syncing={sync.loading || refreshPublicDns.loading} mapping={map.loading} applying={applyDns.loading} starting={processDmarcMigration.loading} error={domainInventory.error?.message || sourceInventory.error?.message || migrationRuns.error?.message || migrationTasks.error?.message || sync.error?.message || refreshPublicDns.error?.message || applyDns.error?.message || processDmarcMigration.error?.message} onSync={syncDomains} onMap={mapDomain} onStartMigration={startMigration} onCompareDns={compareDnsRecord} onApplyDns={(domainId, kind, expectedRecord, settings) => applyDnsRecord(domainId, kind, data.domains.find((item) => item.id === domainId)?.domain ?? "", expectedRecord, settings)} />} />
          <Route path="/settings" element={<SettingsPage loading={context.loading} setup={data.setup} uploading={synthetic.loading} uploadResult={synthetic.data} uploadError={synthetic.error?.message} onUpload={uploadSynthetic} investigations={investigations.rows} investigationsLoading={investigations.loading} investigationLoading={createInvestigation.loading} emlLoading={analyzeEml.loading} investigationError={createInvestigation.error?.message || analyzeEml.error?.message || investigations.error?.message} onCreateInvestigation={issueInvestigation} onUploadEml={uploadEml} dnsChanges={dnsChanges.rows} secretImporting={configureResendSecret.loading} secretImportError={configureResendSecret.error?.message} onImportResendSecret={importResendSecret} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </div>
  );
}
