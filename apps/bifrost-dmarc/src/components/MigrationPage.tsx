import { AlertTriangle, Check, Cloud, ExternalLink, LoaderCircle, MailQuestion, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { detectedDnsProvider } from "../lib/dns";
import { domainHasNoEmail, mailRouteLabel } from "../lib/mail";
import { formatDate, formatNumber, formatPercent } from "../lib/format";
import {
  ACTION_LABELS,
  ACTION_ORDER,
  POLICY_BUCKET_LABELS,
  POLICY_STAGE_LABELS,
  REPORTING_STAGE_LABELS,
  classifyDomainMigration,
  summarizeMissingDmarcReadiness,
  type BulkMigrationOperation,
  type DomainAction,
  type DomainMigrationState,
  type PolicyBucket,
} from "../lib/migration";
import type { DnsComparison, DomainSummary, MigrationRun, MigrationTask, OrganizationSummary, SpfSource } from "../types";
import { BfAlert } from "./bifrost/BfAlert";
import { BfButton } from "./bifrost/BfButton";
import { BfChip } from "./bifrost/BfChip";
import { BfCombobox, type BfComboboxOption } from "./bifrost/BfCombobox";
import { BfCopyField } from "./bifrost/BfCopyField";
import { BfDataTable, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfDialog } from "./bifrost/BfDialog";
import { BfSelect, BfTextField } from "./bifrost/BfField";
import { BfRefreshButton } from "./bifrost/BfRefreshButton";
import { BfSwitch } from "./bifrost/BfSelection";
import { CloudflareMark } from "./CloudflareMark";

interface MigrationPageProps {
  domains: DomainSummary[];
  sources: SpfSource[];
  organizations: OrganizationSummary[];
  runs: MigrationRun[];
  tasks: MigrationTask[];
  loading: boolean;
  syncing: boolean;
  mapping: boolean;
  applying: boolean;
  starting: boolean;
  error?: string;
  onSync: () => Promise<void>;
  onMap: (domainId: string, organizationId: string) => Promise<void>;
  onStartMigration: (operation: BulkMigrationOperation, domainIds: string[], confirmNoEmail?: boolean) => Promise<void>;
  onCompareDns: (domainId: string, kind: "dmarc" | "spf", settings: Record<string, unknown>) => Promise<DnsComparison>;
  onApplyDns: (domainId: string, kind: "dmarc" | "spf", expectedRecord: string, settings: Record<string, unknown>) => Promise<DnsComparison>;
}

const POLICY_ORDER: PolicyBucket[] = ["missing", "monitor", "quarantine", "reject", "strict"];

const BULK_ACTIONS: Array<{ operation: BulkMigrationOperation; label: string; context: string; detail: string; reviewLabel: string }> = [
  { operation: "monitor", label: "Set Up DNS", context: "No DMARC", detail: "Create p=none at 100% so reporting begins without affecting delivery.", reviewLabel: "Ready Domains" },
  { operation: "reject_no_mail", label: "Publish Reject", context: "Confirm No Email Use", detail: "Confirm these domains do not send or receive email, then publish p=reject at 100% with strict alignment.", reviewLabel: "Direct Reject Candidates" },
  { operation: "reporting", label: "Move Reporting", context: "External RUA", detail: "Keep the current policy and replace the aggregate-report destination exactly once.", reviewLabel: "Reporting Changes" },
  { operation: "quarantine", label: "Enforce", context: "Evidence Ready", detail: "Move monitor-only domains with current, 98%+ compliant evidence to quarantine at 100%.", reviewLabel: "Quarantine Changes" },
  { operation: "strict", label: "Tighten Policy", context: "Enforcement Ready", detail: "Move eligible quarantine or relaxed-reject domains to reject with strict alignment.", reviewLabel: "Strict Policy Changes" },
];

function dmarcTag(record: string | undefined, tag: string) {
  const segment = record?.split(";").map((part) => part.trim()).find((part) => part.toLowerCase().startsWith(`${tag.toLowerCase()}=`));
  return segment?.split("=", 2)[1]?.trim().toLowerCase() ?? "";
}

function existingDmarcSettings(domain?: DomainSummary) {
  if (!domain?.has_dmarc && domain && domainHasNoEmail(domain)) return { policy: "reject", subdomain_policy: "", pct: 100, adkim: "s", aspf: "s" };
  if (!domain?.has_dmarc) return { policy: "none", subdomain_policy: "", pct: 100, adkim: "r", aspf: "r" };
  return {
    policy: ["none", "quarantine", "reject"].includes(domain.dmarc_policy) ? domain.dmarc_policy : "none",
    subdomain_policy: domain.dmarc_subdomain_policy ?? "",
    pct: domain.dmarc_pct ?? 100,
    adkim: dmarcTag(domain.dmarc_record, "adkim") === "s" ? "s" : "r",
    aspf: dmarcTag(domain.dmarc_record, "aspf") === "s" ? "s" : "r",
  };
}

function eligibleFor(operation: BulkMigrationOperation, state?: DomainMigrationState) {
  if (!state) return false;
  if (operation === "reporting") return state.reportingEligible;
  if (operation === "monitor") return state.monitorEligible;
  if (operation === "reject_no_mail") return state.rejectNoMailCandidate;
  if (operation === "quarantine") return state.quarantineEligible;
  return state.strictEligible;
}

function statusTone(value: string): "success" | "warning" | "danger" | "info" | "neutral" {
  if (["reporting_current", "strict", "complete", "completed", "skipped"].includes(value)) return "success";
  if (["missing_record", "missing", "resolve_issue", "failed", "reporting_stale"].includes(value)) return "danger";
  if (["needs_reporting", "verify_dns", "review_mail_use", "setup_dns", "move_reporting", "review_evidence", "monitor_coverage", "monitoring", "completed_with_errors"].includes(value)) return "warning";
  if (["await_reports", "publish_reject", "enforce", "tighten_policy", "ready_for_enforcement", "staged_enforcement", "enforced", "queued", "processing"].includes(value)) return "info";
  return "neutral";
}

function policyTone(value: PolicyBucket): "success" | "warning" | "danger" | "info" | "neutral" {
  if (value === "missing") return "danger";
  if (value === "monitor") return "warning";
  if (value === "quarantine" || value === "reject") return "info";
  return "success";
}

function operationName(operation: BulkMigrationOperation) {
  return BULK_ACTIONS.find((item) => item.operation === operation)?.label ?? operation;
}

function operationDescription(operation: BulkMigrationOperation) {
  return BULK_ACTIONS.find((item) => item.operation === operation)?.detail ?? "";
}

function migrationFailureMessage(error?: string) {
  const value = error || "The domain migration failed.";
  if (/EasyDMARC CNAME or Bifrost TXT record changed after comparison/i.test(value)) {
    return "Cutover paused because DNS changed. Nothing was removed. Open this domain to refresh the comparison, then retry.";
  }
  if (/managed DMARC records changed after comparison/i.test(value)) {
    return "DNS changed before cutover. Nothing was removed. Open this domain to refresh the comparison, then retry.";
  }
  return value;
}

function PolicyPosture({ counts, total, selected, onSelect }: { counts: Record<PolicyBucket, number>; total: number; selected: "all" | PolicyBucket; onSelect: (value: "all" | PolicyBucket) => void }) {
  const strictPercent = total ? Math.round((counts.strict / total) * 100) : 0;
  return <section className="policy-posture" aria-labelledby="policy-posture-title">
    <header>
      <div><h2 id="policy-posture-title">Policy Posture</h2><p>Each active domain appears once. Strict means reject at 100% with strict DKIM and SPF alignment.</p></div>
      <div className="policy-posture__completion"><strong>{strictPercent}%</strong><span>strict</span></div>
    </header>
    <div className="policy-posture__bar" aria-label={`${counts.strict} of ${total} domains are strict`}>
      {POLICY_ORDER.map((bucket) => counts[bucket] ? <span key={bucket} className={`policy-posture__segment policy-posture__segment--${bucket}`} style={{ flexGrow: counts[bucket] }} title={`${POLICY_BUCKET_LABELS[bucket]}: ${counts[bucket]}`} /> : null)}
    </div>
    <div className="policy-posture__legend" role="group" aria-label="Filter by policy">
      {POLICY_ORDER.map((bucket) => <button type="button" key={bucket} aria-pressed={selected === bucket} onClick={() => onSelect(selected === bucket ? "all" : bucket)}><i className={`policy-posture__key policy-posture__key--${bucket}`} aria-hidden="true" /><span>{POLICY_BUCKET_LABELS[bucket]}</span><strong>{formatNumber(counts[bucket])}</strong></button>)}
    </div>
  </section>;
}

export function MigrationPage({ domains, sources, organizations, runs, tasks, loading, syncing, mapping, applying, starting, error, onSync, onMap, onStartMigration, onCompareDns, onApplyDns }: MigrationPageProps) {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState<"all" | DomainAction>("all");
  const [policyFilter, setPolicyFilter] = useState<"all" | PolicyBucket>("all");
  const [selectedRowIds, setSelectedRowIds] = useState<string[]>([]);
  const [selected, setSelected] = useState<DomainSummary>();
  const [mappingOrganizationId, setMappingOrganizationId] = useState("");
  const [comparison, setComparison] = useState<DnsComparison>();
  const [comparisonError, setComparisonError] = useState("");
  const [comparing, setComparing] = useState(false);
  const [applied, setApplied] = useState(false);
  const [bulkOperation, setBulkOperation] = useState<BulkMigrationOperation>();
  const [confirmNoEmail, setConfirmNoEmail] = useState(false);
  const [readyOperation, setReadyOperation] = useState<BulkMigrationOperation>("monitor");
  const [queuedAfterRunId, setQueuedAfterRunId] = useState<string | null>(null);
  const compareDnsRef = useRef(onCompareDns);

  const activeDomains = useMemo(() => domains.filter((domain) => domain.lifecycle_status !== "archived"), [domains]);
  const stateById = useMemo(() => new Map(activeDomains.map((domain) => [domain.id, classifyDomainMigration(domain)])), [activeDomains]);
  const policyCounts = useMemo(() => {
    const counts: Record<PolicyBucket, number> = { missing: 0, monitor: 0, quarantine: 0, reject: 0, strict: 0 };
    activeDomains.forEach((domain) => { counts[stateById.get(domain.id)!.policyBucket] += 1; });
    return counts;
  }, [activeDomains, stateById]);
  const actionCounts = useMemo(() => {
    const counts = Object.fromEntries(ACTION_ORDER.map((action) => [action, 0])) as Record<DomainAction, number>;
    activeDomains.forEach((domain) => { counts[stateById.get(domain.id)!.action] += 1; });
    return counts;
  }, [activeDomains, stateById]);
  const reportingCounts = useMemo(() => ({
    current: activeDomains.filter((domain) => stateById.get(domain.id)?.reportingStage === "reporting_current").length,
    awaiting: activeDomains.filter((domain) => stateById.get(domain.id)?.reportingStage === "awaiting_reports").length,
    migration: activeDomains.filter((domain) => stateById.get(domain.id)?.reportingStage === "needs_reporting").length,
  }), [activeDomains, stateById]);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return activeDomains.filter((domain) => {
      const state = stateById.get(domain.id)!;
      if (actionFilter !== "all" && state.action !== actionFilter) return false;
      if (policyFilter !== "all" && state.policyBucket !== policyFilter) return false;
      return !query || `${domain.organization_name} ${domain.domain} ${domain.dmarc_policy} ${state.actionLabel}`.toLowerCase().includes(query);
    });
  }, [actionFilter, activeDomains, policyFilter, search, stateById]);
  const selectedDomains = useMemo(() => activeDomains.filter((domain) => selectedRowIds.includes(domain.id)), [activeDomains, selectedRowIds]);
  const latestRun = runs[0];
  const latestTasks = useMemo(() => tasks.filter((task) => task.run_id === latestRun?.id).sort((a, b) => (a.ordering ?? 0) - (b.ordering ?? 0)), [latestRun?.id, tasks]);
  const selectedSources = useMemo(() => sources.filter((source) => source.domain === selected?.domain), [selected?.domain, sources]);
  const dmarcSettings = useMemo(() => existingDmarcSettings(selected), [selected]);
  const eligibleByOperation = useMemo(() => Object.fromEntries(BULK_ACTIONS.map(({ operation }) => [operation, activeDomains.filter((domain) => eligibleFor(operation, stateById.get(domain.id)))])) as Record<BulkMigrationOperation, DomainSummary[]>, [activeDomains, stateById]);
  const selectedByOperation = useMemo(() => Object.fromEntries(BULK_ACTIONS.map(({ operation }) => [operation, selectedDomains.filter((domain) => eligibleFor(operation, stateById.get(domain.id)))])) as Record<BulkMigrationOperation, DomainSummary[]>, [selectedDomains, stateById]);
  const missingReadiness = useMemo(() => summarizeMissingDmarcReadiness(activeDomains), [activeDomains]);

  const organizationOptions = useMemo<BfComboboxOption[]>(() => [
    { value: "", label: "Unmapped", description: "No Bifrost Organization owns this domain yet." },
    ...organizations.map((organization) => ({ value: organization.id, label: organization.name, description: organization.domain || undefined })),
  ], [organizations]);

  const columns = useMemo<BfDataColumn<DomainSummary>[]>(() => [
    { id: "organization", header: "Organization", width: "17%", sortable: true, sortValue: (domain) => domain.organization_name || "", cell: (domain) => <span className="data-row-name"><strong>{domain.organization_name || "Unmapped"}</strong><small>{domain.mapping_status === "mapped" ? "Ownership confirmed" : "Mapping required"}</small></span> },
    { id: "domain", header: "Domain", width: "17%", sortable: true, sortValue: (domain) => domain.domain, cell: (domain) => <span className="data-row-name"><strong className="domain-name">{domain.domain}</strong><small>{domain.cloudflare_zone_id ? "Cloudflare DNS" : detectedDnsProvider(domain) || "Manual DNS"}</small></span> },
    { id: "mail", header: "Mail", width: "11%", sortable: true, sortValue: mailRouteLabel, cell: (domain) => <span className="data-row-name"><strong>{domainHasNoEmail(domain) ? "No Email Use" : mailRouteLabel(domain)}</strong><small>{domain.email_usage_override ? "Operator confirmed" : domain.mx_provider || "Public DNS"}</small></span> },
    { id: "policy", header: "Policy", width: "12%", sortable: true, sortValue: (domain) => stateById.get(domain.id)?.policyBucket || "", cell: (domain) => { const state = stateById.get(domain.id)!; return <span className="data-row-name"><BfChip tone={policyTone(state.policyBucket)}>{POLICY_BUCKET_LABELS[state.policyBucket]}</BfChip><small>{domain.has_dmarc ? `${domain.dmarc_pct ?? 100}% coverage` : "No DMARC record"}</small></span>; } },
    { id: "reporting", header: "Reporting", width: "13%", sortable: true, sortValue: (domain) => stateById.get(domain.id)?.reportingStage || "", cell: (domain) => { const stage = stateById.get(domain.id)!.reportingStage; return <span className="data-row-name"><BfChip tone={statusTone(stage)}>{REPORTING_STAGE_LABELS[stage]}</BfChip>{domain.dmarc_record_type === "CNAME" ? <small>Managed by {domain.dmarc_managed_provider || "external provider"}</small> : null}</span>; } },
    { id: "evidence", header: "Evidence", width: "10%", align: "end", sortable: true, sortValue: (domain) => domain.compliance ?? 0, cell: (domain) => <span className="data-row-name data-row-name--end"><strong>{formatPercent(domain.compliance)}</strong><small>{formatNumber(domain.volume)} messages</small></span> },
    { id: "action", header: "Action", width: "20%", sortable: true, sortValue: (domain) => stateById.get(domain.id)?.actionLabel || "", cell: (domain) => { const state = stateById.get(domain.id)!; return <span className="data-row-name"><BfChip tone={statusTone(state.action)}>{state.actionLabel}</BfChip><small>{state.actionDetail}</small></span>; } },
  ], [stateById]);

  useEffect(() => { compareDnsRef.current = onCompareDns; }, [onCompareDns]);
  useEffect(() => {
    if (queuedAfterRunId === null || !latestRun?.id || latestRun.id === queuedAfterRunId) return;
    setQueuedAfterRunId(null);
  }, [latestRun?.id, queuedAfterRunId]);
  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setComparison(undefined);
    setComparisonError("");
    setComparing(true);
    void compareDnsRef.current(selected.id, "dmarc", dmarcSettings)
      .then((value) => { if (!cancelled) setComparison(value); })
      .catch((failure: unknown) => { if (!cancelled) setComparisonError(failure instanceof Error ? failure.message : "DMARC comparison failed."); })
      .finally(() => { if (!cancelled) setComparing(false); });
    return () => { cancelled = true; };
  }, [selected?.id]);

  const openDomain = (domain: DomainSummary) => {
    setSelected(domain);
    setMappingOrganizationId(domain.organization_id || "");
    setApplied(false);
  };
  const saveMapping = async () => {
    if (!selected) return;
    await onMap(selected.id, mappingOrganizationId);
  };
  const applyDomain = async () => {
    if (!selected || !comparison) return;
    setComparisonError("");
    try {
      const result = await onApplyDns(selected.id, "dmarc", comparison.record, dmarcSettings);
      setComparison(result);
      setApplied(true);
    } catch (failure) {
      setComparing(true);
      try {
        const refreshed = await onCompareDns(selected.id, "dmarc", dmarcSettings);
        setComparison(refreshed);
        setComparisonError(failure instanceof Error && /changed after comparison/i.test(failure.message)
          ? "DNS changed before Bifrost could finish. Nothing was removed. The comparison is current again; review it and retry."
          : failure instanceof Error ? failure.message : "The DNS update failed. The comparison has been refreshed.");
      } finally {
        setComparing(false);
      }
    }
  };
  const beginBulk = (operation: BulkMigrationOperation, eligible: DomainSummary[]) => {
    setConfirmNoEmail(false);
    setSelectedRowIds(eligible.map((domain) => domain.id));
    setActionFilter(operation === "monitor" ? "setup_dns" : operation === "reject_no_mail" ? "publish_reject" : operation === "reporting" ? "move_reporting" : operation === "quarantine" ? "enforce" : "tighten_policy");
    setPolicyFilter("all");
    setBulkOperation(operation);
  };
  const confirmBulk = async () => {
    if (!bulkOperation) return;
    if (bulkOperation === "reject_no_mail" && !confirmNoEmail) return;
    const eligible = selectedByOperation[bulkOperation];
    const previousRunId = latestRun?.id ?? "";
    await onStartMigration(bulkOperation, eligible.map((domain) => domain.id), bulkOperation === "reject_no_mail" ? confirmNoEmail : undefined);
    setQueuedAfterRunId(previousRunId);
    setBulkOperation(undefined);
    setConfirmNoEmail(false);
    setSelectedRowIds([]);
  };

  const readyDomains = eligibleByOperation[readyOperation];
  const bulkDomains = bulkOperation ? selectedByOperation[bulkOperation] : [];
  const latestProgress = latestRun?.requested ? Math.round(((latestRun.completed + latestRun.skipped + latestRun.failed) / latestRun.requested) * 100) : 0;
  const activeBulkAction = BULK_ACTIONS.find((item) => item.operation === readyOperation)!;

  return (
    <div className="page migration-page page-enter" aria-busy={loading}>
      <header className="page-header migration-header">
        <div><h1>Migration &amp; Enforcement</h1><p>Bring reporting into Bifrost, review evidence, and advance every domain toward strict enforcement.</p></div>
        <BfRefreshButton label="Reconcile Domain Inventory" loading={syncing} onClick={onSync} />
      </header>

      <PolicyPosture counts={policyCounts} total={activeDomains.length} selected={policyFilter} onSelect={(value) => { setPolicyFilter(value); setActionFilter("all"); }} />
      <div className="reporting-summary" aria-label="Reporting coverage"><span><strong>{formatNumber(reportingCounts.current)}</strong> reporting to Bifrost</span><span><strong>{formatNumber(reportingCounts.awaiting)}</strong> awaiting first reports</span><span><strong>{formatNumber(reportingCounts.migration)}</strong> still need reporting moved</span></div>

      <section className="migration-workbench" aria-labelledby="bulk-actions-title">
        <header><div><h2 id="bulk-actions-title">Bulk Actions</h2><p>Only domains that satisfy each action’s DNS and evidence safeguards are included.</p></div><BfChip tone="info">{formatNumber(readyDomains.length)} ready</BfChip></header>
        <div className="migration-workbench__body">
          <div className="migration-workbench__choices" role="group" aria-label="Bulk action">
            {BULK_ACTIONS.map((item) => <button type="button" key={item.operation} aria-pressed={readyOperation === item.operation} onClick={() => setReadyOperation(item.operation)}><span>{item.context}</span><strong>{item.label}</strong><small>{item.operation === "monitor" ? `${formatNumber(missingReadiness.ready)} ready · ${formatNumber(missingReadiness.total)} total` : `${formatNumber(eligibleByOperation[item.operation].length)} ready`}</small></button>)}
          </div>
          <div className="migration-workbench__decision"><div><strong>{activeBulkAction.label}</strong><p>{activeBulkAction.detail}</p>{readyOperation === "monitor" ? <div className="migration-workbench__readiness" aria-label="No DMARC readiness"><strong>{formatNumber(missingReadiness.ready)} of {formatNumber(missingReadiness.total)} ready</strong>{missingReadiness.reviewEmailUse ? <span>{formatNumber(missingReadiness.reviewEmailUse)} need email-use review</span> : null}{missingReadiness.directReject ? <span>{formatNumber(missingReadiness.directReject)} should publish reject instead</span> : null}{missingReadiness.manualDns ? <span>{formatNumber(missingReadiness.manualDns)} require manual DNS</span> : null}{missingReadiness.blocked ? <span>{formatNumber(missingReadiness.blocked)} need mapping or DNS verification</span> : null}</div> : null}</div><BfButton size="compact" disabled={!readyDomains.length || starting} onClick={() => beginBulk(readyOperation, readyDomains)}>Review {formatNumber(readyDomains.length)} {activeBulkAction.reviewLabel}</BfButton></div>
        </div>
        {actionCounts.resolve_issue ? <div className="migration-workbench__exceptions"><AlertTriangle aria-hidden="true" /><div><strong>{actionCounts.resolve_issue} domains need attention</strong><span>Resolve ownership, stale reporting, or manual DNS before bulk progression.</span></div><BfButton size="compact" variant="ghost" onClick={() => { setActionFilter("resolve_issue"); setPolicyFilter("all"); }}>Review Issues</BfButton></div> : null}
        {actionCounts.review_mail_use ? <div className="migration-workbench__exceptions migration-workbench__exceptions--mail"><MailQuestion aria-hidden="true" /><div><strong>{actionCounts.review_mail_use} domains need an email-use decision</strong><span>These domains have no explicit MX route. Confirm email use before choosing monitor-only or direct reject.</span></div><BfButton size="compact" variant="ghost" onClick={() => { setActionFilter("review_mail_use"); setPolicyFilter("all"); }}>Review Email Use</BfButton></div> : null}
      </section>

      {queuedAfterRunId !== null ? <BfAlert tone="success" title="Migration Queued">Bifrost accepted the workflow. Run and per-domain progress will appear here automatically.</BfAlert> : null}
      {latestRun ? <section className="migration-run" aria-live="polite"><div className="migration-run__heading"><div><strong>{operationName(latestRun.operation)}</strong><span>{latestRun.status.replace(/_/g, " ")} · started {formatDate(latestRun.created_at)}</span></div><BfChip tone={statusTone(latestRun.status)}>{latestRun.status.replace(/_/g, " ")}</BfChip></div><div className="migration-run__track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={latestProgress}><span style={{ transform: `scaleX(${latestProgress / 100})` }} /></div><div className="migration-run__counts"><span>{latestRun.completed} completed</span><span>{latestRun.skipped} already current</span><span>{latestRun.failed} failed</span><span>{latestRun.requested} total</span></div>{latestTasks.some((task) => task.status === "failed") ? <div className="migration-run__failures">{latestTasks.filter((task) => task.status === "failed").slice(0, 5).map((task) => <span key={task.id}><strong>{task.domain}</strong>{migrationFailureMessage(task.error)}</span>)}</div> : null}</section> : null}

      <div className="chromatic-section"><span>Domain Queue</span><i aria-hidden="true" /></div>
      <BfDataTable
        className="migration-table"
        ariaLabel="Domain migration and enforcement queue"
        rows={filtered}
        columns={columns}
        getRowId={(domain) => domain.id}
        loading={loading}
        loadingRowCount={8}
        onRowActivate={openDomain}
        defaultSort={{ columnId: "organization", direction: "ascending" }}
        emptyState={{ title: "No domains match these filters", description: "Choose another action or policy, or clear the search." }}
        toolbar={<><BfTextField className="data-toolbar-search" label="Search Domains" value={search} onChange={(event) => setSearch(event.target.value)} leadingIcon={<Search size={15} />} placeholder="Search organizations, domains, policies, or actions" /><BfSelect className="data-toolbar-mapping" label="Action" value={actionFilter} onValueChange={(value) => setActionFilter(value as "all" | DomainAction)} options={[{ value: "all", label: "All Actions" }, ...ACTION_ORDER.map((action) => ({ value: action, label: ACTION_LABELS[action] }))]} />{selectedRowIds.length ? BULK_ACTIONS.map(({ operation, label }) => selectedByOperation[operation].length ? <BfButton key={operation} size="compact" onClick={() => setBulkOperation(operation)}>{label} {selectedByOperation[operation].length}</BfButton> : null) : null}</>}
        selection="multiple"
        selectedRowIds={selectedRowIds}
        onSelectionChange={setSelectedRowIds}
        isRowSelectable={(domain) => BULK_ACTIONS.some(({ operation }) => eligibleFor(operation, stateById.get(domain.id)))}
        footer={<span>{filtered.length} of {activeDomains.length} active domains shown{policyFilter !== "all" ? ` · ${POLICY_BUCKET_LABELS[policyFilter]} policy` : ""}</span>}
        maxHeight="min(58vh, 46rem)"
        minWidth="72rem"
      />

      <BfDialog open={Boolean(bulkOperation)} onOpenChange={(open) => { if (!open) { setBulkOperation(undefined); setConfirmNoEmail(false); } }} title={bulkOperation === "reject_no_mail" ? "Confirm No Email Use & Publish Reject" : bulkOperation ? operationName(bulkOperation) : "Bulk DNS Change"} description={bulkOperation ? operationDescription(bulkOperation) : ""} footer={<><BfButton variant="ghost" onClick={() => { setBulkOperation(undefined); setConfirmNoEmail(false); }}>Cancel</BfButton><BfButton icon={<CloudflareMark />} onClick={confirmBulk} disabled={starting || !bulkDomains.length || (bulkOperation === "reject_no_mail" && !confirmNoEmail)}>{starting ? "Queueing…" : bulkOperation === "reject_no_mail" ? `Confirm & Queue ${bulkDomains.length} Domain${bulkDomains.length === 1 ? "" : "s"}` : `Queue ${bulkDomains.length} Domain${bulkDomains.length === 1 ? "" : "s"}`}</BfButton></>}>
        <div className="migration-confirm"><strong>{bulkDomains.length} eligible domains</strong><p>Bifrost rechecks every Cloudflare record immediately before writing it. Changed, duplicated, or inaccessible records fail individually and remain visible in run history.</p>{bulkOperation === "reject_no_mail" ? <BfSwitch checked={confirmNoEmail} onChange={setConfirmNoEmail} label="I Confirm These Domains Do Not Send or Receive Email" description="Bifrost will save this decision and publish p=reject at 100% with strict DKIM and SPF alignment." /> : null}<div>{bulkDomains.slice(0, 8).map((domain) => <span key={domain.id}>{domain.organization_name} · {domain.domain}</span>)}{bulkDomains.length > 8 ? <span>+ {bulkDomains.length - 8} more</span> : null}</div></div>
      </BfDialog>

      <BfDialog open={Boolean(selected)} onOpenChange={(open) => !open && setSelected(undefined)} title={selected?.domain ?? "Domain"} description={selected ? stateById.get(selected.id)?.actionDetail : undefined} footer={<><BfButton variant="ghost" onClick={() => setSelected(undefined)}>Close</BfButton><BfButton trailingIcon={<ExternalLink size={14} />} onClick={() => selected && navigate(`/domains?domain=${encodeURIComponent(selected.id)}`)}>Manage Policy</BfButton></>}>
        {selected ? <div className="migration-detail">
          <section><div className="detail-heading"><h4>Ownership</h4><BfChip tone={selected.mapping_status === "mapped" ? "success" : "warning"}>{selected.mapping_status}</BfChip></div><BfCombobox label="Organization" value={mappingOrganizationId} onValueChange={setMappingOrganizationId} options={organizationOptions} searchPlaceholder="Search Organizations" /><BfButton size="compact" variant="secondary" onClick={saveMapping} disabled={mapping}>{mapping ? "Saving…" : "Save Organization"}</BfButton></section>
          <section><div className="detail-heading"><h4>Current State</h4><span>{formatDate(selected.cached_at)}</span></div><div className="migration-state-grid"><div><span>Action</span><BfChip tone={statusTone(stateById.get(selected.id)!.action)}>{stateById.get(selected.id)!.actionLabel}</BfChip></div><div><span>Policy</span><BfChip tone={policyTone(stateById.get(selected.id)!.policyBucket)}>{POLICY_BUCKET_LABELS[stateById.get(selected.id)!.policyBucket]}</BfChip></div><div><span>Reporting</span><BfChip tone={statusTone(stateById.get(selected.id)!.reportingStage)}>{REPORTING_STAGE_LABELS[stateById.get(selected.id)!.reportingStage]}</BfChip></div><div><span>Evidence</span><strong>{formatPercent(selected.compliance)} · {formatNumber(selected.volume)} messages</strong></div><div><span>Policy Detail</span><strong>{POLICY_STAGE_LABELS[stateById.get(selected.id)!.policyStage]}</strong></div><div><span>Approved SPF Sources</span><strong>{selectedSources.length}</strong></div></div>{selected.dmarc_record_type === "CNAME" && selected.dmarc_cname_target ? <BfCopyField label={`${selected.dmarc_managed_provider || "Managed"} CNAME`} value={selected.dmarc_cname_target} /> : null}{selected.dmarc_record ? <BfCopyField label="Effective DMARC Policy" value={selected.dmarc_record} /> : null}</section>
          <section><div className="detail-heading"><h4>Managed DNS Change</h4><Cloud aria-hidden="true" /></div>{comparing ? <span className="dns-comparison-status" role="status"><LoaderCircle className="bds-spin" aria-hidden="true" />Comparing with DNS…</span> : null}{comparisonError ? <BfAlert tone="danger" title="DNS Update Needs Review">{comparisonError}</BfAlert> : null}{comparison ? <div className={`record-result record-result--${comparison.action}`}>{comparison.current_record_type === "CNAME" && comparison.current_cname_target ? <BfCopyField label="Current Managed CNAME" value={comparison.current_cname_target} /> : null}<BfCopyField label="Bifrost DMARC Value" value={comparison.record} tone="managed" /><p>{comparison.action === "none" ? "The managed value is already current." : comparison.action === "manual" ? "Copy this value to the authoritative DNS provider." : comparison.current_record_type === "CNAME" ? "This replaces the external managed CNAME with a Bifrost-managed TXT record." : "Cloudflare is ready for this guarded update."}</p>{comparison.action !== "none" && comparison.action !== "manual" && !applied ? <BfButton icon={<CloudflareMark />} onClick={applyDomain} disabled={applying}>{applying ? "Updating…" : "Update Cloudflare"}</BfButton> : null}{applied ? <span className="applied-state"><Check aria-hidden="true" />Cloudflare Updated</span> : null}</div> : null}</section>
        </div> : null}
      </BfDialog>
      {error ? <div className="error-banner" role="alert">{error}</div> : null}
    </div>
  );
}
