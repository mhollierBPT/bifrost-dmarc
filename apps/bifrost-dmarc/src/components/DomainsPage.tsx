import { Archive, Building2, Check, CheckCircle2, CircleHelp, CircleOff, Clipboard, ExternalLink, Globe2, Mail, MailX, Plus, RefreshCw, RotateCcw, Search, Settings2, TriangleAlert, X, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { formatDate, formatNumber, formatPercent } from "../lib/format";
import { detectedDnsProvider, dnsProviderEvidence, nameserverSummary } from "../lib/dns";
import { domainHasNoEmail, mailRouteDetail, mailRouteLabel } from "../lib/mail";
import type { DashboardData, DnsComparison, DomainSummary } from "../types";
import { BfActionMenu } from "./bifrost/BfActionMenu";
import { BfAlert } from "./bifrost/BfAlert";
import { BfButton, BfButtonLink, BfIconButton } from "./bifrost/BfButton";
import { BfCombobox, type BfComboboxOption } from "./bifrost/BfCombobox";
import { BfCopyField } from "./bifrost/BfCopyField";
import { BfDataTable, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfDialog } from "./bifrost/BfDialog";
import { BfSelect, BfTextField } from "./bifrost/BfField";
import { BfSwitch } from "./bifrost/BfSelection";
import { BfChip } from "./bifrost/BfChip";
import { BfTabs } from "./bifrost/BfTabs";
import { BfTooltip } from "./bifrost/BfTooltip";
import { BfRefreshButton } from "./bifrost/BfRefreshButton";
import { dmarcPolicyTone } from "../lib/dmarcPolicyTone";
import { ACTION_LABELS, ACTION_ORDER, classifyDomainMigration, domainNeedsAttention, type DomainAction } from "../lib/migration";
import { CloudflareMark } from "./CloudflareMark";
import { Drawer } from "./Drawer";
import { SpfBuilder } from "./SpfBuilder";

interface DomainsProps {
  data?: DashboardData;
  loading: boolean;
  syncing: boolean;
  mapping: boolean;
  onSync: () => Promise<void>;
  onMap: (domainId: string, organizationId: string) => Promise<void>;
  onMapAccount?: (accountId: string, organizationId: string) => Promise<void>;
  creating?: boolean;
  lifecycleChanging?: boolean;
  mutationError?: string;
  onCreateDomain?: (domain: string, organizationId: string) => Promise<DomainSummary>;
  onSetLifecycle?: (domainId: string, action: "archive" | "restore", reason?: string) => Promise<DomainSummary>;
  onBulkArchive?: (domainIds: string[]) => Promise<void>;
  emailUsageUpdating?: boolean;
  onSetEmailUsage?: (domainId: string, value: "" | "uses_email" | "no_email") => Promise<void>;
  comparing?: boolean;
  applying?: boolean;
  dnsError?: string;
  onCompareDns?: (domainId: string, kind: "dmarc" | "spf", settings: Record<string, unknown>) => Promise<DnsComparison>;
  onApplyDns?: (domainId: string, kind: "dmarc" | "spf", confirmDomain: string, expectedRecord: string, settings: Record<string, unknown>) => Promise<DnsComparison>;
  managerOnly?: boolean;
  requestedDomainId?: string;
  onManagerClose?: () => void;
}

const DMARC_COVERAGE_OPTIONS: BfComboboxOption[] = [
  { value: "100", label: "100% of Messages" },
  { value: "75", label: "75% of Messages" },
  { value: "50", label: "50% of Messages" },
  { value: "25", label: "25% of Messages" },
  { value: "10", label: "10% of Messages" },
  { value: "0", label: "0% of Messages" },
];

function dmarcTag(record: string | undefined, tag: string) {
  const segment = record
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.toLowerCase().startsWith(`${tag.toLowerCase()}=`));
  return segment?.split("=", 2)[1]?.trim().toLowerCase() ?? "";
}

export function DomainsPage({ data, loading, syncing, mapping, onSync, onMap, onMapAccount, creating, lifecycleChanging, mutationError, onCreateDomain, onSetLifecycle, onBulkArchive, emailUsageUpdating, onSetEmailUsage, comparing, applying, dnsError, onCompareDns, onApplyDns, managerOnly = false, requestedDomainId = "", onManagerClose }: DomainsProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [showOrphaned, setShowOrphaned] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [selectedRowIds, setSelectedRowIds] = useState<string[]>([]);
  const [bulkArchiveOpen, setBulkArchiveOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [manualDomain, setManualDomain] = useState("");
  const [manualOrganizationId, setManualOrganizationId] = useState("");
  const [lifecycleTarget, setLifecycleTarget] = useState<DomainSummary>();
  const [managed, setManaged] = useState<DomainSummary>();
  const [kind, setKind] = useState<"dmarc" | "spf">("dmarc");
  const [policy, setPolicy] = useState("none");
  const [subdomainPolicy, setSubdomainPolicy] = useState("");
  const [pct, setPct] = useState(100);
  const [adkim, setAdkim] = useState("r");
  const [aspf, setAspf] = useState("r");
  const [spfTerms, setSpfTerms] = useState<string[]>([]);
  const [comparison, setComparison] = useState<DnsComparison>();
  const [applied, setApplied] = useState(false);
  const [mappingOrganizationId, setMappingOrganizationId] = useState("");
  const [mapWholeAccount, setMapWholeAccount] = useState(true);
  const compareDnsRef = useRef(onCompareDns);
  const activeInventory = data?.domains?.length ? data.domains : data?.attention ?? [];
  const inventory = useMemo(
    () => [...activeInventory, ...(data?.archived_domains ?? [])],
    [activeInventory, data?.archived_domains],
  );

  const organizationFilter = searchParams.get("organization") ?? "";
  const mappingFilter = (["mapped", "unmapped"].includes(searchParams.get("mapping") ?? "") ? searchParams.get("mapping") : "all") as "all" | "mapped" | "unmapped";
  const attentionFilter = searchParams.get("attention") ?? "";
  const dmarcFilter = searchParams.get("dmarc") ?? "";
  const organizationName = data?.organizations.find((item) => item.id === organizationFilter)?.name;
  const setUrlFilter = (name: string, value: string, emptyValue = "") => {
    const next = new URLSearchParams(searchParams);
    if (!value || value === emptyValue) next.delete(name); else next.set(name, value);
    setSearchParams(next);
  };
  const domains = useMemo(() => {
    const query = search.trim().toLowerCase();
    return inventory.filter((domain) => {
      if (mappingFilter !== "all" && domain.mapping_status !== mappingFilter) return false;
      const migration = classifyDomainMigration(domain);
      if (attentionFilter === "all" && !domainNeedsAttention(domain)) return false;
      if (attentionFilter && attentionFilter !== "all" && migration.action !== attentionFilter) return false;
      if (dmarcFilter === "present" && !domain.has_dmarc) return false;
      if (dmarcFilter === "missing" && domain.has_dmarc) return false;
      if (showOrphaned && !domain.orphan_status) return false;
      if (!showArchived && domain.lifecycle_status === "archived") return false;
      if (organizationFilter && domain.organization_id !== organizationFilter) return false;
      if (!query) return true;
      return `${domain.domain} ${domain.organization_name} ${domain.cloudflare_account_name} ${detectedDnsProvider(domain)} ${domain.nameservers?.join(" ") ?? ""} ${domain.mx_provider} ${domain.mx_records?.map((record) => record.exchange).join(" ") ?? ""} ${domain.registration_status} ${domain.archive_reason} ${domain.dmarc_policy} ${domain.spf_status}`.toLowerCase().includes(query);
    });
  }, [attentionFilter, dmarcFilter, inventory, mappingFilter, organizationFilter, search, showArchived, showOrphaned]);

  const attentionOptions = useMemo(() => {
    const counts = new Map<DomainAction, number>();
    inventory.filter((domain) => domain.lifecycle_status !== "archived" && domainNeedsAttention(domain)).forEach((domain) => {
      const action = classifyDomainMigration(domain).action;
      counts.set(action, (counts.get(action) ?? 0) + 1);
    });
    return [
      { value: "", label: "All Domains" },
      { value: "all", label: `Needs Attention (${[...counts.values()].reduce((sum, count) => sum + count, 0)})` },
      ...ACTION_ORDER.filter((action) => counts.has(action)).map((action) => ({ value: action, label: `${ACTION_LABELS[action]} (${counts.get(action)})` })),
    ];
  }, [inventory]);

  const selectedActiveDomains = useMemo(
    () => inventory.filter((domain) => selectedRowIds.includes(domain.id) && domain.lifecycle_status !== "archived"),
    [inventory, selectedRowIds],
  );

  const accountDomainCount = managed?.cloudflare_account_id
    ? activeInventory.filter((domain) => domain.cloudflare_account_id === managed.cloudflare_account_id).length
    : 0;

  useEffect(() => {
    if (!managed) return;
    const current = inventory.find((domain) => domain.id === managed.id);
    if (current && current !== managed) setManaged(current);
  }, [inventory, managed?.id]);

  const invalidateComparison = () => {
    setComparison(undefined);
    setApplied(false);
  };

  const openManager = (domain: DomainSummary) => {
    setManaged(domain);
    setKind("dmarc");
    setPolicy(["missing", "not_checked", "lookup_failed", "unknown"].includes(domain.dmarc_policy) ? "none" : domain.dmarc_policy);
    setSubdomainPolicy(domain.dmarc_subdomain_policy ?? "");
    setPct(domain.dmarc_pct ?? 100);
    setAdkim(dmarcTag(domain.dmarc_record, "adkim") === "s" ? "s" : "r");
    setAspf(dmarcTag(domain.dmarc_record, "aspf") === "s" ? "s" : "r");
    setSpfTerms(domain.spf_terms ?? domain.spf_record?.split(/\s+/).slice(1) ?? ["~all"]);
    setMappingOrganizationId(domain.organization_id ?? "");
    setMapWholeAccount(Boolean(domain.cloudflare_account_id));
    invalidateComparison();
  };
  const closeManager = () => {
    setManaged(undefined);
    onManagerClose?.();
  };
  const organizationOptions = useMemo<BfComboboxOption[]>(() => [
    { value: "", label: "Unmapped", description: "No organization override" },
    ...(data?.organizations ?? []).map((organization) => ({ value: organization.id, label: organization.name, description: organization.domain || undefined })),
  ], [data?.organizations]);
  const coverageOptions = useMemo<BfComboboxOption[]>(() => {
    const current = String(pct);
    if (DMARC_COVERAGE_OPTIONS.some((option) => option.value === current)) return DMARC_COVERAGE_OPTIONS;
    return [{ value: current, label: `${current}% of Messages` }, ...DMARC_COVERAGE_OPTIONS];
  }, [pct]);
  const toneFor = (value?: string): "neutral" | "success" | "warning" | "danger" | "info" => {
    if (["reject", "valid", "mapped", "current"].includes(value ?? "")) return "success";
    if (["quarantine", "none", "unmapped", "awaiting", "stale", "multiple"].includes(value ?? "")) return "warning";
    if (["missing", "lookup_failed", "not_configured"].includes(value ?? "")) return "danger";
    if (["not_checked", "unknown"].includes(value ?? "")) return "warning";
    return "neutral";
  };
  const columns = useMemo<BfDataColumn<DomainSummary>[]>(() => [
    { id: "organization", header: "Organization", width: "18%", sortable: true, sortValue: (domain) => domain.organization_name ?? "", cell: (domain) => <span className="data-row-name"><strong>{domain.organization_name || "Unmapped"}</strong><small>{domain.cloudflare_account_name || detectedDnsProvider(domain) || (domain.management_mode === "manual" ? "Manually managed" : "DNS provider unknown")}</small></span> },
    { id: "domain", header: "Domain", width: "20%", sortable: true, sortValue: (domain) => domain.domain, cell: (domain) => <span className="data-row-name"><strong className="domain-name">{domain.domain}</strong><small>{domain.registration_status === "unregistered" ? "Not registered · automatically archived" : `${formatNumber(domain.volume)} messages · ${formatPercent(domain.compliance)} compliant`}</small></span> },
    { id: "inventory", header: "DNS", width: "12%", sortable: true, sortValue: managementLabel, cell: (domain) => <ManagementStatus domain={domain} /> },
    { id: "mail", header: "Mail", width: "12%", sortable: true, sortValue: mailRouteLabel, cell: (domain) => <MailRoutingStatus domain={domain} /> },
    { id: "dmarc", header: "DMARC", width: "9%", sortable: true, sortValue: (domain) => domain.dmarc_policy ?? "", cell: (domain) => <BfChip tone={dmarcPolicyTone(domain.dmarc_policy)}>{dnsStateLabel(domain.dmarc_policy)}</BfChip> },
    { id: "spf", header: "SPF", width: "6%", align: "center", sortable: true, sortValue: (domain) => domain.spf_status ?? "", cell: (domain) => <AuthStatusIcon status={domain.spf_status} label="SPF" /> },
    { id: "reporting", header: "Reporting", width: "10%", sortable: true, sortValue: (domain) => domain.reporting_status ?? "", cell: (domain) => <BfChip tone={toneFor(domain.reporting_status)}>{reportingStateLabel(domain.reporting_status)}</BfChip> },
    { id: "action", header: "Next Action", width: "18%", sortable: true, sortValue: (domain) => classifyDomainMigration(domain).actionLabel, cell: (domain) => { const state = classifyDomainMigration(domain); return <span className="attention-action"><BfChip tone={state.action === "complete" ? "success" : state.action === "await_reports" ? "info" : state.action === "resolve_issue" ? "danger" : "warning"}>{state.actionLabel}</BfChip><small title={state.actionDetail}>{state.actionDetail}</small></span>; } },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (domain) => <BfActionMenu label={`Actions for ${domain.domain}`} items={domain.lifecycle_status === "archived" ? [{ value: "restore", label: "Restore Domain", icon: <RotateCcw size={14} /> }] : [{ value: "manage", label: "Manage DNS", icon: <Settings2 size={14} /> }, { value: "archive", label: "Archive Domain", icon: <Archive size={14} />, tone: "danger", separatorBefore: true }]} onSelect={(value) => value === "manage" ? openManager(domain) : setLifecycleTarget(domain)} /> },
  ], []);

  useEffect(() => {
    if (managerOnly) return;
    const routeDomainId = searchParams.get("domain");
    const requestedDomain = inventory.find((domain) => domain.id === routeDomainId);
    if (!requestedDomain) return;
    openManager(requestedDomain);
    const next = new URLSearchParams(searchParams);
    next.delete("domain");
    setSearchParams(next, { replace: true });
  }, [inventory, managerOnly, requestedDomainId, searchParams, setSearchParams]);

  useEffect(() => {
    if (!managerOnly || !requestedDomainId) return;
    const requestedDomain = inventory.find((domain) => domain.id === requestedDomainId);
    if (!requestedDomain || managed?.id === requestedDomain.id) return;
    openManager(requestedDomain);
  }, [inventory, managed?.id, managerOnly, requestedDomainId]);

  const settings = kind === "dmarc"
    ? { policy, subdomain_policy: subdomainPolicy, pct, adkim, aspf }
    : { terms: spfTerms };

  useEffect(() => {
    compareDnsRef.current = onCompareDns;
  }, [onCompareDns]);

  const spfTermsKey = spfTerms.join("\u0000");
  useEffect(() => {
    if (!managed || !compareDnsRef.current) return;
    let cancelled = false;
    const requestSettings = kind === "dmarc"
      ? { policy, subdomain_policy: subdomainPolicy, pct, adkim, aspf }
      : { terms: spfTerms };
    const timer = window.setTimeout(() => {
      const compareDns = compareDnsRef.current;
      if (!compareDns) return;
      setApplied(false);
      void compareDns(managed.id, kind, requestSettings)
        .then((result) => {
          if (!cancelled) setComparison(result);
        })
        .catch(() => {
          if (!cancelled) setComparison(undefined);
        });
    }, 300);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [managed?.id, kind, policy, subdomainPolicy, pct, adkim, aspf, spfTermsKey]);

  const runApply = async () => {
    if (!managed || !onApplyDns || !comparison) return;
    setComparison(await onApplyDns(managed.id, kind, managed.domain, comparison.record, settings));
    setApplied(true);
  };

  const saveMapping = async () => {
    if (!managed) return;
    if (mapWholeAccount && managed.cloudflare_account_id && onMapAccount) {
      await onMapAccount(managed.cloudflare_account_id, mappingOrganizationId);
    } else {
      await onMap(managed.id, mappingOrganizationId);
    }
    closeManager();
  };

  const createDomain = async () => {
    if (!onCreateDomain || !manualDomain.trim()) return;
    await onCreateDomain(manualDomain, manualOrganizationId);
    setCreateOpen(false);
    setManualDomain("");
    setManualOrganizationId("");
  };

  const changeLifecycle = async () => {
    if (!lifecycleTarget || !onSetLifecycle) return;
    const action = lifecycleTarget.lifecycle_status === "archived" ? "restore" : "archive";
    await onSetLifecycle(
      lifecycleTarget.id,
      action,
      action === "archive" && lifecycleTarget.orphan_status
        ? `Archived after inventory reconciliation: ${lifecycleTarget.orphan_status.replace(/_/g, " ")}`
        : "",
    );
    setLifecycleTarget(undefined);
    if (managerOnly) closeManager();
  };

  const bulkArchive = async () => {
    if (!onBulkArchive || !selectedActiveDomains.length) return;
    await onBulkArchive(selectedActiveDomains.map((domain) => domain.id));
    setSelectedRowIds([]);
    setBulkArchiveOpen(false);
  };

  return (
    <div className={managerOnly ? "domain-manager-overlay-host" : "page page-enter"} aria-busy={loading}>
      {!managerOnly ? <>
      <header className="page-header">
        <div><h1>Domains</h1><p>Authentication posture, reporting coverage, organization overrides, and managed DNS.</p></div>
        <div className="page-header-actions"><BfButton variant="secondary" icon={<Plus />} onClick={() => setCreateOpen(true)}>Add Domain</BfButton><BfRefreshButton label="Refresh Domain Inventory" loading={syncing} onClick={onSync} /></div>
      </header>
      {attentionFilter ? <BfAlert tone="warning" title={attentionFilter === "all" ? `${domains.length} Domains Need Attention` : `${domains.length} Domains: ${ACTION_LABELS[attentionFilter as DomainAction] ?? "Filtered Action"}`}>Each row names the next action and why it is required. Open a row to resolve DNS, reporting, policy, or organization state.</BfAlert> : null}
      <BfDataTable
        ariaLabel="Domain inventory"
        rows={domains}
        columns={columns}
        getRowId={(domain) => domain.id}
        loading={loading}
        loadingRowCount={8}
        onRowActivate={(domain) => domain.lifecycle_status === "archived" ? setLifecycleTarget(domain) : openManager(domain)}
        defaultSort={{ columnId: "organization", direction: "ascending" }}
        emptyState={{ title: "No domains match these filters", description: "Clear a filter or search for another domain." }}
        toolbar={<>
          <BfTextField className="data-toolbar-search" label="Search Domains" value={search} onChange={(event) => setSearch(event.target.value)} leadingIcon={<Search size={15} />} placeholder="Search domains, organizations, or Cloudflare accounts" />
          <BfSelect className="data-toolbar-mapping" label="Mapping" value={mappingFilter} onValueChange={(value) => setUrlFilter("mapping", value, "all")} options={[{ value: "all", label: "All Domains" }, { value: "mapped", label: "Mapped Only" }, { value: "unmapped", label: "Unmapped Only" }]} />
          <BfSelect className="data-toolbar-attention" label="Next Action" value={attentionFilter} onValueChange={(value) => setUrlFilter("attention", value)} options={attentionOptions} />
          <div className="data-toolbar-switch"><BfSwitch checked={showOrphaned} onChange={setShowOrphaned} label="Orphaned Only" /></div>
          <div className="data-toolbar-switch"><BfSwitch checked={showArchived} onChange={setShowArchived} label="Show Archived" /></div>
          {selectedActiveDomains.length ? <div className="bulk-maintenance"><span>{selectedActiveDomains.length} selected</span><BfIconButton label="Archive Selected Domains" icon={<Archive />} variant="danger" size="compact" onClick={() => setBulkArchiveOpen(true)} /></div> : null}
          {organizationFilter ? <BfButton variant="ghost" trailingIcon={<X size={14} />} onClick={() => { const next = new URLSearchParams(searchParams); next.delete("organization"); setSearchParams(next); }}>{organizationName ?? "Selected organization"}</BfButton> : null}
        </>}
        selection="multiple"
        selectedRowIds={selectedRowIds}
        onSelectionChange={setSelectedRowIds}
        isRowSelectable={(domain) => domain.lifecycle_status !== "archived"}
        footer={<span>{domains.length} domains shown · {data?.summary.orphaned ?? 0} orphaned · {data?.summary.auto_archived ?? 0} auto-archived · {data?.summary.archived ?? 0} archived total</span>}
        maxHeight="min(68vh, 52rem)"
        minWidth="76rem"
      />

      <BfDialog open={bulkArchiveOpen} onOpenChange={setBulkArchiveOpen} title="Archive Selected Domains" description="Remove these domains from active dashboards while preserving their reports, SPF sources, and DNS audit history." footer={<><BfButton variant="ghost" onClick={() => setBulkArchiveOpen(false)}>Cancel</BfButton><BfButton variant="danger" icon={<Archive size={14} />} onClick={bulkArchive} disabled={lifecycleChanging}>{lifecycleChanging ? "Archiving…" : `Archive ${selectedActiveDomains.length} Domains`}</BfButton></>}>
        <div className="bulk-domain-list">{selectedActiveDomains.map((domain) => <div key={domain.id}><strong>{domain.domain}</strong><span>{domain.organization_name || "Unmapped"}</span></div>)}</div>
        {mutationError ? <div className="error-banner" role="alert">{mutationError}</div> : null}
      </BfDialog>

      <BfDialog open={createOpen} onOpenChange={setCreateOpen} title="Add Domain" description="Add a domain without Cloudflare. Bifrost will provide copyable DMARC and SPF records for manual DNS changes." footer={<><BfButton variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</BfButton><BfButton onClick={createDomain} disabled={creating || !manualDomain.trim()}>{creating ? "Adding…" : "Add Domain"}</BfButton></>}>
        <div className="form-grid domain-create-form"><BfTextField label="Domain" value={manualDomain} onChange={(event) => setManualDomain(event.target.value)} placeholder="example.com" autoComplete="off" /><BfCombobox label="Organization" value={manualOrganizationId} onValueChange={setManualOrganizationId} options={organizationOptions} searchPlaceholder="Search Organizations" /></div>
        {mutationError ? <div className="error-banner" role="alert">{mutationError}</div> : null}
      </BfDialog>
      </> : null}

      <BfDialog
        open={Boolean(lifecycleTarget)}
        onOpenChange={(open) => {
          if (!open) setLifecycleTarget(undefined);
        }}
        title={lifecycleTarget?.lifecycle_status === "archived" ? "Restore Domain" : "Archive Domain"}
        description={lifecycleTarget?.lifecycle_status === "archived"
          ? lifecycleTarget.registration_status === "unregistered"
            ? "Return this domain to active inventory. It will be automatically archived again if the registry still confirms it is unregistered during the next scan."
            : "Return this domain to active inventory. Retained reports and SPF history are already intact."
          : "Remove this domain from active dashboards without deleting retained reports, SPF sources, or DNS audit history."}
        footer={<>
          <BfButton variant="ghost" onClick={() => setLifecycleTarget(undefined)}>Cancel</BfButton>
          <BfButton
            variant={lifecycleTarget?.lifecycle_status === "archived" ? "primary" : "danger"}
            onClick={changeLifecycle}
            disabled={lifecycleChanging}
          >
            {lifecycleChanging ? "Updating…" : lifecycleTarget?.lifecycle_status === "archived" ? "Restore Domain" : "Archive Domain"}
          </BfButton>
        </>}
      >
        <p className="dialog-domain-summary"><strong>{lifecycleTarget?.domain}</strong><span>{lifecycleTarget?.organization_name || "Unmapped"}{lifecycleTarget?.orphan_status ? ` · ${lifecycleTarget.orphan_status.replace(/_/g, " ")}` : ""}</span></p>
        {lifecycleTarget?.registration_status === "unregistered" ? <BfAlert tone="warning" title="Registry Confirms Domain Is Unregistered">This is not merely a missing DNS record. The authoritative registration service returned no registration for this exact domain.</BfAlert> : null}
        {mutationError ? <div className="error-banner" role="alert">{mutationError}</div> : null}
      </BfDialog>

      {managed ? <Drawer className="dns-manager" ariaLabel={`Manage ${managed.domain}`} title={managed.domain} subtitle={<>{managementSubtitle(managed)} · checked {formatDate(managed.cached_at)}</>} actions={managed.lifecycle_status !== "archived" ? <BfIconButton label="Archive Domain" title="Archive Domain" icon={<Archive />} variant="danger" size="compact" onClick={() => setLifecycleTarget(managed)} /> : undefined} onClose={closeManager}>
        <OrphanGuidance domain={managed} />
        <section className="mapping-builder">
          <div className="builder-heading">
            <div><strong>Organization Mapping</strong><span>Manual overrides take priority over the one-to-one Cloudflare integration mapping.</span></div>
            <BfChip tone={managed.mapping_status === "mapped" ? "success" : "warning"}>{managed.mapping_status}</BfChip>
          </div>
          <div className="mapping-fields">
            <BfCombobox label="Organization" hideLabel value={mappingOrganizationId} onValueChange={setMappingOrganizationId} options={organizationOptions} searchPlaceholder="Search Organizations" />
            <div className="mapping-actions"><BfButton variant="secondary" onClick={saveMapping} disabled={mapping}>{mapping ? "Saving Mapping…" : "Save Mapping"}</BfButton></div>
            {managed.cloudflare_account_id && accountDomainCount > 1 ? <div className="account-mapping-scope"><BfSwitch checked={mapWholeAccount} onChange={setMapWholeAccount} label="Map Entire Cloudflare Account" description={`Also assign the selected organization to all ${accountDomainCount} domains in ${managed.cloudflare_account_name || "this Cloudflare account"}.`} /></div> : null}
          </div>
        </section>
        <MailRoutingPanel domain={managed} updating={emailUsageUpdating} onChange={async (value) => {
          if (!onSetEmailUsage) return;
          await onSetEmailUsage(managed.id, value);
          setManaged({ ...managed, email_usage_override: value });
        }} />
        <BfTabs label="DNS Record Type" items={[{ id: "dmarc", label: "DMARC Policy" }, { id: "spf", label: "SPF" }]} value={kind} onChange={(value) => { setKind(value as "dmarc" | "spf"); invalidateComparison(); }} distribution="equal" />
        {kind === "dmarc" ? <>
          <CurrentDmarcRecord domain={managed} />
          <div className="form-grid">
            <BfSelect label="Policy" value={policy} onValueChange={(value) => { setPolicy(value); invalidateComparison(); }} options={[{ value: "none", label: "Monitor Only" }, { value: "quarantine", label: "Send Failures to Spam" }, { value: "reject", label: "Reject Failures" }]} />
            <BfSelect label="Subdomain Policy" value={subdomainPolicy} onValueChange={(value) => { setSubdomainPolicy(value); invalidateComparison(); }} options={[{ value: "", label: "Inherit the Main Policy" }, { value: "none", label: "Monitor Only" }, { value: "quarantine", label: "Send Failures to Spam" }, { value: "reject", label: "Reject Failures" }]} />
            <BfSelect label="Policy Coverage" value={String(pct)} onValueChange={(value) => { setPct(Number(value)); invalidateComparison(); }} options={coverageOptions} />
            <BfSelect label="DKIM Alignment" value={adkim} onValueChange={(value) => { setAdkim(value); invalidateComparison(); }} options={[{ value: "r", label: "Relaxed" }, { value: "s", label: "Strict" }]} />
            <BfSelect label="SPF Alignment" value={aspf} onValueChange={(value) => { setAspf(value); invalidateComparison(); }} options={[{ value: "r", label: "Relaxed" }, { value: "s", label: "Strict" }]} />
          </div>
        </> : <SpfBuilder terms={spfTerms} onChange={(terms) => { setSpfTerms(terms); invalidateComparison(); }} />}
        <div className="manager-actions">
          <span className="dns-comparison-status" role="status" aria-live="polite">{comparing ? <><RefreshCw className="spin" aria-hidden="true" />Comparing with DNS…</> : null}</span>
          <Link to={`/reports?domain=${encodeURIComponent(managed.domain)}`}>View Reports for This Domain <ExternalLink aria-hidden="true" /></Link>
        </div>
        {comparison ? <div className={`dns-comparison comparison-${comparison.action}`}><div className="comparison-heading">{comparison.action === "none" ? <><Check aria-hidden="true" /><div><strong>DNS Is Up to Date</strong><span>The live {kind.toUpperCase()} record already matches the managed value.</span></div></> : comparison.action === "manual" ? <><Clipboard aria-hidden="true" /><div><strong>Manual DNS Update Needed</strong><span>Copy the managed value into your DNS provider. Cloudflare is optional.</span></div></> : <><CloudflareMark /><div><strong>{comparison.action === "create" ? "Ready to Create in Cloudflare" : "Ready to Update Cloudflare"}</strong><span>Compared {formatDate(comparison.checked_at)}</span></div></>}</div>{comparison.previous ? <BfCopyField label="Current" value={comparison.previous} /> : null}<BfCopyField label="Managed" value={comparison.record} tone="managed" />{comparison.lookup_count !== undefined ? <div className="lookup-status"><ShieldCheckIcon /><span>{comparison.lookup_count} direct DNS lookup{comparison.lookup_count === 1 ? "" : "s"}. Nested provider includes are not flattened automatically because their authorized IPs change over time.</span></div> : null}{comparison.warnings.map((warning) => <div className="warning-banner" key={warning}>{warning}</div>)}{applied ? <div className="success-banner" role="status"><Check aria-hidden="true" /><span>Cloudflare was updated and the cached check time was refreshed.</span></div> : null}{comparison.action === "manual" ? <div className="comparison-actions"><BfButtonLink variant="secondary" icon={<CloudflareMark />} href="/integrations" target="_top">Link Cloudflare</BfButtonLink></div> : comparison.action !== "none" && !applied ? <BfButton className="cloudflare-button" variant="secondary" icon={<CloudflareMark />} onClick={runApply} disabled={applying}>{applying ? "Updating Cloudflare…" : "Update Cloudflare"}</BfButton> : null}</div> : null}
        {dnsError ? <div className="error-banner" role="alert">{dnsError}</div> : null}
      </Drawer> : null}
    </div>
  );
}

function ShieldCheckIcon() {
  return <Check aria-hidden="true" />;
}

function dnsStateLabel(value?: string) {
  if (!value || value === "unknown" || value === "not_checked") return "Not Checked";
  if (value === "lookup_failed") return "Lookup Failed";
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function reportingStateLabel(value?: string) {
  if (value === "unknown" || value === "needs_review") return "Needs Review";
  return dnsStateLabel(value || "not_configured");
}

function MailRoutingStatus({ domain }: { domain: DomainSummary }) {
  const noEmail = domainHasNoEmail(domain);
  const Icon = noEmail || ["null_mx", "no_route"].includes(domain.mx_status ?? "") ? MailX : Mail;
  const tone = noEmail ? "is-success" : domain.mx_status === "present" ? "is-neutral" : domain.mx_status === "lookup_failed" || domain.mx_status === "invalid" ? "is-warning" : "is-neutral";
  const label = noEmail ? "No Email Use" : mailRouteLabel(domain);
  return <BfTooltip content={`${mailRouteDetail(domain)}${domain.email_usage_override ? " Email use was confirmed by an operator." : ""}`}><span className={`compact-status ${tone}`} aria-label={label}><Icon aria-hidden="true" /><span>{label}</span></span></BfTooltip>;
}

function MailRoutingPanel({ domain, updating, onChange }: { domain: DomainSummary; updating?: boolean; onChange: (value: "" | "uses_email" | "no_email") => Promise<void> }) {
  const mxValue = (domain.mx_records ?? []).map((record) => `${record.priority} ${record.exchange}`).join("\n");
  const noEmail = domainHasNoEmail(domain);
  return <section className="mail-routing" aria-label="Mail Routing">
    <div className="builder-heading">
      <div><strong>Mail Routing</strong><span>{mailRouteDetail(domain)}</span></div>
      <BfChip tone={noEmail ? "success" : domain.mx_status === "lookup_failed" || domain.mx_status === "invalid" ? "warning" : "neutral"}>{noEmail ? "No Email Use" : mailRouteLabel(domain)}</BfChip>
    </div>
    <div className="mail-routing__fields">
      <BfSelect
        label="Email Use"
        value={domain.email_usage_override ?? ""}
        disabled={updating}
        onValueChange={(value) => void onChange(value as "" | "uses_email" | "no_email")}
        options={[
          { value: "", label: "Use DNS Evidence" },
          { value: "uses_email", label: "Sends or Receives Email" },
          { value: "no_email", label: "Does Not Send or Receive Email" },
        ]}
      />
      <p>Direct reject is offered only when DNS proves no inbound and outbound email, or an operator confirms this domain has no email use.</p>
    </div>
    {mxValue ? <BfCopyField label={domain.mx_provider ? `${domain.mx_provider} MX Records` : "MX Records"} value={mxValue} /> : null}
  </section>;
}

function CurrentDmarcRecord({ domain }: { domain: DomainSummary }) {
  const record = domain.dmarc_record?.trim();
  const recordCount = domain.dmarc_record_count ?? (record ? 1 : 0);
  const detail = recordCount > 1
    ? `${recordCount} records were found at the DMARC name. Keep exactly one TXT record or one managed CNAME.`
    : domain.dmarc_record_type === "CNAME"
      ? record
        ? `${domain.dmarc_managed_provider || "Managed DMARC"} CNAME · effective policy checked ${formatDate(domain.cached_at)}`
        : `${domain.dmarc_managed_provider || "Managed DMARC"} CNAME does not currently resolve to a valid DMARC policy`
    : record
      ? `Cached from DNS · checked ${formatDate(domain.cached_at)}`
      : domain.dmarc_verification_status === "mismatch"
        ? "Cloudflare and receiver-visible public DNS disagree. Refresh the inventory before making a change."
      : domain.dmarc_status === "lookup_failed" || domain.dmarc_verification_status === "lookup_failed"
        ? "The public DNS lookup failed. Bifrost will retry automatically."
        : domain.dmarc_status === "not_checked" || domain.dmarc_status === "unknown"
          ? "Public DNS has not been checked yet."
          : domain.dmarc_verification_status === "verified_absent"
            ? `No DMARC record found in the DNS provider or public DNS · verified ${formatDate(domain.dmarc_verified_at || domain.cached_at)}`
            : `No DMARC record found · checked ${formatDate(domain.cached_at)}`;

  return <section className="current-dns-record" aria-label="Current DMARC Record">
    <div className="current-dns-record__heading">
      <div><strong>Current DMARC Record</strong><span>{detail}</span></div>
    </div>
    {domain.dmarc_record_type === "CNAME" && domain.dmarc_cname_target ? <BfCopyField label="CNAME Target" value={domain.dmarc_cname_target} /> : null}
    {record ? <BfCopyField label={domain.dmarc_record_type === "CNAME" ? "Effective DMARC Policy" : "Current"} value={record} /> : <span className="current-dns-record__empty">Bifrost will generate the recommended record automatically from the settings below.</span>}
  </section>;
}

function managementLabel(domain: DomainSummary) {
  if (domain.registration_status === "unregistered") return "Unregistered";
  if (domain.lifecycle_status === "archived") return "Archived";
  if (domain.cloudflare_zone_id) return "Cloudflare";
  const provider = detectedDnsProvider(domain);
  if (provider) return provider;
  if (domain.orphan_status === "cloudflare_and_organization_missing") return "DNS and organization need review";
  if (domain.orphan_status === "cloudflare_missing") return "DNS provider unknown";
  if (domain.orphan_status === "organization_missing") return "Organization missing";
  return "Other";
}

function managementSubtitle(domain: DomainSummary) {
  if (domain.registration_status === "unregistered") return domain.archive_source === "automatic_registration_scan" ? "Unregistered · Auto-Archived" : "Unregistered";
  if (domain.cloudflare_zone_id) return domain.cloudflare_account_name ? `Cloudflare · ${domain.cloudflare_account_name}` : "Managed in Cloudflare";
  const provider = detectedDnsProvider(domain);
  if (provider) return domain.dns_provider ? `DNS hosted by ${provider}` : `Nameserver · ${provider}`;
  if (domain.orphan_status === "cloudflare_and_organization_missing") return "DNS and organization need review";
  if (domain.orphan_status === "cloudflare_missing") return "DNS provider could not be identified";
  if (domain.orphan_status === "organization_missing") return "Organization missing";
  return domain.management_mode === "manual" ? "Manual DNS management" : "Managed outside Cloudflare";
}

function ManagementStatus({ domain }: { domain: DomainSummary }) {
  const label = managementLabel(domain);
  if (domain.registration_status === "unregistered") {
    return <BfTooltip content={`The authoritative registry confirms ${domain.domain} is not registered. ${domain.archive_source === "automatic_registration_scan" ? "Bifrost automatically archived it without deleting retained history." : "Archive it if it no longer belongs in inventory."}`}><span className="compact-status is-danger" aria-label={label}><CircleOff aria-hidden="true" /><span>Unregistered</span></span></BfTooltip>;
  }
  if (domain.lifecycle_status === "archived") {
    return <BfTooltip content="Archived from active inventory. Reports, SPF sources, mappings, and DNS audit history are retained."><span className="compact-status is-neutral" aria-label={label}><Archive aria-hidden="true" /><span>Archived</span></span></BfTooltip>;
  }
  if (domain.cloudflare_zone_id) {
    return <BfTooltip content={domain.cloudflare_account_name ? `Managed through the ${domain.cloudflare_account_name} Cloudflare account.` : "Managed through Cloudflare."}><span className="compact-status is-cloudflare" aria-label={label}><CloudflareMark /><span>Cloudflare</span></span></BfTooltip>;
  }
  const provider = detectedDnsProvider(domain);
  const nameserverDetail = nameserverSummary(domain);
  if (provider === "Cloudflare") {
    return <BfTooltip content={`Public nameservers still indicate Cloudflare, but this zone is not in the latest accessible Cloudflare inventory. ${nameserverDetail}`}><span className="compact-status is-cloudflare has-warning" aria-label="Cloudflare DNS; access missing"><CloudflareMark /><span>Cloudflare</span></span></BfTooltip>;
  }
  if (provider) {
    return <BfTooltip content={`${dnsProviderEvidence(domain)} ${nameserverDetail}`}><span className="compact-status is-provider" aria-label={label}><Globe2 aria-hidden="true" /><span>{provider}</span></span></BfTooltip>;
  }
  if (domain.registration_status === "registered_undelegated") {
    return <BfTooltip content={`The authoritative registry confirms ${domain.domain} is registered, but public DNS returned no authoritative nameservers. This domain was not auto-archived.`}><span className="compact-status is-warning" aria-label="Registered without DNS"><TriangleAlert aria-hidden="true" /><span>No DNS</span></span></BfTooltip>;
  }
  if (domain.registration_status === "subdomain") {
    return <BfTooltip content="This exact name is a subdomain of a registered parent. It was not auto-archived even though it has no separate nameserver delegation."><span className="compact-status is-neutral" aria-label="Registered parent domain"><Globe2 aria-hidden="true" /><span>Subdomain</span></span></BfTooltip>;
  }
  if (domain.orphan_status === "cloudflare_and_organization_missing") {
    return <BfTooltip content="Neither the prior Cloudflare zone nor its mapped organization is accessible, and public DNS did not identify a provider. Open the domain to remap or archive it."><span className="compact-status is-danger" aria-label={label}><TriangleAlert aria-hidden="true" /><span>DNS Unknown</span></span></BfTooltip>;
  }
  if (domain.orphan_status === "cloudflare_missing") {
    return <BfTooltip content="This zone is absent from the latest accessible Cloudflare inventory, and public DNS did not identify its current provider."><span className="compact-status is-danger" aria-label={label}><TriangleAlert aria-hidden="true" /><span>DNS Unknown</span></span></BfTooltip>;
  }
  if (domain.orphan_status === "organization_missing") {
    return <BfTooltip content="The mapped Bifrost organization is no longer accessible. Open the domain to choose another organization or archive it."><span className="compact-status is-danger" aria-label={label}><Building2 aria-hidden="true" /><span>Missing</span></span></BfTooltip>;
  }
  return <BfTooltip content="Managed outside Cloudflare. Bifrost provides records for manual DNS changes."><span className="compact-status is-neutral" aria-label="Other DNS provider"><Globe2 aria-hidden="true" /><span>Other</span></span></BfTooltip>;
}

function OrphanGuidance({ domain }: { domain: DomainSummary }) {
  if (!domain.orphan_status) return null;
  const bothMissing = domain.orphan_status === "cloudflare_and_organization_missing";
  const cloudflareMissing = domain.orphan_status === "cloudflare_missing" || bothMissing;
  const provider = detectedDnsProvider(domain);
  const providerIsCloudflare = provider === "Cloudflare";
  const externalDnsDetected = cloudflareMissing && Boolean(provider) && !providerIsCloudflare;
  const showIntegrations = cloudflareMissing && !externalDnsDetected;
  const title = externalDnsDetected
    ? `${domain.dns_provider || "External"} DNS Detected${bothMissing ? "; Organization Missing" : ""}`
    : bothMissing
      ? "Cloudflare Access and Organization Missing"
      : cloudflareMissing
        ? "Cloudflare Access Missing"
        : "Organization Missing";
  return <div className="orphan-guidance"><BfAlert tone="warning" title={title} action={showIntegrations ? <a className="orphan-guidance-link" href="/integrations" target="_blank" rel="noreferrer">Open Integrations <ExternalLink aria-hidden="true" /></a> : undefined}>
    {bothMissing
      ? externalDnsDetected
        ? `Public nameservers indicate ${provider}. Choose an organization below, then use Bifrost's copyable DNS values for manual changes or archive the domain.`
        : "This zone was not found in the latest Cloudflare inventory, and its mapped organization is no longer available. Choose an organization below, then restore Cloudflare access, use the managed DNS value, or archive the domain."
      : cloudflareMissing
        ? externalDnsDetected
          ? `Public nameservers indicate ${provider}. Bifrost can compare records and provide copyable values without Cloudflare access. Archive the domain if it is no longer in scope.`
          : "This zone was not found in the latest Cloudflare inventory. Restore access to its Cloudflare account, use the managed DNS value below, or archive the domain if it is no longer in scope."
        : "The mapped Bifrost organization is no longer available. Choose another organization below, or archive the domain if it is no longer in scope."}
  </BfAlert></div>;
}

function AuthStatusIcon({ status, label }: { status?: string; label: string }) {
  const normalized = !status || status === "unknown" ? "not_checked" : status;
  const title = `${label}: ${dnsStateLabel(normalized)}`;
  const Icon = normalized === "valid" ? CheckCircle2 : normalized === "missing" ? XCircle : normalized === "multiple" ? TriangleAlert : CircleHelp;
  const tone = normalized === "valid" ? "is-success" : normalized === "missing" ? "is-danger" : normalized === "multiple" ? "is-warning" : "is-neutral";
  return <span className={`auth-status-icon ${tone}`} aria-label={title} title={title}><Icon aria-hidden="true" /></span>;
}
