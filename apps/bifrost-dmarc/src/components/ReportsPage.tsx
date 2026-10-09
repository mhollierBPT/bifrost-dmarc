import { AlertTriangle, Check, Download, ExternalLink, Inbox, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { formatDate, formatNumber } from "../lib/format";
import type { AggregateReport, DashboardData, FailureRecord, IngestStatus } from "../types";
import { BfActionMenu } from "./bifrost/BfActionMenu";
import { BfButton } from "./bifrost/BfButton";
import { BfMultiSelect, type BfComboboxOption } from "./bifrost/BfCombobox";
import { BfDataTable, BfPagination, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfTextField } from "./bifrost/BfField";
import { BfChip } from "./bifrost/BfChip";
import { BfTabs } from "./bifrost/BfTabs";
import { Drawer } from "./Drawer";

type ReportTab = "aggregate" | "failures" | "inbound";
const REPORT_PAGE_SIZE = 50;
const DETAIL_PAGE_SIZE = 25;

function reportedValue(value: string | undefined, fallback: string) {
  return !value || value.trim().toLowerCase().startsWith("unknown") ? fallback : value;
}

function ReportToolbar({ search, onSearch, filters, onClearFilter, onExport }: { search: string; onSearch: (value: string) => void; filters: Array<{ key: string; label: string }>; onClearFilter: (key: string) => void; onExport: () => void }) {
  return <>
    <BfTextField className="data-toolbar-search" label="Search Reports" value={search} onChange={(event) => onSearch(event.target.value)} leadingIcon={<Search size={15} />} placeholder="Search domain, organization, reporter, source, or IP" />
    {filters.map((filter) => <BfButton key={filter.key} variant="ghost" trailingIcon={<X size={14} />} onClick={() => onClearFilter(filter.key)}>{filter.label}</BfButton>)}
    <BfButton variant="secondary" icon={<Download size={14} />} onClick={onExport}>Export CSV</BfButton>
  </>;
}

function DomainIdentifiers({ record }: { record: FailureRecord }) {
  const values = [
    { label: "From", value: reportedValue(record.header_from || record.domain, "Not Reported") },
    { label: "Mail From", value: reportedValue(record.envelope_from, "Not Reported") },
    { label: "To", value: reportedValue(record.envelope_to, "Not Reported") },
  ];
  return (
    <div className="report-identifiers" aria-label="Message domains for result combination">
      {values.map(({ label, value }) => <span key={label} className={value === "Not Reported" ? "is-missing" : ""} aria-label={`${label}: ${value}`} title={`${label}: ${value}`}>{value === "Not Reported" ? "—" : value}</span>)}
    </div>
  );
}

function AuthenticationMark({ label, value }: { label: "DMARC" | "SPF" | "DKIM"; value: string }) {
  const pass = value === "pass";
  const displayValue = value ? `${value.charAt(0).toUpperCase()}${value.slice(1).replace(/_/g, " ")}` : "Not Reported";
  return <span className={`report-auth-mark ${pass ? "pass" : "fail"}`} aria-label={`${label}: ${displayValue}`} title={`${label}: ${displayValue}`}>{pass ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}</span>;
}

export function ReportsPage({ data, loading }: { data?: DashboardData; loading: boolean }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedView = searchParams.get("view");
  const [tab, setTab] = useState<ReportTab>(requestedView === "failures" || requestedView === "inbound" ? requestedView : "aggregate");
  const [search, setSearch] = useState(searchParams.get("domain") ?? "");
  const [sourceFilters, setSourceFilters] = useState<string[]>(searchParams.get("source") ? [searchParams.get("source")!] : []);
  const [selectedReport, setSelectedReport] = useState<AggregateReport>();
  const [selectedRecord, setSelectedRecord] = useState<FailureRecord>();
  const [selectedIngest, setSelectedIngest] = useState<IngestStatus>();
  const [detailPage, setDetailPage] = useState(1);
  const query = search.trim().toLowerCase();
  const dateFilter = searchParams.get("date") ?? "";
  const organizationFilter = searchParams.get("organization") ?? "";
  const organizationName = data?.organizations.find((organization) => organization.id === organizationFilter)?.name ?? "";
  const organizationDomains = useMemo(() => new Set((data?.domains ?? []).filter((domain) => !organizationFilter || domain.organization_id === organizationFilter).map((domain) => domain.domain)), [data?.domains, organizationFilter]);
  const allRecords = data?.records ?? data?.failures ?? [];
  const aggregateReports = useMemo(() => (data?.reports ?? []).filter((report) => (!organizationFilter || organizationDomains.has(report.domain)) && (!dateFilter || report.date_end?.slice(0, 10) === dateFilter) && (!query || `${report.domain} ${report.organization_name} ${report.reporter} ${report.report_id}`.toLowerCase().includes(query))), [data?.reports, dateFilter, organizationDomains, organizationFilter, query]);
  const sources = useMemo(() => Array.from(new Set((data?.failures ?? []).map((row) => row.sending_source))).filter(Boolean).sort(), [data?.failures]);
  const failures = useMemo(() => (data?.failures ?? []).filter((failure) => (!organizationFilter || organizationDomains.has(failure.domain)) && (!dateFilter || failure.date?.slice(0, 10) === dateFilter) && (!sourceFilters.length || sourceFilters.includes(failure.sending_source)) && (!query || `${failure.domain} ${failure.organization_name} ${failure.sending_source} ${failure.source_ip} ${failure.header_from} ${failure.envelope_from} ${failure.envelope_to}`.toLowerCase().includes(query))), [data?.failures, dateFilter, organizationDomains, organizationFilter, query, sourceFilters]);
  const inbound = useMemo(() => (data?.ingest_events ?? []).filter((event) => !query || `${event.status} ${event.route} ${event.recipients?.join(" ")} ${event.error} ${event.ignore_reason}`.toLowerCase().includes(query)), [data?.ingest_events, query]);
  const expectedDomains = (data?.domains ?? []).filter((domain) => domain.reports_to_bifrost);
  const missingDomains = expectedDomains.filter((domain) => domain.reporting_status === "awaiting" || domain.reporting_status === "stale");

  useEffect(() => {
    if (requestedView === "aggregate" || requestedView === "failures" || requestedView === "inbound") setTab(requestedView);
  }, [requestedView]);

  const clearUrlFilter = (name: string) => {
    const next = new URLSearchParams(searchParams);
    next.delete(name);
    setSearchParams(next, { replace: true });
    if (name === "source") setSourceFilters([]);
    if (name === "domain") setSearch("");
  };
  const toolbarFilters = [
    ...(searchParams.get("domain") ? [{ key: "domain", label: searchParams.get("domain")! }] : []),
    ...(dateFilter ? [{ key: "date", label: formatDate(dateFilter) }] : []),
    ...(organizationFilter ? [{ key: "organization", label: organizationName || "Selected Organization" }] : []),
  ];
  const changeTab = (value: string) => {
    const nextTab = value as ReportTab;
    setTab(nextTab);
    const next = new URLSearchParams(searchParams);
    next.set("view", nextTab);
    setSearchParams(next, { replace: true });
  };

  const exportCsv = () => {
    const rows = tab === "aggregate"
      ? [["Organization", "Domain", "Reporter", "Report date", "Aggregate rows", "Messages"], ...aggregateReports.map((row) => [row.organization_name, row.domain, row.reporter, row.date_end, row.record_count, row.message_count])]
      : tab === "failures"
        ? [["Organization", "Domain", "Date", "Sending Source", "Source IP", "Header From Domain", "Envelope From Domain", "Envelope To Domain", "Messages", "Classification", "Disposition", "SPF", "DKIM"], ...failures.map((row) => [row.organization_name, row.domain, row.date, row.sending_source, row.source_ip, row.header_from, row.envelope_from, row.envelope_to, row.count, row.classification, row.disposition, row.spf, row.dkim])]
        : [["Status", "Route", "Recipients", "Reports", "Messages", "Completed", "Error"], ...inbound.map((row) => [row.status, row.route, row.recipients?.join("; "), row.report_count, row.message_count, row.completed_at, row.error || row.ignore_reason])];
    const csv = rows.map((row) => row.map((cell) => `"${String(cell ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `bifrost-dmarc-${tab}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const reportForRecord = selectedRecord ? data?.reports.find((report) => report.id === selectedRecord.report_key || report.report_id === selectedRecord.report_id) : undefined;
  const detailReport = selectedReport ?? reportForRecord;
  const detailRecords = detailReport ? allRecords.filter((record) => record.report_key === detailReport.id || record.report_id === detailReport.report_id) : selectedRecord ? [selectedRecord] : [];
  const detailPageCount = Math.max(1, Math.ceil(detailRecords.length / DETAIL_PAGE_SIZE));
  useEffect(() => setDetailPage(1), [detailReport?.id, selectedRecord?.id]);
  useEffect(() => setDetailPage((current) => Math.min(current, detailPageCount)), [detailPageCount]);
  const visibleDetailRecords = detailRecords.slice((detailPage - 1) * DETAIL_PAGE_SIZE, detailPage * DETAIL_PAGE_SIZE);
  const groupedRecords = visibleDetailRecords.reduce<Record<string, FailureRecord[]>>((groups, record) => {
    const key = reportedValue(record.sending_source, "Unidentified Source");
    (groups[key] ??= []).push(record);
    return groups;
  }, {});
  const detailSourceCount = new Set(detailRecords.map((record) => reportedValue(record.sending_source, "Unidentified Source"))).size;
  const sourceOptions = useMemo<BfComboboxOption[]>(() => sources.map((item) => ({ value: item, label: item })), [sources]);
  const openReport = (report: AggregateReport) => { setSelectedReport(report); setSelectedRecord(undefined); };
  const openFailure = (failure: FailureRecord) => { setSelectedRecord(failure); setSelectedReport(undefined); };
  const aggregateColumns = useMemo<BfDataColumn<AggregateReport>[]>(() => [
    { id: "organization", header: "Organization", width: "24%", sortable: true, accessor: (report) => report.organization_name || "Unassigned" },
    { id: "domain", header: "Domain", width: "24%", sortable: true, accessor: (report) => <strong className="domain-name">{report.domain}</strong>, sortValue: (report) => report.domain },
    { id: "reporter", header: "Reporter", width: "20%", sortable: true, accessor: "reporter" },
    { id: "date", header: "Report Date", width: "20%", sortable: true, sortValue: (report) => report.date_end ?? "", accessor: (report) => formatDate(report.date_end) },
    { id: "messages", header: "Messages", width: "12%", align: "end", sortable: true, sortValue: (report) => report.message_count, accessor: (report) => <strong>{formatNumber(report.message_count)}</strong> },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (report) => <BfActionMenu label={`Actions for ${report.domain} report`} items={[{ value: "open", label: "Open Report", icon: <ExternalLink size={14} /> }]} onSelect={() => openReport(report)} /> },
  ], []);
  const failureColumns = useMemo<BfDataColumn<FailureRecord>[]>(() => [
    { id: "organization", header: "Organization", width: "16%", sortable: true, accessor: (failure) => failure.organization_name || "Unassigned" },
    { id: "domain", header: "Domain", width: "16%", sortable: true, accessor: (failure) => <strong className="domain-name">{failure.domain}</strong>, sortValue: (failure) => failure.domain },
    { id: "date", header: "Date", width: "11%", sortable: true, sortValue: (failure) => failure.date ?? "", accessor: (failure) => formatDate(failure.date) },
    { id: "source", header: "Sending Source", width: "15%", sortable: true, accessor: (failure) => reportedValue(failure.sending_source, "Not Reported") },
    { id: "ip", header: "Source IP", width: "14%", sortable: true, accessor: (failure) => <span className="mono">{reportedValue(failure.source_ip, "Not Reported")}</span> },
    { id: "messages", header: "Messages", width: "8%", align: "end", sortable: true, sortValue: (failure) => failure.count, accessor: (failure) => <strong>{formatNumber(failure.count)}</strong> },
    { id: "issue", header: "Issue", width: "10%", sortable: true, sortValue: (failure) => failure.classification, accessor: (failure) => <BfChip tone={failure.classification === "compliant" ? "success" : failure.classification === "forwarded" ? "info" : "danger"}>{failure.classification.replace("_", " ")}</BfChip> },
    { id: "spf", header: "SPF", width: "5%", accessor: (failure) => <BfChip tone={failure.spf === "pass" ? "success" : "danger"}>{failure.spf}</BfChip> },
    { id: "dkim", header: "DKIM", width: "5%", accessor: (failure) => <BfChip tone={failure.dkim === "pass" ? "success" : "danger"}>{failure.dkim}</BfChip> },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (failure) => <BfActionMenu label={`Actions for ${failure.domain} issue`} items={[{ value: "open", label: "Open Issue", icon: <ExternalLink size={14} /> }]} onSelect={() => openFailure(failure)} /> },
  ], []);
  const inboundColumns = useMemo<BfDataColumn<IngestStatus>[]>(() => [
    { id: "status", header: "Status", width: "15%", sortable: true, accessor: (event) => <BfChip tone={event.status === "completed" ? "success" : event.status === "failed" ? "danger" : "info"}>{event.status}</BfChip> },
    { id: "route", header: "Route", width: "18%", sortable: true, accessor: (event) => event.route || "—" },
    { id: "recipients", header: "Recipients", width: "29%", accessor: (event) => event.recipients?.join(", ") || "—" },
    { id: "reports", header: "Reports", width: "9%", align: "end", sortable: true, accessor: (event) => event.report_count ?? 0 },
    { id: "messages", header: "Messages", width: "10%", align: "end", sortable: true, accessor: (event) => event.message_count ?? 0 },
    { id: "completed", header: "Completed", width: "17%", sortable: true, sortValue: (event) => event.completed_at ?? "", accessor: (event) => formatDate(event.completed_at) },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (event) => <BfActionMenu label={`Actions for ${event.status} inbound delivery`} items={[{ value: "open", label: "Open Delivery", icon: <ExternalLink size={14} /> }]} onSelect={() => setSelectedIngest(event)} /> },
  ], []);
  return (
    <div className="page page-enter" aria-busy={loading}>
      <header className="page-header"><div><h1>Reports</h1><p>Provider reports, authentication issues, and every inbound delivery attempt.</p></div></header>
      <section className="report-health" aria-label="Report coverage">
        <article><span>Real Aggregate Reports</span><strong>{(data?.reports ?? []).filter((report) => !report.email_id?.startsWith("synthetic-")).length}</strong><small>{formatNumber((data?.reports ?? []).reduce((sum, report) => sum + Number(report.message_count || 0), 0))} messages represented</small></article>
        <article><span>Domains Reporting Here</span><strong>{data?.health?.reporting_current ?? 0} / {expectedDomains.length}</strong><small>Current within three days</small></article>
        <article className={missingDomains.length ? "needs-attention" : ""}><span>Awaiting or Stale</span><strong>{missingDomains.length}</strong><small>{missingDomains.length ? "Open domain inventory to investigate" : "No expected reports are overdue"}</small></article>
        <article className={data?.health?.recent_ingest_failures ? "needs-attention" : ""}><span>Inbound Failures</span><strong>{data?.health?.recent_ingest_failures ?? 0}</strong><small>Across the latest {data?.health?.recent_ingest_events ?? 0} deliveries</small></article>
      </section>
      <BfTabs label="DMARC Report Views" items={[{ id: "aggregate", label: `Aggregate Reports (${aggregateReports.length})` }, { id: "failures", label: `Issues (${failures.length})` }, { id: "inbound", label: `Inbound Activity (${inbound.length})` }]} value={tab} onChange={changeTab} distribution="equal" />
      {tab === "aggregate" ? <BfDataTable ariaLabel="Aggregate reports" rows={aggregateReports} columns={aggregateColumns} getRowId={(report) => report.id} loading={loading} onRowActivate={openReport} defaultSort={{ columnId: "date", direction: "descending" }} clientPageSize={REPORT_PAGE_SIZE} clientPaginationKey={`${query}:${dateFilter}:${organizationFilter}`} toolbar={<ReportToolbar search={search} onSearch={setSearch} filters={toolbarFilters} onClearFilter={clearUrlFilter} onExport={exportCsv} />} emptyState={{ title: "No aggregate reports match these filters", description: "Try a broader domain, organization, reporter, or date." }} footer={<span>{aggregateReports.length} provider reports</span>} maxHeight="min(58vh, 44rem)" minWidth="52rem" /> : tab === "failures" ? <BfDataTable ariaLabel="Authentication issues" rows={failures} columns={failureColumns} getRowId={(failure) => failure.id} loading={loading} onRowActivate={openFailure} defaultSort={{ columnId: "date", direction: "descending" }} clientPageSize={REPORT_PAGE_SIZE} clientPaginationKey={`${query}:${sourceFilters.join(",")}:${dateFilter}:${organizationFilter}`} toolbar={<><BfTextField className="data-toolbar-search" label="Search Issues" value={search} onChange={(event) => setSearch(event.target.value)} leadingIcon={<Search size={15} />} placeholder="Search domain, organization, source, or IP" /><BfMultiSelect className="data-toolbar-filter" label="Sending Sources" value={sourceFilters} onValueChange={setSourceFilters} options={sourceOptions} placeholder="All Sending Sources" maxDisplayedItems={1} showBulkActions={false} />{toolbarFilters.map((filter) => <BfButton key={filter.key} variant="ghost" trailingIcon={<X size={14} />} onClick={() => clearUrlFilter(filter.key)}>{filter.label}</BfButton>)}<BfButton variant="secondary" icon={<Download size={14} />} onClick={exportCsv}>Export CSV</BfButton></>} emptyState={{ title: "No authentication issues match these filters", description: "Clear a source, date, organization, or search term to widen the result set." }} footer={<span>{failures.length} provider-aggregated result combinations</span>} maxHeight="min(58vh, 44rem)" minWidth="68rem" /> : <BfDataTable ariaLabel="Inbound deliveries" rows={inbound} columns={inboundColumns} getRowId={(event) => `${event.completed_at}-${event.route}-${event.recipients?.join(";")}`} loading={loading} onRowActivate={setSelectedIngest} defaultSort={{ columnId: "completed", direction: "descending" }} clientPageSize={REPORT_PAGE_SIZE} clientPaginationKey={query} toolbar={<ReportToolbar search={search} onSearch={setSearch} filters={toolbarFilters.filter((filter) => filter.key === "domain")} onClearFilter={clearUrlFilter} onExport={exportCsv} />} emptyState={{ title: "No inbound deliveries match these filters", description: "Try a broader status, route, or recipient search." }} footer={<span>{inbound.length} accepted, ignored, or failed deliveries</span>} maxHeight="min(58vh, 44rem)" minWidth="54rem" />}

      {detailReport || selectedRecord ? <Drawer className="report-drawer" title={detailReport?.domain ?? selectedRecord?.domain ?? "Report Detail"} subtitle={detailReport ? `${reportedValue(detailReport.reporter, "Reporter Not Identified")} · ${formatDate(detailReport.date_end)} · ${formatNumber(detailReport.message_count)} messages` : `${reportedValue(selectedRecord?.sending_source, "Sending Source Not Reported")} · ${reportedValue(selectedRecord?.source_ip, "Source IP Not Reported")}`} onClose={() => { setSelectedReport(undefined); setSelectedRecord(undefined); }}><div className="report-detail-summary"><span><strong>{detailReport?.record_count ?? detailRecords.length}</strong>Result Combinations</span><span><strong>{formatNumber(detailReport?.message_count ?? detailRecords.reduce((sum, item) => sum + item.count, 0))}</strong>Messages Represented</span><span><strong>{detailSourceCount}</strong>Sending Sources</span></div><div className="source-groups">{Object.entries(groupedRecords).map(([sourceName, records]) => <section key={sourceName}><div className="source-heading"><div><strong>{sourceName}</strong><span>{records.length} result combination{records.length === 1 ? "" : "s"}{detailRecords.length > DETAIL_PAGE_SIZE ? " on this page" : ""}</span></div><strong>{formatNumber(records.reduce((sum, record) => sum + record.count, 0))} messages</strong></div><div className="table-wrap"><table className="report-results-table"><thead><tr><th><div className="report-domain-heading"><strong>Message Domains</strong><span><span title="Header From Domain">From</span><span title="Envelope From Domain">Mail From</span><span title="Envelope To Domain">To</span></span></div></th><th>Source IP</th><th className="numeric">Messages</th><th>DMARC</th><th>SPF</th><th>DKIM</th><th>Disposition</th></tr></thead><tbody>{records.map((record) => <tr key={record.id} className={selectedRecord?.id === record.id ? "selected-row" : ""}><td><DomainIdentifiers record={record} /></td><td><span className="mono report-source-ip" title={reportedValue(record.source_ip, "Not Reported")}>{reportedValue(record.source_ip, "Not Reported")}</span></td><td className="numeric">{formatNumber(record.count)}</td><td><AuthenticationMark label="DMARC" value={record.classification === "compliant" ? "pass" : "issue"} /></td><td><AuthenticationMark label="SPF" value={record.spf} /></td><td><AuthenticationMark label="DKIM" value={record.dkim} /></td><td className="report-disposition">{record.disposition}</td></tr>)}</tbody></table></div></section>)}</div><BfPagination className="report-detail-pagination" page={detailPage} pageSize={DETAIL_PAGE_SIZE} total={detailRecords.length} onPageChange={setDetailPage} label="Report Result Pagination" />{!detailRecords.length ? <div className="table-empty"><AlertTriangle aria-hidden="true" />This report has no retained result combinations in the selected date window.</div> : null}</Drawer> : null}
      {selectedIngest ? <Drawer className="ingest-drawer" title="Inbound Delivery" subtitle={formatDate(selectedIngest.completed_at)} onClose={() => setSelectedIngest(undefined)}><div className={`ingest-result ${selectedIngest.status}`}>{selectedIngest.status === "completed" ? <Check aria-hidden="true" /> : selectedIngest.status === "failed" ? <AlertTriangle aria-hidden="true" /> : <Inbox aria-hidden="true" />}<div><strong>{selectedIngest.status}</strong><span>{selectedIngest.error || selectedIngest.ignore_reason || "Processed without an error."}</span></div></div><dl><div><dt>Route</dt><dd>{selectedIngest.route || "Not recorded"}</dd></div><div><dt>Recipients</dt><dd>{selectedIngest.recipients?.join(", ") || "Not recorded"}</dd></div><div><dt>Reports</dt><dd>{selectedIngest.report_count ?? 0}</dd></div><div><dt>Messages represented</dt><dd>{selectedIngest.message_count ?? 0}</dd></div><div><dt>Signature</dt><dd>{selectedIngest.signature_status?.replace(/_/g, " ") || "Not recorded"}</dd></div></dl></Drawer> : null}
    </div>
  );
}
