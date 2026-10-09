import { AlertTriangle, ArrowUpRight, Globe2, MailCheck, Settings2, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useMemo, useState } from "react";

import { formatDate, formatNumber, formatPercent } from "../lib/format";
import type { DashboardData, DomainSummary, TrendPoint } from "../types";
import { BfActionMenu } from "./bifrost/BfActionMenu";
import { BfCombobox, type BfComboboxOption } from "./bifrost/BfCombobox";
import { BfDataTable, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfChip } from "./bifrost/BfChip";
import { LoadingRows, LoadingVeil } from "./LoadingState";
import { dmarcPolicyTone } from "../lib/dmarcPolicyTone";
import { classifyDomainMigration } from "../lib/migration";

interface OverviewProps {
  data?: DashboardData;
  loading: boolean;
  organizationId: string;
  days: number;
  onOrganizationChange: (value: string) => void;
  onDaysChange: (value: number) => void;
  onOpenDomain: (domainId: string) => void;
}

const series = [
  { key: "compliant" as const, label: "Compliant", color: "var(--report-compliant)" },
  { key: "non_compliant" as const, label: "Non-Compliant", color: "var(--report-noncompliant)" },
  { key: "forwarded" as const, label: "Forwarded", color: "var(--report-forwarded)" },
];

function linePoints(points: TrendPoint[], key: keyof TrendPoint, max: number): string {
  if (!points.length) return "";
  return points
    .map((point, index) => {
      const x = points.length === 1 ? 360 : (index / (points.length - 1)) * 720;
      const y = 210 - ((Number(point[key]) || 0) / max) * 180;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

function VolumeChart({ points, loading, onOpenDate }: { points: TrendPoint[]; loading: boolean; onOpenDate: (date: string) => void }) {
  const max = Math.max(1, ...points.map((point) => Number(point.total) || 0));
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const activePoint = activeIndex == null ? undefined : points[activeIndex];
  return (
    <section className="panel chart-panel loading-surface" aria-labelledby="volume-title">
      <LoadingVeil active={loading} label="Refreshing volume chart" />
      <div className="panel-heading">
        <h2 id="volume-title">Message Volume Over Time</h2>
        <span>Daily</span>
      </div>
      <div className="legend">
        {series.map((item) => <span key={item.key}><i style={{ background: item.color }} />{item.label}</span>)}
      </div>
      {points.length ? (
        <div className="volume-chart-shell">
        <svg className="volume-chart" viewBox="0 0 720 240" role="img" aria-label="Daily DMARC message volume. Focus or hover a date for details; activate it to open reports.">
          {[30, 75, 120, 165, 210].map((y) => <line key={y} x1="0" y1={y} x2="720" y2={y} />)}
          {series.map((item) => (
            <polyline
              key={item.key}
              points={linePoints(points, item.key, max)}
              fill="none"
              stroke={item.color}
              strokeWidth="3"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {points.length === 1 ? series.map((item) => (
            <circle
              key={`${item.key}-point`}
              cx="360"
              cy={210 - ((Number(points[0][item.key]) || 0) / max) * 180}
              r="5"
              fill={item.color}
            />
          )) : null}
          {points.map((point, index) => {
            const segmentWidth = 720 / points.length;
            const x = points.length === 1 ? 360 : (index / (points.length - 1)) * 720;
            return (
              <g
                key={point.date}
                className="chart-hit-target"
                role="button"
                tabIndex={0}
                aria-label={`${point.date}: ${formatNumber(point.total)} messages. Open reports for this date.`}
                onMouseEnter={() => setActiveIndex(index)}
                onMouseLeave={() => setActiveIndex(null)}
                onFocus={() => setActiveIndex(index)}
                onBlur={() => setActiveIndex(null)}
                onClick={() => onOpenDate(point.date)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onOpenDate(point.date);
                  }
                }}
              >
                <rect x={Math.max(0, x - segmentWidth / 2)} y="20" width={segmentWidth} height="200" fill="transparent" />
                {activeIndex === index ? <line className="chart-cursor" x1={x} x2={x} y1="24" y2="212" /> : null}
                {activeIndex === index ? series.map((item) => <circle key={item.key} cx={x} cy={210 - ((Number(point[item.key]) || 0) / max) * 180} r="5" fill={item.color} />) : null}
              </g>
            );
          })}
        </svg>
        {activePoint ? <div className="chart-tooltip" style={{ left: `${points.length === 1 ? 50 : (activeIndex! / (points.length - 1)) * 100}%` }} role="status"><strong>{formatDate(activePoint.date)}</strong><span>{formatNumber(activePoint.total)} messages</span>{series.map((item) => <small key={item.key}><i style={{ background: item.color }} />{item.label}<b>{formatNumber(Number(activePoint[item.key]) || 0)}</b></small>)}<em>Open reports</em></div> : null}
        </div>
      ) : <div className="empty-chart">Reports will appear here after the first inbound DMARC email.</div>}
      <div className="chart-dates">
        <span>{points[0]?.date ?? ""}</span><span>{points[points.length - 1]?.date ?? ""}</span>
      </div>
    </section>
  );
}

export function OverviewPage(props: OverviewProps) {
  const navigate = useNavigate();
  const summary = props.data?.summary;
  const withOverviewScope = (path: string, extra: Record<string, string> = {}) => {
    const [pathname, existingQuery = ""] = path.split("?");
    const query = new URLSearchParams(existingQuery);
    if (props.organizationId) query.set("organization", props.organizationId);
    query.set("days", String(props.days));
    Object.entries(extra).forEach(([key, value]) => query.set(key, value));
    return `${pathname}?${query.toString()}`;
  };
  const metrics = [
    { label: "Messages Evaluated", value: formatNumber(summary?.messages), detail: `${props.days}-day volume`, icon: MailCheck, tone: "teal", href: withOverviewScope("/reports", { view: "aggregate" }) },
    { label: "DMARC Compliant", value: formatPercent(summary?.compliance), detail: `${formatNumber(Math.round((summary?.messages ?? 0) * ((summary?.compliance ?? 0) / 100)))} compliant`, icon: ShieldCheck, tone: "teal", href: withOverviewScope("/reports", { view: "aggregate" }) },
    { label: "Domains Protected", value: `${summary?.protected ?? 0} / ${summary?.domain_count ?? 0}`, detail: `${summary?.reporting ?? 0} reporting in this period`, icon: Globe2, tone: "teal", href: withOverviewScope("/domains", { dmarc: "present" }) },
    { label: "Unmapped Domains", value: formatNumber(summary?.unmapped), detail: "Need an organization", icon: AlertTriangle, tone: "amber", href: withOverviewScope("/domains", { mapping: "unmapped" }) },
  ];
  const organizationOptions = useMemo<BfComboboxOption[]>(() => [
    { value: "", label: "All Organizations" },
    ...(props.data?.organizations ?? []).map((organization) => ({ value: organization.id, label: organization.name, description: organization.domain || undefined })),
  ], [props.data?.organizations]);
  const dateRangeOptions = useMemo<BfComboboxOption[]>(() => [
    { value: "14", label: "Last 14 Days" },
    { value: "30", label: "Last 30 Days" },
    { value: "60", label: "Last 60 Days" },
    { value: "90", label: "Last 90 Days" },
  ], []);
  const attentionColumns = useMemo<BfDataColumn<DomainSummary>[]>(() => [
    { id: "organization", header: "Organization", width: "18%", sortable: true, accessor: (domain) => domain.organization_name || domain.cloudflare_account_name || "Unassigned" },
    { id: "domain", header: "Domain", width: "18%", sortable: true, accessor: (domain) => <strong className="domain-name">{domain.domain}</strong>, sortValue: (domain) => domain.domain },
    { id: "action", header: "Next Action", width: "31%", sortable: true, sortValue: (domain) => classifyDomainMigration(domain).actionLabel, accessor: (domain) => { const state = classifyDomainMigration(domain); return <span className="attention-action"><BfChip tone={state.action === "resolve_issue" ? "danger" : "warning"}>{state.actionLabel}</BfChip><small title={state.actionDetail}>{state.actionDetail}</small></span>; } },
    { id: "policy", header: "Policy", width: "10%", sortable: true, accessor: (domain) => <BfChip tone={dmarcPolicyTone(domain.dmarc_policy)}>{domain.dmarc_policy}</BfChip> },
    { id: "volume", header: "Volume", width: "8%", align: "end", sortable: true, sortValue: (domain) => domain.volume, accessor: (domain) => formatNumber(domain.volume) },
    { id: "last", header: "Last Report", width: "12%", sortable: true, sortValue: (domain) => domain.last_report_at ?? "", accessor: (domain) => domain.last_report_at ? formatDate(domain.last_report_at) : <span className="warning-text">No report</span> },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (domain) => <BfActionMenu label={`Actions for ${domain.domain}`} items={[{ value: "manage", label: "Manage Domain", icon: <Settings2 size={14} /> }]} onSelect={() => props.onOpenDomain(domain.id)} /> },
  ], [props.onOpenDomain]);
  return (
    <div className="page overview-page page-enter" aria-busy={props.loading}>
      <header className="page-header">
        <div><h1>DMARC Overview</h1><p>Message authentication across Bifrost organizations and domains.</p></div>
        <div className="filters"><BfCombobox label="Organization" value={props.organizationId} onValueChange={props.onOrganizationChange} options={organizationOptions} searchPlaceholder="Search Organizations" /><BfCombobox label="Date Range" value={String(props.days)} onValueChange={(value) => props.onDaysChange(Number(value))} options={dateRangeOptions} searchPlaceholder="Search Date Ranges" /></div>
      </header>
      <section className="metric-grid" aria-label="DMARC summary">
        {metrics.map(({ label, value, detail, icon: Icon, tone, href }) => <Link className="metric loading-surface" key={label} to={href}><LoadingVeil active={props.loading} label={`Loading ${label}`} /><span className={`metric-icon ${tone}`}><Icon aria-hidden="true" /></span><div><span>{label}</span><strong>{props.loading && !props.data ? "—" : value}</strong><small>{detail}</small></div><ArrowUpRight className="metric-link-icon" aria-hidden="true" /></Link>)}
      </section>
      <div className="overview-grid">
        <VolumeChart points={props.data?.trend ?? []} loading={props.loading} onOpenDate={(date) => navigate(withOverviewScope("/reports", { view: "aggregate", date }))} />
        <section className="panel sources-panel loading-surface"><LoadingVeil active={props.loading} label="Refreshing sending sources" /><div className="panel-heading"><h2>Top Sending Sources by Volume</h2><span>Messages</span></div>{props.loading && !props.data ? <LoadingRows rows={6} /> : props.data?.sources.length ? <ol>{props.data.sources.map((source) => <li key={source.name}><Link to={withOverviewScope("/reports", { view: "failures", source: source.name })}><span>{source.name}</span><div><i style={{ width: `${Math.max(4, source.messages / props.data!.sources[0].messages * 100)}%` }} /><strong>{formatNumber(source.messages)}</strong></div></Link></li>)}</ol> : <div className="empty-list">No sending sources yet.</div>}</section>
      </div>
      <section className="attention-section"><div className="section-heading"><div><h2>Domains Needing Attention</h2><p>Only domains with a specific operator action are shown.</p></div><Link to={withOverviewScope("/domains", { attention: "all" })}>Review All {props.data?.attention.length ?? 0}</Link></div><BfDataTable ariaLabel="Domains needing attention" rows={props.data?.attention.slice(0, 8) ?? []} columns={attentionColumns} getRowId={(domain) => domain.id} loading={props.loading} loadingRowCount={6} onRowActivate={(domain) => props.onOpenDomain(domain.id)} emptyState={{ title: "No domains need attention", description: "All active domains are either complete or waiting for expected reports." }} maxHeight="28rem" minWidth="64rem" /></section>
    </div>
  );
}
