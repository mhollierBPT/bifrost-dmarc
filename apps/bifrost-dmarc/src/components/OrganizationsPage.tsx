import { Building2, ExternalLink, Search } from "lucide-react";
import { useMemo, useState } from "react";

import type { DashboardData } from "../types";
import { BfActionMenu } from "./bifrost/BfActionMenu";
import { BfDataTable, type BfDataColumn } from "./bifrost/BfDataTable";
import { BfTextField } from "./bifrost/BfField";
import { BfSwitch } from "./bifrost/BfSelection";

export function OrganizationsPage({ data, loading, onSelect }: { data?: DashboardData; loading: boolean; onSelect: (organizationId: string) => void }) {
  const [search, setSearch] = useState("");
  const [showEmpty, setShowEmpty] = useState(false);
  const organizations = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (data?.organizations ?? []).filter((organization) => {
      if (!showEmpty && organization.domain_count === 0) return false;
      return !query || `${organization.name} ${organization.domain}`.toLowerCase().includes(query);
    });
  }, [data?.organizations, search, showEmpty]);
  const columns = useMemo<BfDataColumn<(NonNullable<DashboardData["organizations"]>)[number]>[]>(() => [
    { id: "organization", header: "Organization", width: "32%", sortable: true, sortValue: (organization) => organization.name, cell: (organization) => <span className="organization-cell"><i><Building2 aria-hidden="true" /></i><strong>{organization.name}</strong></span> },
    { id: "domain", header: "Primary Domain", width: "25%", sortable: true, accessor: (organization) => organization.domain || "—" },
    { id: "mapped", header: "Mapped Domains", width: "14%", align: "end", sortable: true, sortValue: (organization) => organization.domain_count, accessor: "domain_count" },
    { id: "records", header: "DMARC Records", width: "14%", align: "end", sortable: true, sortValue: (organization) => organization.protected_count, accessor: "protected_count" },
    { id: "coverage", header: "Coverage", width: "15%", sortable: true, sortValue: (organization) => organization.domain_count ? organization.protected_count / organization.domain_count : 0, cell: (organization) => { const coverage = organization.domain_count ? organization.protected_count / organization.domain_count * 100 : 0; return <div className="coverage"><i><span style={{ width: `${coverage}%` }} /></i><span>{coverage.toFixed(0)}%</span></div>; } },
    { id: "actions", header: <span className="sr-only">Actions</span>, width: "2.75rem", align: "end", cell: (organization) => <BfActionMenu label={`Actions for ${organization.name}`} items={[{ value: "open", label: "View Domains", icon: <ExternalLink size={14} /> }]} onSelect={() => onSelect(organization.id)} /> },
  ], [onSelect]);
  return (
    <div className="page page-enter" aria-busy={loading}>
      <header className="page-header"><div><h1>Organizations</h1><p>Bifrost organizations represented in active DMARC inventory. Empty organizations remain in Bifrost and can be revealed here.</p></div></header>
      <BfDataTable
        ariaLabel="Organization directory"
        rows={organizations}
        columns={columns}
        getRowId={(organization) => organization.id}
        loading={loading}
        loadingRowCount={8}
        onRowActivate={(organization) => onSelect(organization.id)}
        defaultSort={{ columnId: "organization", direction: "ascending" }}
        emptyState={{ title: "No organizations match that search", description: "Try a broader organization or domain name." }}
        toolbar={<><BfTextField className="data-toolbar-search" label="Search Organizations" value={search} onChange={(event) => setSearch(event.target.value)} leadingIcon={<Search size={15} />} placeholder="Search Organizations or Primary Domains" /><div className="data-toolbar-switch"><BfSwitch checked={showEmpty} onChange={setShowEmpty} label="Show Organizations Without Active Domains" /></div></>}
        footer={<span>{organizations.length} of {data?.organizations.length ?? 0} organizations</span>}
        maxHeight="min(68vh, 52rem)"
        minWidth="46rem"
      />
    </div>
  );
}
