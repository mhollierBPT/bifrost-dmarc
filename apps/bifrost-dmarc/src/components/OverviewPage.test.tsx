import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import type { DashboardData } from "../types";
import { OverviewPage } from "./OverviewPage";

const data: DashboardData = {
  summary: { messages: 200418, compliance: 98.2, protected: 124, domain_count: 133, unmapped: 9 },
  trend: [{ date: "2026-08-12", total: 6000, compliant: 5900, non_compliant: 50, forwarded: 50 }],
  sources: [{ name: "Microsoft 365 / Outlook", messages: 43000 }],
  attention: [], organizations: [{ id: "org-1", name: "Example Organization", domain: "example.com", domain_count: 2, protected_count: 2 }],
  domains: [], reports: [], failures: [], ingest: null,
};

describe("OverviewPage", () => {
  it("shows true message volume and applies organization filters", async () => {
    const user = userEvent.setup();
    const onOrganizationChange = vi.fn();
    render(<MemoryRouter><OverviewPage data={data} loading={false} organizationId="" days={30} onOrganizationChange={onOrganizationChange} onDaysChange={vi.fn()} onOpenDomain={vi.fn()} /></MemoryRouter>);

    expect(screen.getByText("200,418")).toBeInTheDocument();
    expect(screen.getByText("98.2%")).toBeInTheDocument();
    await user.click(screen.getByRole("combobox", { name: "Organization" }));
    await user.click(screen.getByRole("option", { name: /Example Organization/ }));
    expect(onOrganizationChange).toHaveBeenCalledWith("org-1");
  });

  it("uses the styled combobox menu for Date Range", async () => {
    const user = userEvent.setup();
    const onDaysChange = vi.fn();
    render(<MemoryRouter><OverviewPage data={data} loading={false} organizationId="" days={30} onOrganizationChange={vi.fn()} onDaysChange={onDaysChange} onOpenDomain={vi.fn()} /></MemoryRouter>);

    await user.click(screen.getByRole("combobox", { name: "Date Range" }));
    expect(screen.getByRole("listbox", { name: "Date Range" })).toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: "Last 60 Days" }));
    expect(onDaysChange).toHaveBeenCalledWith(60);
  });

  it("turns summary metrics and chart dates into scoped report navigation", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><OverviewPage data={data} loading={false} organizationId="org-1" days={30} onOrganizationChange={vi.fn()} onDaysChange={vi.fn()} onOpenDomain={vi.fn()} /></MemoryRouter>);

    expect(screen.getByRole("link", { name: /Messages Evaluated/ })).toHaveAttribute("href", expect.stringContaining("organization=org-1"));
    expect(screen.getByRole("link", { name: /Unmapped Domains/ })).toHaveAttribute("href", expect.stringContaining("mapping=unmapped"));
    const chartDate = screen.getByRole("button", { name: /2026-08-12: 6,000 messages/ });
    await user.hover(chartDate);
    expect(screen.getByRole("status")).toHaveTextContent("6,000 messages");
    expect(screen.getByRole("link", { name: /Microsoft 365 \/ Outlook/ })).toHaveAttribute("href", expect.stringContaining("view=failures"));
  });

  it("opens domain details without navigating away from Overview", async () => {
    const user = userEvent.setup();
    const onOpenDomain = vi.fn();
    const attentionData = { ...data, attention: [{ id: "domain-1", domain: "example.com", organization_id: "org-1", organization_name: "Example Organization", mapping_status: "mapped" as const, mapping_source: "manual", dmarc_policy: "none", dmarc_record: "", rua: "", has_dmarc: true, spf_status: "valid", spf_record: "", cached_at: "2026-08-24T00:00:00Z" }] };
    render(<MemoryRouter><OverviewPage data={attentionData} loading={false} organizationId="" days={30} onOrganizationChange={vi.fn()} onDaysChange={vi.fn()} onOpenDomain={onOpenDomain} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    expect(onOpenDomain).toHaveBeenCalledWith("domain-1");
  });

  it("shows DMARC quarantine with the info chip tone", () => {
    const quarantineData = {
      ...data,
      attention: [{ id: "domain-1", domain: "example.com", organization_id: "org-1", organization_name: "Example Organization", mapping_status: "mapped" as const, mapping_source: "manual", dmarc_policy: "quarantine", dmarc_record: "", rua: "", has_dmarc: true, spf_status: "valid", spf_record: "", cached_at: "2026-08-24T00:00:00Z" }],
    };
    render(<MemoryRouter><OverviewPage data={quarantineData} loading={false} organizationId="" days={30} onOrganizationChange={vi.fn()} onDaysChange={vi.fn()} onOpenDomain={vi.fn()} /></MemoryRouter>);

    expect(screen.getByText("quarantine")).toHaveClass("bds-chip--info");
  });
});
