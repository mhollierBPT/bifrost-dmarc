import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { DashboardData } from "../types";
import { OrganizationsPage } from "./OrganizationsPage";

const data = {
  summary: { messages: 0, compliance: 0, protected: 1, domain_count: 1, unmapped: 0 },
  trend: [], sources: [], reports: [], failures: [], ingest: null, attention: [], domains: [],
  organizations: [{ id: "org-1", name: "Example Organization", domain: "example.com", domain_count: 1, protected_count: 1 }],
} satisfies DashboardData;

describe("OrganizationsPage", () => {
  it("opens the selected organization's domain inventory", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<OrganizationsPage data={data} loading={false} onSelect={onSelect} />);

    await user.click(screen.getByRole("row", { name: /Example Organization/i }));
    expect(onSelect).toHaveBeenCalledWith("org-1");
  });

  it("hides organizations without active domains until requested", async () => {
    const user = userEvent.setup();
    const withEmptyOrganization = {
      ...data,
      organizations: [...data.organizations, { id: "org-empty", name: "Former Customer", domain: "former.example", domain_count: 0, protected_count: 0 }],
    } satisfies DashboardData;

    render(<OrganizationsPage data={withEmptyOrganization} loading={false} onSelect={vi.fn()} />);
    expect(screen.queryByText("Former Customer")).not.toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "Show Organizations Without Active Domains" }));
    expect(screen.getByText("Former Customer")).toBeInTheDocument();
  });
});
