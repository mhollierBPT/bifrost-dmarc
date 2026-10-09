import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import type { DashboardData } from "../types";
import { DomainsPage } from "./DomainsPage";

const data = {
  summary: { messages: 0, compliance: 0, protected: 0, domain_count: 1, unmapped: 1 },
  trend: [], sources: [], reports: [], failures: [], ingest: null,
  organizations: [{ id: "org-1", name: "Example Organization", domain: "example.com", domain_count: 1, protected_count: 0 }],
  domains: [],
  attention: [{ id: "domain-1", domain: "example.com", organization_id: "", organization_name: "", mapping_status: "unmapped", mapping_source: "report", dmarc_policy: "quarantine", dmarc_record: "", rua: "", has_dmarc: true, spf_status: "valid", spf_record: "", cached_at: "2026-08-13T12:00:00Z" }],
} satisfies DashboardData;

describe("DomainsPage", () => {
  it("can render the shared domain manager without the Domains page", async () => {
    const user = userEvent.setup();
    const onManagerClose = vi.fn();
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} managerOnly requestedDomainId="domain-1" onManagerClose={onManagerClose} /></MemoryRouter>);

    expect(await screen.findByRole("dialog", { name: "Manage example.com" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Domains" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close Panel" }));
    expect(onManagerClose).toHaveBeenCalledOnce();
  });

  it("keeps Organization as the first data column", () => {
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    const headings = screen.getAllByRole("columnheader").map((heading) => heading.textContent?.trim()).filter(Boolean);
    expect(headings[0]).toContain("Organization");
    expect(headings[1]).toContain("Domain");
  });

  it("deep-links to an explanatory attention queue", () => {
    render(<MemoryRouter initialEntries={["/domains?attention=all"]}><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    expect(screen.getByText("1 Domains Need Attention")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Next Action/ })).toBeInTheDocument();
    expect(screen.getByText("Resolve Issue")).toBeInTheDocument();
    expect(screen.getByText(/Map this domain to an organization/)).toBeInTheDocument();
  });

  it("explains a domain that is missing from accessible Cloudflare inventory", async () => {
    const user = userEvent.setup();
    const orphanedData = {
      ...data,
      attention: [{
        ...data.attention[0],
        management_mode: "cloudflare" as const,
        orphan_status: "cloudflare_missing" as const,
        cloudflare_account_name: "Example Account",
        dns_provider: "Cloudflare",
        nameservers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
      }],
    } satisfies DashboardData;
    render(<MemoryRouter><DomainsPage data={orphanedData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    const cloudflareStatus = screen.getByLabelText("Cloudflare DNS; access missing");
    expect(cloudflareStatus).toHaveTextContent("Cloudflare");
    expect(cloudflareStatus).toHaveClass("has-warning");
    await user.hover(screen.getByLabelText("Cloudflare DNS; access missing"));
    expect(screen.getByRole("tooltip")).toHaveTextContent("Public nameservers still indicate Cloudflare");

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    expect(screen.getByText("Cloudflare Access Missing")).toBeInTheDocument();
    expect(screen.getByText(/Restore access to its Cloudflare account/)).toBeInTheDocument();
    const integrationsAction = screen.getByRole("link", { name: "Open Integrations" });
    expect(integrationsAction).toHaveClass("orphan-guidance-link");
    expect(integrationsAction).not.toHaveClass("bds-button");
    expect(integrationsAction).toHaveAttribute("target", "_blank");
    expect(integrationsAction.querySelector("svg")).toBeInTheDocument();
    const archiveAction = screen.getByRole("button", { name: "Archive Domain" });
    expect(archiveAction).toHaveClass("bds-button", "bds-button--danger", "bds-button--compact");
    expect(archiveAction.parentElement).toHaveClass("drawer-header-actions");
    expect(archiveAction.querySelector("svg")).toBeInTheDocument();
  });

  it("shows the cached DMARC record without requiring a separate comparison action", async () => {
    const user = userEvent.setup();
    const record = "v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.example.test;";
    const currentRecordData = {
      ...data,
      attention: [{ ...data.attention[0], dmarc_record: record, dmarc_record_count: 1 }],
    } satisfies DashboardData;

    render(<MemoryRouter><DomainsPage data={currentRecordData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);
    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    expect(screen.getByRole("region", { name: "Current DMARC Record" })).toHaveTextContent(record);
    expect(screen.getByRole("button", { name: "Copy Current" })).toBeInTheDocument();
  });

  it("shows verified missing DMARC and lets an operator classify email use", async () => {
    const user = userEvent.setup();
    const onSetEmailUsage = vi.fn().mockResolvedValue(undefined);
    const mailData = {
      ...data,
      attention: [{
        ...data.attention[0],
        has_dmarc: false,
        dmarc_policy: "missing",
        dmarc_status: "missing",
        dmarc_verification_status: "verified_absent" as const,
        dmarc_verified_at: "2026-08-25T12:00:00Z",
        mx_status: "present" as const,
        mx_provider: "Microsoft 365",
        mx_records: [{ priority: 0, exchange: "example-com.mail.protection.outlook.com" }],
      }],
    } satisfies DashboardData;

    render(<MemoryRouter><DomainsPage data={mailData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} onSetEmailUsage={onSetEmailUsage} /></MemoryRouter>);
    expect(screen.getByLabelText("Microsoft 365")).toBeInTheDocument();
    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    expect(screen.getByRole("region", { name: "Current DMARC Record" })).toHaveTextContent("No DMARC record found in the DNS provider or public DNS");
    await user.click(screen.getByRole("combobox", { name: "Email Use" }));
    await user.click(screen.getByRole("option", { name: "Does Not Send or Receive Email" }));
    expect(onSetEmailUsage).toHaveBeenCalledWith("domain-1", "no_email");
  });

  it("shows a managed DMARC CNAME and its effective policy", async () => {
    const user = userEvent.setup();
    const cnameData = {
      ...data,
      attention: [{
        ...data.attention[0],
        dmarc_record: "v=DMARC1; p=reject;",
        dmarc_record_count: 1,
        dmarc_record_type: "CNAME" as const,
        dmarc_cname_target: "_dmarc.example_com._d.easydmarc.pro",
        dmarc_managed_provider: "EasyDMARC",
      }],
    } satisfies DashboardData;

    render(<MemoryRouter><DomainsPage data={cnameData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);
    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    const region = screen.getByRole("region", { name: "Current DMARC Record" });
    expect(region).toHaveTextContent("EasyDMARC CNAME");
    expect(screen.getByRole("button", { name: "Copy CNAME Target" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy Effective DMARC Policy" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Registration")).not.toBeInTheDocument();
  });

  it("renders quarantine DMARC as an info chip", () => {
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    expect(screen.getByText("Quarantine")).toHaveClass("bds-chip--info");
  });

  it("shows the public DNS provider when a prior Cloudflare zone moved elsewhere", async () => {
    const user = userEvent.setup();
    const externalData = {
      ...data,
      attention: [{
        ...data.attention[0],
        management_mode: "cloudflare" as const,
        orphan_status: "cloudflare_missing" as const,
        dns_provider: "Route 53",
        nameservers: ["ns-123.awsdns-45.com", "ns-678.awsdns-90.net"],
      }],
    } satisfies DashboardData;
    render(<MemoryRouter><DomainsPage data={externalData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    expect(screen.getByLabelText("Route 53")).toHaveTextContent("Route 53");
    await user.hover(screen.getByLabelText("Route 53"));
    expect(screen.getByRole("tooltip")).toHaveTextContent("Detected from authoritative nameservers");

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    expect(screen.getByText("Route 53 DNS Detected")).toBeInTheDocument();
    expect(screen.getByText(/without Cloudflare access/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open Integrations" })).not.toBeInTheDocument();
  });

  it("uses bounded policy coverage choices instead of an unconstrained number field", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);
    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    expect(screen.queryByRole("spinbutton", { name: "Percentage" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("combobox", { name: "Policy Coverage" }));
    expect(screen.getByRole("option", { name: /100% of Messages/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /^0% of Messages/ })).toBeInTheDocument();
    expect(screen.queryByText(/Apply the policy to/)).not.toBeInTheDocument();
  });

  it("loads every DMARC control from the existing record", async () => {
    const user = userEvent.setup();
    const existingPolicyData = {
      ...data,
      attention: [{
        ...data.attention[0],
        dmarc_policy: "reject",
        dmarc_subdomain_policy: "quarantine",
        dmarc_pct: 75,
        dmarc_record: "v=DMARC1; p=reject; sp=quarantine; pct=75; adkim=s; aspf=s;",
      }],
    } satisfies DashboardData;
    render(<MemoryRouter><DomainsPage data={existingPolicyData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    expect(screen.getByRole("combobox", { name: "Policy" })).toHaveTextContent("Reject Failures");
    expect(screen.getByRole("combobox", { name: "Subdomain Policy" })).toHaveTextContent("Send Failures to Spam");
    expect(screen.getByRole("combobox", { name: "Policy Coverage" })).toHaveTextContent("75% of Messages");
    expect(screen.getByRole("combobox", { name: "DKIM Alignment" })).toHaveTextContent("Strict");
    expect(screen.getByRole("combobox", { name: "SPF Alignment" })).toHaveTextContent("Strict");
  });

  it("adds a manually managed domain without Cloudflare", async () => {
    const user = userEvent.setup();
    const onCreateDomain = vi.fn().mockResolvedValue({ id: "manual-1", domain: "manual.example" });
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} onCreateDomain={onCreateDomain} /></MemoryRouter>);

    await user.click(screen.getByRole("button", { name: "Add Domain" }));
    const dialog = screen.getByRole("dialog", { name: "Add Domain" });
    await user.type(within(dialog).getByRole("textbox", { name: "Domain" }), "manual.example");
    await user.click(within(dialog).getByRole("combobox", { name: "Organization" }));
    await user.click(screen.getByRole("option", { name: /Example Organization/ }));
    await user.click(within(dialog).getByRole("button", { name: "Add Domain" }));

    expect(onCreateDomain).toHaveBeenCalledWith("manual.example", "org-1");
  });

  it("maps an unmapped domain to a Bifrost organization", async () => {
    const user = userEvent.setup();
    const onMap = vi.fn().mockResolvedValue(undefined);
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={onMap} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    await user.click(screen.getByRole("combobox", { name: "Organization" }));
    await user.click(screen.getByRole("option", { name: /Example Organization/ }));
    await user.click(screen.getByRole("button", { name: "Save Mapping" }));
    expect(onMap).toHaveBeenCalledWith("domain-1", "org-1");
  });

  it("filters the inventory to mapped domains", async () => {
    const user = userEvent.setup();
    const mappedData = {
      ...data,
      domains: [
        ...data.attention,
        { ...data.attention[0], id: "domain-2", domain: "mapped.example", organization_id: "org-1", organization_name: "Example Organization", mapping_status: "mapped" as const },
      ],
      attention: [],
    } satisfies DashboardData;
    render(<MemoryRouter><DomainsPage data={mappedData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    await user.click(screen.getByRole("combobox", { name: "Mapping" }));
    await user.click(screen.getByRole("option", { name: "Mapped Only" }));
    expect(screen.getByText("mapped.example")).toBeInTheDocument();
    expect(screen.queryByText("example.com")).not.toBeInTheDocument();
  });

  it("archives selected active domains in one maintenance action", async () => {
    const user = userEvent.setup();
    const onBulkArchive = vi.fn().mockResolvedValue(undefined);
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} onBulkArchive={onBulkArchive} /></MemoryRouter>);

    await user.click(screen.getByRole("checkbox", { name: "Select row domain-1" }));
    await user.click(screen.getByRole("button", { name: "Archive Selected Domains" }));
    const dialog = screen.getByRole("dialog", { name: "Archive Selected Domains" });
    await user.click(within(dialog).getByRole("button", { name: "Archive 1 Domains" }));

    expect(onBulkArchive).toHaveBeenCalledWith(["domain-1"]);
  });

  it("keeps registry-confirmed unregistered domains reviewable without a persistent banner", async () => {
    const user = userEvent.setup();
    const unregisteredData = {
      ...data,
      summary: { ...data.summary, archived: 1, auto_archived: 1, unregistered: 1 },
      archived_domains: [{
        ...data.attention[0],
        id: "domain-unregistered",
        domain: "missing.example",
        lifecycle_status: "archived" as const,
        registration_status: "unregistered" as const,
        registration_source: "rdap.example",
        archive_source: "automatic_registration_scan" as const,
        archive_reason: "Automatically archived because the authoritative registry confirmed this domain is not registered.",
      }],
    } satisfies DashboardData;
    render(<MemoryRouter><DomainsPage data={unregisteredData} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    expect(screen.queryByText("1 Unregistered Domain Auto-Archived")).not.toBeInTheDocument();
    expect(screen.queryByText("missing.example")).not.toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "Show Archived" }));
    const row = screen.getByRole("row", { name: /missing\.example/ });
    expect(row).toHaveTextContent("Unregistered");
    expect(row).toHaveTextContent("Not registered · automatically archived");

    await user.click(row);
    const dialog = screen.getByRole("dialog", { name: "Restore Domain" });
    expect(dialog).toHaveTextContent("Registry Confirms Domain Is Unregistered");
    expect(dialog).toHaveTextContent("automatically archived again");
  });

  it("automatically refreshes the DNS comparison when managed settings change", async () => {
    const user = userEvent.setup();
    const onCompareDns = vi.fn().mockImplementation(async (_domainId, _kind, settings) => ({
        kind: "dmarc" as const,
        domain_id: "domain-1",
        domain: "example.com",
        name: "_dmarc.example.com",
        previous: "",
        record: `v=DMARC1; p=${String(settings.policy)}; rua=mailto:rua@dmarc.example.com;`,
        action: "create" as const,
        warnings: [],
      }));
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} onCompareDns={onCompareDns} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    expect(await screen.findByText(/v=DMARC1; p=quarantine/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Preview|Compare/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("combobox", { name: "Policy" }));
    await user.click(screen.getByRole("option", { name: "Reject Failures" }));
    expect(screen.queryByText(/v=DMARC1; p=quarantine/)).not.toBeInTheDocument();
    expect(await screen.findByText(/v=DMARC1; p=reject/)).toBeInTheDocument();
  });

  it("opens a linked domain directly from an inventory deep link", async () => {
    render(<MemoryRouter initialEntries={["/domains?domain=domain-1"]}><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} /></MemoryRouter>);

    expect(await screen.findByRole("dialog", { name: "Manage example.com" })).toBeInTheDocument();
  });

  it("explains when live DNS already matches the managed value", async () => {
    const user = userEvent.setup();
    const onCompareDns = vi.fn().mockResolvedValue({
      kind: "dmarc",
      domain_id: "domain-1",
      domain: "example.com",
      name: "_dmarc.example.com",
      previous: "v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.example.com;",
      record: "v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.example.com;",
      action: "none",
      cloudflare_connected: true,
      checked_at: "2026-08-14T12:00:00Z",
      warnings: [],
    });
    render(<MemoryRouter><DomainsPage data={data} loading={false} syncing={false} mapping={false} onSync={vi.fn()} onMap={vi.fn()} onCompareDns={onCompareDns} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    expect(await screen.findByText("DNS Is Up to Date")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Update Cloudflare/ })).not.toBeInTheDocument();
  });
});
