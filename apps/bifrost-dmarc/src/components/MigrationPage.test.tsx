import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import type { DnsComparison, DomainSummary, OrganizationSummary, SpfSource } from "../types";
import { MigrationPage } from "./MigrationPage";

const domain: DomainSummary = {
  id: "domain-1",
  domain: "example.com",
  organization_id: "org-1",
  organization_name: "Example Organization",
  mapping_status: "mapped",
  mapping_source: "manual",
  dmarc_policy: "none",
  dmarc_record: "",
  rua: "",
  has_dmarc: false,
  dmarc_verification_status: "verified_absent",
  spf_status: "valid",
  spf_record: "",
  cached_at: "2026-08-23T12:00:00Z",
  source_inventory_origin: "easydmarc",
  source_inventory_imported_at: "2026-08-23T12:00:00Z",
  source_inventory_count: 1,
  inventory_status: "ready",
  lifecycle_status: "active",
};

const organizations: OrganizationSummary[] = [{ id: "org-1", name: "Example Organization", domain: "example.com", domain_count: 1, protected_count: 0 }];
const sources: SpfSource[] = [{ id: "source-1", domain: "example.com", source_name: "Microsoft 365", spf_part: "include:spf.protection.outlook.com", enabled: true }];

describe("MigrationPage", () => {
  const renderPage = (props: Partial<React.ComponentProps<typeof MigrationPage>> = {}) => render(<MemoryRouter><MigrationPage domains={[domain]} sources={sources} organizations={organizations} runs={[]} tasks={[]} loading={false} syncing={false} mapping={false} applying={false} starting={false} onSync={vi.fn()} onMap={vi.fn()} onStartMigration={vi.fn()} onCompareDns={vi.fn()} onApplyDns={vi.fn()} {...props} /></MemoryRouter>);

  it("automatically compares DMARC without a Preview action", async () => {
    const user = userEvent.setup();
    const onCompareDns = vi.fn(async (_domainId: string, kind: "dmarc" | "spf"): Promise<DnsComparison> => ({
      kind,
      domain_id: "domain-1",
      domain: "example.com",
      name: kind === "dmarc" ? "_dmarc.example.com" : "example.com",
      previous: "",
      record: kind === "dmarc" ? "v=DMARC1; p=none;" : "v=spf1 include:spf.protection.outlook.com ~all",
      action: "manual",
      cloudflare_connected: false,
      warnings: [],
    }));

    renderPage({ onCompareDns });
    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    await waitFor(() => expect(onCompareDns).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("v=DMARC1; p=none;")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Preview|Compare/ })).not.toBeInTheDocument();
  });

  it("keeps the organization menu inside the modal top layer", async () => {
    const user = userEvent.setup();
    renderPage({ onCompareDns: vi.fn(async (): Promise<DnsComparison> => ({
      kind: "dmarc",
      domain_id: domain.id,
      domain: domain.domain,
      name: `_dmarc.${domain.domain}`,
      previous: "",
      record: "v=DMARC1; p=none; pct=100;",
      action: "manual",
      cloudflare_connected: false,
      warnings: [],
    })) });

    await user.click(screen.getByRole("row", { name: /example\.com/ }));
    const dialog = screen.getByRole("dialog");
    await user.click(screen.getByRole("combobox", { name: "Organization" }));

    const listbox = screen.getByRole("listbox", { name: "Organization" });
    expect(dialog).toContainElement(listbox);
    await user.click(screen.getByRole("option", { name: /Unmapped/ }));
    expect(screen.getByRole("combobox", { name: "Organization" })).toHaveTextContent("Unmapped");
  });

  it("identifies an EasyDMARC CNAME and presents it as an explicit cutover", async () => {
    const user = userEvent.setup();
    const managedDomain: DomainSummary = {
      ...domain,
      has_dmarc: true,
      dmarc_policy: "reject",
      dmarc_record: "v=DMARC1; p=reject; pct=100;",
      dmarc_record_count: 1,
      dmarc_record_type: "CNAME",
      dmarc_cname_target: "_dmarc.example_com._d.easydmarc.pro",
      dmarc_managed_provider: "EasyDMARC",
    };
    const onCompareDns = vi.fn(async (_domainId: string, kind: "dmarc" | "spf"): Promise<DnsComparison> => ({
      kind,
      domain_id: "domain-1",
      domain: "example.com",
      name: kind === "dmarc" ? "_dmarc.example.com" : "example.com",
      previous: kind === "dmarc" ? managedDomain.dmarc_record : "",
      record: kind === "dmarc" ? "v=DMARC1; p=reject; pct=100;" : "v=spf1 include:spf.protection.outlook.com ~all",
      action: kind === "dmarc" ? "update" : "none",
      current_record_type: kind === "dmarc" ? "CNAME" : "TXT",
      current_cname_target: kind === "dmarc" ? managedDomain.dmarc_cname_target : "",
      current_managed_provider: kind === "dmarc" ? "EasyDMARC" : "",
      cloudflare_connected: true,
      warnings: [],
    }));

    renderPage({ domains: [managedDomain], onCompareDns });
    expect(screen.getByText("Managed by EasyDMARC")).toBeInTheDocument();
    await user.click(screen.getByRole("row", { name: /example\.com/ }));

    expect(await screen.findByRole("button", { name: "Copy EasyDMARC CNAME" })).toBeInTheDocument();
    expect(screen.getByText("This replaces the external managed CNAME with a Bifrost-managed TXT record.")).toBeInTheDocument();
  });

  it("queues eligible missing domains as monitor-only at full coverage", async () => {
    const user = userEvent.setup();
    const onStartMigration = vi.fn(async () => undefined);
    const monitorDomain = { ...domain, cloudflare_zone_id: "zone-1", reports_to_bifrost: false };
    renderPage({ domains: [monitorDomain], onStartMigration });

    await user.click(screen.getByRole("button", { name: /Set Up DNS/ }));
    await user.click(screen.getByRole("button", { name: "Review 1 Ready Domains" }));
    expect(screen.getAllByText(/Create p=none at 100%/).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Queue 1 Domain" }));

    await waitFor(() => expect(onStartMigration).toHaveBeenCalledWith("monitor", ["domain-1"], undefined));
    expect(screen.getByText("Migration Queued")).toBeInTheDocument();
    expect(screen.getByText(/progress will appear here automatically/i)).toBeInTheDocument();
  });

  it("explains why the no-DMARC total is larger than the ready monitor cohort", () => {
    const readyDomain = { ...domain, id: "ready", domain: "ready.example", cloudflare_zone_id: "zone-1", mx_status: "present" as const };
    const reviewDomain = { ...domain, id: "review", domain: "review.example", cloudflare_zone_id: "zone-2", mx_status: "implicit" as const };
    const manualDomain = { ...domain, id: "manual", domain: "manual.example", mx_status: "present" as const };

    renderPage({ domains: [readyDomain, reviewDomain, manualDomain] });

    expect(screen.getByText("1 ready · 3 total")).toBeInTheDocument();
    expect(screen.getByText("1 of 3 ready")).toBeInTheDocument();
    expect(screen.getByText("1 need email-use review")).toBeInTheDocument();
    expect(screen.getByText("1 require manual DNS")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review 1 Ready Domains" })).toBeInTheDocument();
  });

  it("queues confirmed no-email domains directly to reject", async () => {
    const user = userEvent.setup();
    const onStartMigration = vi.fn(async () => undefined);
    const parkedDomain = { ...domain, cloudflare_zone_id: "zone-1", mx_status: "null_mx" as const, spf_record: "v=spf1 -all" };
    renderPage({ domains: [parkedDomain], onStartMigration });

    await user.click(screen.getByRole("button", { name: /Publish Reject/ }));
    await user.click(screen.getByRole("button", { name: "Review 1 Direct Reject Candidates" }));
    const queueButton = screen.getByRole("button", { name: "Confirm & Queue 1 Domain" });
    expect(queueButton).toBeDisabled();
    await user.click(screen.getByRole("switch", { name: "I Confirm These Domains Do Not Send or Receive Email" }));
    await user.click(queueButton);

    await waitFor(() => expect(onStartMigration).toHaveBeenCalledWith("reject_no_mail", ["domain-1"], true));
  });

  it("makes Review Email Use domains available for guarded bulk reject", async () => {
    const user = userEvent.setup();
    const onStartMigration = vi.fn(async () => undefined);
    const reviewDomain = { ...domain, cloudflare_zone_id: "zone-1", mx_status: "implicit" as const, spf_record: "" };
    renderPage({ domains: [reviewDomain], onStartMigration });

    await user.click(screen.getByRole("button", { name: "Review Email Use" }));
    await user.click(screen.getByRole("checkbox", { name: "Select row domain-1" }));
    await user.click(screen.getByRole("button", { name: "Publish Reject 1" }));
    await user.click(screen.getByRole("switch", { name: "I Confirm These Domains Do Not Send or Receive Email" }));
    await user.click(screen.getByRole("button", { name: "Confirm & Queue 1 Domain" }));

    await waitFor(() => expect(onStartMigration).toHaveBeenCalledWith("reject_no_mail", ["domain-1"], true));
  });
});
