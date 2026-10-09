import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import type { DashboardData } from "../types";
import { ReportsPage } from "./ReportsPage";

const data = {
  summary: { messages: 6000, compliance: 99, protected: 1, domain_count: 1, unmapped: 0 },
  trend: [], sources: [], attention: [], organizations: [], domains: [], ingest: null,
  reports: [{ id: "r1", reporter: "Google", domain: "example.com", organization_name: "Example Organization", date_end: "2026-08-13T00:00:00Z", message_count: 6000, record_count: 2 }],
  records: [{ id: "f1", report_key: "r1", date: "2026-08-13", domain: "example.com", organization_name: "Example Organization", source_ip: "192.0.2.1", count: 13, sending_source: "Forwarder", disposition: "none", dkim: "fail", spf: "fail", classification: "forwarded", header_from: "example.com", envelope_from: "bounce.sender.example", envelope_to: "recipient.example" }],
  failures: [{ id: "f1", report_key: "r1", date: "2026-08-13", domain: "example.com", organization_name: "Example Organization", source_ip: "192.0.2.1", count: 13, sending_source: "Forwarder", disposition: "none", dkim: "fail", spf: "fail", classification: "forwarded", header_from: "example.com", envelope_from: "bounce.sender.example", envelope_to: "recipient.example" }],
} satisfies DashboardData;

describe("ReportsPage", () => {
  it("switches from provider reports to failure combinations", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><ReportsPage data={data} loading={false} /></MemoryRouter>);
    expect(screen.getByText("Google")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /Issues/ }));
    expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
    expect(screen.getByText("13")).toBeInTheDocument();
  });

  it("opens an aggregate report and drills into its sending-source combinations", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><ReportsPage data={data} loading={false} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com.*Google/ }));

    expect(screen.getByRole("dialog", { name: "example.com" })).toBeInTheDocument();
    expect(screen.getByText("Forwarder")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Message Domains.*From.*Mail From.*To/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Source IP" })).toBeInTheDocument();
    expect(screen.getByLabelText("From: example.com")).toBeInTheDocument();
    expect(screen.getByLabelText("Mail From: bounce.sender.example")).toBeInTheDocument();
    expect(screen.getByLabelText("To: recipient.example")).toBeInTheDocument();
    expect(screen.getByText("bounce.sender.example")).toBeInTheDocument();
    expect(screen.getByText("recipient.example")).toBeInTheDocument();
    expect(screen.getByLabelText("DMARC: Issue")).toBeInTheDocument();
    expect(screen.getByLabelText("SPF: Fail")).toBeInTheDocument();
    expect(screen.getByLabelText("DKIM: Fail")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /PTR/i })).not.toBeInTheDocument();
  });

  it("keeps missing optional domain identifiers in fixed labeled positions", async () => {
    const user = userEvent.setup();
    const record = { ...data.records[0], envelope_from: undefined, envelope_to: undefined };
    render(<MemoryRouter><ReportsPage data={{ ...data, records: [record] }} loading={false} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com.*Google/ }));

    const identifiers = screen.getByLabelText("Message domains for result combination");
    expect(identifiers).toHaveTextContent("example.com——");
    expect(screen.getByLabelText("Mail From: Not Reported")).toBeInTheDocument();
    expect(screen.getByLabelText("To: Not Reported")).toBeInTheDocument();
  });

  it("removes the internal aggregate-row count from the report inventory", () => {
    render(<MemoryRouter><ReportsPage data={data} loading={false} /></MemoryRouter>);

    expect(screen.queryByRole("columnheader", { name: "Aggregate Rows" })).not.toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Messages" })).toBeInTheDocument();
  });

  it("paginates long report inventories instead of rendering every row in one scroller", async () => {
    const user = userEvent.setup();
    const reports = Array.from({ length: 51 }, (_, index) => ({
      ...data.reports[0],
      id: `report-${index + 1}`,
      domain: `domain-${index + 1}.example`,
    }));
    render(<MemoryRouter><ReportsPage data={{ ...data, reports }} loading={false} /></MemoryRouter>);

    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
    expect(screen.queryByText("domain-51.example")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next Page" }));

    expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
    expect(screen.getByText("domain-51.example")).toBeInTheDocument();
  });

  it("paginates long result-combination lists inside the report drawer", async () => {
    const user = userEvent.setup();
    const records = Array.from({ length: 26 }, (_, index) => ({
      ...data.records[0],
      id: `record-${index + 1}`,
      source_ip: `192.0.2.${index + 1}`,
      count: 1,
    }));
    const pagedData: DashboardData = {
      ...data,
      reports: [{ ...data.reports[0], record_count: 26, message_count: 26 }],
      records,
      failures: [],
    };
    render(<MemoryRouter><ReportsPage data={pagedData} loading={false} /></MemoryRouter>);

    await user.click(screen.getByRole("row", { name: /example\.com.*Google/ }));

    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
    expect(screen.queryByText("192.0.2.26")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next Page" }));

    expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.26")).toBeInTheDocument();
  });
});
