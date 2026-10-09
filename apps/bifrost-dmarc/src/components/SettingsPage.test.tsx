import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SettingsPage } from "./SettingsPage";

describe("SettingsPage", () => {
  it("uploads a synthetic report before DNS is changed", async () => {
    const user = userEvent.setup();
    const onUpload = vi.fn().mockResolvedValue(undefined);
    render(<SettingsPage uploading={false} onUpload={onUpload} />);
    const file = new File(["<feedback />"], "report.xml", { type: "application/xml" });

    await user.upload(screen.getByLabelText(/Choose a DMARC Report/), file);

    expect(onUpload).toHaveBeenCalledWith("report.xml", btoa("<feedback />"));
  });

  it("shows aggregate rows separately from message volume", () => {
    render(<SettingsPage uploading={false} onUpload={vi.fn()} uploadResult={{ reports: 1, records: 2, messages: 6000 }} />);
    expect(screen.getByText(/2 aggregate rows, and 6,000 messages/)).toBeInTheDocument();
  });

  it("renders sparse historical investigation analysis without crashing", () => {
    render(<SettingsPage uploading={false} onUpload={vi.fn()} investigations={[{
      id: "investigation-1",
      address: "investigate+old@dmarc.example.com",
      status: "completed",
      source: "resend",
      created_at: "2026-08-01T00:00:00Z",
      expires_at: "2026-08-02T00:00:00Z",
      analysis: { from: [], to: [], return_path: [] },
    }]} />);

    expect(screen.getByText("DMARC")).toBeInTheDocument();
    expect(screen.getAllByText("not recorded")).toHaveLength(3);
  });

  it("replaces a newly issued address with its live table result without refreshing", async () => {
    const user = userEvent.setup();
    const waiting = {
      id: "investigation-live",
      address: "investigate+live@dmarc.example.com",
      status: "waiting" as const,
      source: "resend" as const,
      created_at: "2026-08-14T12:00:00Z",
      expires_at: "2026-08-15T12:00:00Z",
    };
    const onCreateInvestigation = vi.fn().mockResolvedValue(waiting);
    const { rerender } = render(<SettingsPage uploading={false} onUpload={vi.fn()} onCreateInvestigation={onCreateInvestigation} investigations={[]} />);

    await user.click(screen.getByRole("button", { name: "Create Test Address" }));
    expect(await screen.findByText("Waiting for your email")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Refresh results/i })).not.toBeInTheDocument();

    rerender(<SettingsPage uploading={false} onUpload={vi.fn()} onCreateInvestigation={onCreateInvestigation} investigations={[{
      ...waiting,
      status: "completed",
      subject: "Live authentication result",
      analysis: { from: [], to: [], return_path: [], results: { dmarc: "pass", dkim: "pass", spf: "pass" } },
    }]} />);

    expect(screen.getByText("Live authentication result")).toBeInTheDocument();
    expect(screen.getByText("Results update automatically")).toBeInTheDocument();
  });
});
