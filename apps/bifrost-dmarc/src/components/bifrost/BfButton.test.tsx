import { render, screen } from "@testing-library/react";
import { Copy } from "lucide-react";
import { describe, expect, it } from "vitest";

import { BfButtonLink, BfIconButton } from "./BfButton";
import { BfRefreshButton } from "./BfRefreshButton";

describe("Bifrost action controls", () => {
  it("renders icon-only actions with the shared ghost treatment and an accessible name", () => {
    render(<BfIconButton label="Copy Record" icon={<Copy />} size="compact" />);

    const button = screen.getByRole("button", { name: "Copy Record" });
    expect(button).toHaveClass("bds-button", "bds-button--ghost", "bds-button--icon", "bds-button--compact");
    expect(button).toHaveAttribute("title", "Copy Record");
    expect(button).not.toHaveTextContent("Copy Record");
  });

  it("renders navigational actions as semantic links with button styling", () => {
    render(<BfButtonLink href="/integrations" target="_blank" rel="noreferrer" variant="secondary">Open Integrations</BfButtonLink>);

    const link = screen.getByRole("link", { name: "Open Integrations" });
    expect(link).toHaveClass("bds-button", "bds-button--secondary");
    expect(link).toHaveAttribute("href", "/integrations");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("standardizes refresh loading behavior without changing its transparent ghost surface", () => {
    render(<BfRefreshButton label="Refresh Inventory" loading />);

    const button = screen.getByRole("button", { name: "Refresh Inventory" });
    expect(button).toHaveClass("bds-button--ghost", "bds-button--icon");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    expect(button.querySelector("svg")).toHaveClass("bds-spin");
  });
});
