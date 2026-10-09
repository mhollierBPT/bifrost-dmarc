import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { SpfBuilder } from "./SpfBuilder";

function Harness({ initialTerms }: { initialTerms: string[] }) {
  const [terms, setTerms] = useState(initialTerms);
  return <SpfBuilder terms={terms} onChange={setTerms} />;
}

describe("SpfBuilder", () => {
  it("adds a sender from the bottom panel and keeps the terminal policy", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(<SpfBuilder terms={["~all"]} onChange={onChange} />);

    await user.click(screen.getByRole("button", { name: /IPv4/i }));
    await user.type(screen.getByRole("textbox", { name: "IPv4 Address or Network" }), "192.0.2.10/32");
    await user.click(screen.getByRole("button", { name: "Add Sender" }));

    expect(onChange).toHaveBeenCalledWith(["ip4:192.0.2.10/32", "~all"]);
  });

  it("reveals the advanced mechanism select and can emit a redirect policy", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(<SpfBuilder terms={["~all"]} onChange={onChange} />);

    await user.click(screen.getByRole("button", { name: /Advanced/i }));
    expect(screen.getByRole("combobox", { name: "Advanced Mechanism" })).toBeInTheDocument();

    await user.click(screen.getByRole("combobox", { name: "Advanced Mechanism" }));
    await user.click(screen.getByRole("option", { name: "Redirect" }));
    await user.type(screen.getByRole("textbox", { name: "Redirect Target" }), "spf.shadow.example");
    await user.click(screen.getByRole("button", { name: "Add Sender" }));

    expect(onChange).toHaveBeenCalledWith(["redirect=spf.shadow.example"]);
  });

  it("keeps the terminal policy visible until a redirect term is already present", () => {
    render(<Harness initialTerms={["include:spf.protection.outlook.com", "~all"]} />);
    expect(screen.getByRole("combobox", { name: "Terminal Policy" })).toBeInTheDocument();
    expect(screen.queryByText(/delegates the final decision/i)).not.toBeInTheDocument();
  });

  it("replaces the terminal policy select with a redirect note when redirect is present", () => {
    render(<Harness initialTerms={["include:spf.protection.outlook.com", "redirect=spf.shadow.example"]} />);

    expect(screen.queryByRole("combobox", { name: "Terminal Policy" })).not.toBeInTheDocument();
    expect(screen.getByText(/delegates the final decision/i)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("spf.shadow.example");
  });

  it("removes the last sender and restores the terminal policy", async () => {
    const user = userEvent.setup();
    render(<Harness initialTerms={["include:spf.protection.outlook.com", "~all"]} />);

    await user.click(screen.getByRole("button", { name: /remove include spf\.protection\.outlook\.com/i }));

    expect(screen.queryByText("spf.protection.outlook.com")).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Terminal Policy" })).toHaveTextContent("Mark as Suspicious");
  });
});
