import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Drawer } from "./Drawer";

describe("Drawer", () => {
  afterEach(() => document.getElementById("dmarc-drawer-root")?.remove());

  it("renders in the shared drawer layer and closes with Escape", async () => {
    const root = document.createElement("div");
    root.id = "dmarc-drawer-root";
    document.body.append(root);
    const onClose = vi.fn();
    const user = userEvent.setup();

    render(<Drawer title="Domain detail" subtitle="Live data" onClose={onClose}><p>Panel body</p></Drawer>);

    expect(root).toContainElement(screen.getByRole("dialog", { name: "Domain detail" }));
    expect(screen.getByRole("button", { name: "Close Panel" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });
});
