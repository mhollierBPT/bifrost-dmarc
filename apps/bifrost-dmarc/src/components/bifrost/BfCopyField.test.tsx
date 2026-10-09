import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BfCopyField } from "./BfCopyField";

describe("BfCopyField", () => {
  it("copies from an in-field icon and confirms with a check state", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(<BfCopyField label="Managed DMARC Value" value="v=DMARC1; p=reject;" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy Managed DMARC Value" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith("v=DMARC1; p=reject;"));
    expect(screen.getByRole("button", { name: "Managed DMARC Value Copied" })).toBeInTheDocument();
  });
});
