import { describe, expect, it, vi } from "vitest";

import { dispatchWorkflow } from "./useWorkflowDispatch";

describe("dispatchWorkflow", () => {
  it("returns after the workflow execution is accepted without polling for completion", async () => {
    const authedFetch = vi.fn(async () => new Response(
      JSON.stringify({ execution_id: "execution-1", status: "Pending" }),
      { status: 202, headers: { "Content-Type": "application/json" } },
    ));

    await expect(dispatchWorkflow(
      authedFetch,
      "app-1",
      "functions/dmarc.py::process_dmarc_migration",
      { operation: "reporting", domain_ids: ["domain-1", "domain-2"] },
    )).resolves.toBe("execution-1");

    expect(authedFetch).toHaveBeenCalledTimes(1);
    expect(authedFetch).toHaveBeenCalledWith("/api/workflows/execute", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({
        workflow_id: "functions/dmarc.py::process_dmarc_migration",
        input_data: { operation: "reporting", domain_ids: ["domain-1", "domain-2"] },
        app_id: "app-1",
      }),
    }));
  });
});
