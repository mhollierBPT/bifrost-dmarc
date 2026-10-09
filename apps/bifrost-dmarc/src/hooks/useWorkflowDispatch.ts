import { useCallback, useState } from "react";
import { useBifrostContext } from "bifrost";

interface DispatchResponse {
  execution_id?: string;
}

type AuthenticatedFetch = (input: string, init?: RequestInit) => Promise<Response>;

export async function dispatchWorkflow(
  authedFetch: AuthenticatedFetch,
  appId: string | null | undefined,
  workflowRef: string,
  input: Record<string, unknown>,
): Promise<string> {
  const response = await authedFetch("/api/workflows/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      workflow_id: workflowRef,
      input_data: input,
      ...(appId ? { app_id: appId } : {}),
    }),
  });
  if (!response.ok) {
    throw new Error(`workflow dispatch failed: ${response.status} ${response.statusText}`);
  }
  const body = await response.json() as DispatchResponse;
  if (!body.execution_id) throw new Error("workflow dispatch did not return an execution ID");
  return body.execution_id;
}

export function useWorkflowDispatch(workflowRef: string) {
  const { authedFetch, appId } = useBifrostContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [executionId, setExecutionId] = useState("");

  const dispatch = useCallback(async (input: Record<string, unknown>) => {
    setLoading(true);
    setError(null);
    try {
      const nextExecutionId = await dispatchWorkflow(authedFetch, appId, workflowRef, input);
      setExecutionId(nextExecutionId);
      return nextExecutionId;
    } catch (dispatchError) {
      const nextError = dispatchError instanceof Error ? dispatchError : new Error(String(dispatchError));
      setError(nextError);
      throw nextError;
    } finally {
      setLoading(false);
    }
  }, [appId, authedFetch, workflowRef]);

  return { dispatch, loading, error, executionId };
}
