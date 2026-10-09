import { renderHook, waitFor } from "@testing-library/react";
import { StrictMode, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useInfiniteTable } from "bifrost";
import { useCompleteTable } from "./useCompleteTable";

vi.mock("bifrost", () => ({ useInfiniteTable: vi.fn() }));

const mockedUseInfiniteTable = vi.mocked(useInfiniteTable);

describe("useCompleteTable", () => {
  beforeEach(() => vi.clearAllMocks());

  it("does not request the same next page twice during Strict Mode effects", async () => {
    let finishLoading!: () => void;
    const loadMore = vi.fn(() => new Promise<void>((resolve) => { finishLoading = resolve; }));
    mockedUseInfiniteTable.mockReturnValue({
      rows: [],
      total: 2,
      loading: false,
      error: null,
      hasMore: true,
      loadMore,
    } as ReturnType<typeof useInfiniteTable>);

    renderHook(() => useCompleteTable("reports"), {
      wrapper: ({ children }: { children: ReactNode }) => <StrictMode>{children}</StrictMode>,
    });

    await waitFor(() => expect(loadMore).toHaveBeenCalledTimes(1));
    finishLoading();
  });

  it("exposes each table document once when a subscription repeats a page", () => {
    mockedUseInfiniteTable.mockReturnValue({
      rows: [{ id: "report-1", domain: "example.com" }, { id: "report-1", domain: "example.com" }],
      total: 1,
      loading: false,
      error: null,
      hasMore: false,
      loadMore: vi.fn(),
    } as ReturnType<typeof useInfiniteTable>);

    const { result } = renderHook(() => useCompleteTable<{ id: string; domain: string }>("reports"));

    expect(result.current.rows).toEqual([{ id: "report-1", domain: "example.com" }]);
  });
});
