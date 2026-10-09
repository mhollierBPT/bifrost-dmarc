import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteTable } from "bifrost";

interface CompleteTableQuery {
  where?: Record<string, unknown>;
  pageSize?: number;
  order_by?: string;
  order_dir?: "asc" | "desc";
  scope?: string;
}

/**
 * Keeps the fully loaded table window subscribed to document changes. Tables
 * remain the UI source of truth while mutations stay in guarded workflows.
 */
export function useCompleteTable<TData>(name: string, query: CompleteTableQuery = {}) {
  const table = useInfiniteTable<TData>(name, query);
  const [loadingMore, setLoadingMore] = useState(false);
  const loadingMoreRef = useRef(false);
  const rows = useMemo(() => {
    const seen = new Set<string>();
    return table.rows.filter((row) => {
      const id = typeof row === "object" && row !== null && "id" in row ? String(row.id ?? "") : "";
      if (!id) return true;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  }, [table.rows]);

  useEffect(() => {
    if (table.loading || table.error || loadingMoreRef.current || !table.hasMore) return;
    loadingMoreRef.current = true;
    setLoadingMore(true);
    void table.loadMore().finally(() => {
      loadingMoreRef.current = false;
      setLoadingMore(false);
    });
  }, [table.error, table.hasMore, table.loadMore, table.loading, table.rows.length]);

  return {
    ...table,
    rows,
    loading: table.loading || (!table.error && (loadingMore || table.hasMore)),
  };
}
