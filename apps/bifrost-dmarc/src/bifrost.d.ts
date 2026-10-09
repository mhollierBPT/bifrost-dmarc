declare module "bifrost" {
  import type { ComponentType, ReactNode } from "react";

  export const BifrostHeader: ComponentType<{
    action?: ReactNode;
    className?: string;
    logo?: string | null;
    title?: string;
  }>;
  export const BifrostProvider: ComponentType<{
    appId?: string | null;
    baseUrl: string;
    children: ReactNode;
    onLogout?: () => void;
    orgScope?: string | null;
    solutionId?: string | null;
    supportsTheme?: boolean;
    theme?: "light" | "dark";
    token: string;
  }>;
  export interface BifrostContextValue {
    baseUrl: string;
    appId: string | null;
    authedFetch: (input: string, init?: RequestInit) => Promise<Response>;
    logout: () => void;
    theme: "light" | "dark";
    setTheme: (theme: "light" | "dark") => void;
    toggleTheme: () => void;
    supportsTheme: boolean;
  }
  export function useBifrostContext(): BifrostContextValue;
  export const tables: {
    update: <TData = Record<string, unknown>>(
      table: string,
      id: string,
      data: Record<string, unknown>,
      scope?: string,
    ) => Promise<{ id: string; data: TData } | null>;
  };
  export function useWorkflowMutation<TData = unknown>(ref: string): {
    data?: TData;
    error?: Error | null;
    loading: boolean;
    mutate: (params?: Record<string, unknown>) => Promise<TData>;
  };
  export function useWorkflowQuery<TData = unknown>(ref: string, params?: Record<string, unknown>): {
    data?: TData;
    error?: Error | null;
    loading: boolean;
    refresh: () => Promise<void>;
  };
  export function useTable<TData = Record<string, unknown>>(name: string, query?: {
    where?: Record<string, unknown>;
    page?: number;
    pageSize?: number;
    order_by?: string;
    order_dir?: "asc" | "desc";
    scope?: string;
  }): {
    rows: TData[];
    total: number;
    totalPages: number;
    loading: boolean;
    error: Error | null;
  };
  export function useInfiniteTable<TData = Record<string, unknown>>(name: string, query?: {
    where?: Record<string, unknown>;
    pageSize?: number;
    order_by?: string;
    order_dir?: "asc" | "desc";
    scope?: string;
  }): {
    rows: TData[];
    loadMore: () => Promise<void>;
    hasMore: boolean;
    loading: boolean;
    error: Error | null;
  };
}
