import { useEffect, useMemo, useState, type CSSProperties, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, ChevronsUpDown, RotateCcw } from "lucide-react";
import { BfButton, BfIconButton } from "./BfButton";
import "./components.css";

export type BfSortDirection = "ascending" | "descending";

export interface BfDataColumn<Row> {
  id: string;
  header: ReactNode;
  accessor?: keyof Row | ((row: Row) => ReactNode);
  cell?: (row: Row) => ReactNode;
  sortValue?: (row: Row) => string | number | Date | null | undefined;
  sortable?: boolean;
  align?: "start" | "center" | "end";
  width?: string;
  className?: string;
}

export interface BfDataTableSort {
  columnId: string;
  direction: BfSortDirection;
}

export interface BfDataTablePagination {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}

interface BfPaginationProps extends BfDataTablePagination {
  className?: string;
  label?: string;
}

export function BfPagination({ page, pageSize, total, onPageChange, className = "", label = "Pagination" }: BfPaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize) return null;
  const rangeStart = total ? (page - 1) * pageSize + 1 : 0;
  const rangeEnd = Math.min(page * pageSize, total);
  return (
    <div className={`bds-pagination ${className}`.trim()}>
      <span>Showing {rangeStart}–{rangeEnd} of {total}</span>
      <nav aria-label={label}>
        <BfIconButton size="compact" label="Previous Page" icon={<ArrowLeft />} disabled={page <= 1} onClick={() => onPageChange(page - 1)} />
        <span>Page {page} of {totalPages}</span>
        <BfIconButton size="compact" label="Next Page" icon={<ArrowRight />} disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} />
      </nav>
    </div>
  );
}

export interface BfDataTableState {
  title: string;
  description?: string;
  action?: ReactNode;
}

export interface BfDataTableError extends BfDataTableState {
  onRetry?: () => void;
}

export interface BfDataTableProps<Row> {
  rows: Row[];
  columns: BfDataColumn<Row>[];
  getRowId: (row: Row) => string;
  caption?: string;
  ariaLabel?: string;
  toolbar?: ReactNode;
  footer?: ReactNode;
  loading?: boolean;
  loadingRowCount?: number;
  error?: BfDataTableError;
  emptyState?: BfDataTableState;
  sort?: BfDataTableSort;
  defaultSort?: BfDataTableSort;
  onSortChange?: (sort: BfDataTableSort) => void;
  selection?: "none" | "single" | "multiple";
  selectedRowIds?: string[];
  onSelectionChange?: (ids: string[]) => void;
  isRowSelectable?: (row: Row) => boolean;
  getRowHref?: (row: Row) => string | undefined;
  onRowActivate?: (row: Row) => void;
  pagination?: BfDataTablePagination;
  clientPageSize?: number;
  clientPaginationKey?: string;
  stickyHeader?: boolean;
  maxHeight?: string;
  minWidth?: string;
  className?: string;
}

function readCell<Row>(column: BfDataColumn<Row>, row: Row): ReactNode {
  if (column.cell) return column.cell(row);
  if (typeof column.accessor === "function") return column.accessor(row);
  if (column.accessor) return row[column.accessor] as ReactNode;
  return null;
}

function comparable(value: string | number | Date | null | undefined) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "string") return value.toLocaleLowerCase();
  return value ?? "";
}

function isInteractiveTarget(target: EventTarget | null) {
  return target instanceof Element && Boolean(target.closest("a, button, input, select, textarea, [role=button], [role=menuitem]"));
}

export function BfDataTable<Row>({
  rows,
  columns,
  getRowId,
  caption,
  ariaLabel,
  toolbar,
  footer,
  loading = false,
  loadingRowCount = 5,
  error,
  emptyState = { title: "No results", description: "There is nothing to show yet." },
  sort: controlledSort,
  defaultSort,
  onSortChange,
  selection = "none",
  selectedRowIds = [],
  onSelectionChange,
  isRowSelectable = () => true,
  getRowHref,
  onRowActivate,
  pagination,
  clientPageSize,
  clientPaginationKey = "",
  stickyHeader = true,
  maxHeight = "32rem",
  minWidth = "100%",
  className = "",
}: BfDataTableProps<Row>) {
  const [internalSort, setInternalSort] = useState<BfDataTableSort | undefined>(defaultSort);
  const [clientPage, setClientPage] = useState(1);
  const sort = controlledSort ?? internalSort;
  const selectedSet = useMemo(() => new Set(selectedRowIds), [selectedRowIds]);
  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((item) => item.id === sort.columnId);
    if (!column) return rows;
    return [...rows].sort((left, right) => {
      const leftValue = comparable(column.sortValue?.(left) ?? String(readCell(column, left) ?? ""));
      const rightValue = comparable(column.sortValue?.(right) ?? String(readCell(column, right) ?? ""));
      const result = leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
      return sort.direction === "ascending" ? result : -result;
    });
  }, [columns, rows, sort]);
  const clientTotalPages = clientPageSize ? Math.max(1, Math.ceil(sortedRows.length / clientPageSize)) : 1;
  useEffect(() => {
    setClientPage((current) => Math.min(current, clientTotalPages));
  }, [clientTotalPages]);
  useEffect(() => {
    setClientPage(1);
  }, [clientPaginationKey]);
  const visibleRows = clientPageSize
    ? sortedRows.slice((clientPage - 1) * clientPageSize, clientPage * clientPageSize)
    : sortedRows;

  const updateSort = (column: BfDataColumn<Row>) => {
    if (!column.sortable) return;
    const next: BfDataTableSort = {
      columnId: column.id,
      direction: sort?.columnId === column.id && sort.direction === "ascending" ? "descending" : "ascending",
    };
    setInternalSort(next);
    onSortChange?.(next);
  };

  const updateSelection = (rowId: string) => {
    if (selection === "none") return;
    if (selection === "single") {
      onSelectionChange?.(selectedSet.has(rowId) ? [] : [rowId]);
      return;
    }
    onSelectionChange?.(selectedSet.has(rowId) ? selectedRowIds.filter((id) => id !== rowId) : [...selectedRowIds, rowId]);
  };

  const selectableRows = visibleRows.filter(isRowSelectable);
  const allVisibleSelected = selectableRows.length > 0 && selectableRows.every((row) => selectedSet.has(getRowId(row)));
  const toggleAll = () => {
    const visibleIds = selectableRows.map(getRowId);
    if (allVisibleSelected) onSelectionChange?.(selectedRowIds.filter((id) => !visibleIds.includes(id)));
    else onSelectionChange?.([...new Set([...selectedRowIds, ...visibleIds])]);
  };

  const activate = (row: Row, event?: MouseEvent<HTMLTableRowElement> | KeyboardEvent<HTMLTableRowElement>) => {
    onRowActivate?.(row);
    const href = getRowHref?.(row);
    if (!href) return;
    if (event && "metaKey" in event && (event.metaKey || event.ctrlKey)) window.open(href, "_blank", "noopener,noreferrer");
  };

  const activePagination = pagination ?? (clientPageSize ? {
    page: clientPage,
    pageSize: clientPageSize,
    total: sortedRows.length,
    onPageChange: setClientPage,
  } : undefined);
  const columnCount = columns.length + (selection !== "none" ? 1 : 0);

  return (
    <section className={`bds-data-table ${className}`.trim()} style={{ "--bds-data-table-min-width": minWidth } as CSSProperties}>
      {toolbar && <div className="bds-data-table__toolbar">{toolbar}</div>}
      <div className="bds-data-table__scroller" style={{ maxHeight }}>
        <table aria-label={ariaLabel} aria-busy={loading || undefined}>
          {caption && <caption>{caption}</caption>}
          <thead className={stickyHeader ? "is-sticky" : ""}>
            <tr>
              {selection !== "none" && <th className="bds-data-table__selection">
                {selection === "multiple" && <input type="checkbox" aria-label="Select all visible rows" checked={allVisibleSelected} disabled={!selectableRows.length} onChange={toggleAll} />}
              </th>}
              {columns.map((column) => (
                <th
                  key={column.id}
                  scope="col"
                  className={column.className}
                  data-align={column.align ?? "start"}
                  aria-sort={sort?.columnId === column.id ? sort.direction : undefined}
                  style={{ width: column.width }}
                >
                  {column.sortable ? (
                    <button type="button" onClick={() => updateSort(column)}>
                      <span>{column.header}</span>
                      {sort?.columnId === column.id ? sort.direction === "ascending" ? <ArrowUp size={14} /> : <ArrowDown size={14} /> : <ChevronsUpDown size={14} />}
                    </button>
                  ) : column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? Array.from({ length: loadingRowCount }, (_, index) => (
              <tr key={`loading-${index}`} aria-hidden="true">
                {Array.from({ length: columnCount }, (__, cellIndex) => <td key={cellIndex}><span className="bds-data-table__skeleton" /></td>)}
              </tr>
            )) : error ? (
              <tr><td colSpan={columnCount}><div className="bds-data-table__state bds-data-table__state--error">
                <strong>{error.title}</strong>
                {error.description && <p>{error.description}</p>}
                {error.action ?? (error.onRetry && <BfButton variant="secondary" icon={<RotateCcw size={14} />} onClick={error.onRetry}>Try again</BfButton>)}
              </div></td></tr>
            ) : !visibleRows.length ? (
              <tr><td colSpan={columnCount}><div className="bds-data-table__state">
                <strong>{emptyState.title}</strong>
                {emptyState.description && <p>{emptyState.description}</p>}
                {emptyState.action}
              </div></td></tr>
            ) : visibleRows.map((row) => {
              const rowId = getRowId(row);
              const selectable = isRowSelectable(row);
              const interactive = Boolean(onRowActivate || getRowHref?.(row));
              return (
                <tr
                  key={rowId}
                  data-selected={selectedSet.has(rowId) || undefined}
                  data-interactive={interactive || undefined}
                  tabIndex={interactive ? 0 : undefined}
                  onClick={(event) => {
                    if (!isInteractiveTarget(event.target)) activate(row, event);
                  }}
                  onAuxClick={(event) => {
                    if (event.button === 1 && !isInteractiveTarget(event.target) && getRowHref?.(row)) window.open(getRowHref(row), "_blank", "noopener,noreferrer");
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      activate(row, event);
                    }
                  }}
                >
                  {selection !== "none" && <td className="bds-data-table__selection"><input type="checkbox" aria-label={`Select row ${rowId}`} checked={selectedSet.has(rowId)} disabled={!selectable} onChange={() => updateSelection(rowId)} /></td>}
                  {columns.map((column) => <td key={column.id} className={column.className} data-align={column.align ?? "start"}><div className="bds-data-table__cell">{readCell(column, row)}</div></td>)}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {(footer || activePagination) && <footer className="bds-data-table__footer">
        {footer}
        {activePagination ? <BfPagination {...activePagination} label="Table Pagination" /> : null}
      </footer>}
    </section>
  );
}
