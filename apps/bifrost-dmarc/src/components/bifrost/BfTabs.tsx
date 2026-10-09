import type { KeyboardEvent } from "react";
import "./components.css";

export type BfTab = { id: string; label: string };

function nextIndex(key: string, current: number, total: number) {
  if (key === "ArrowRight") return (current + 1) % total;
  if (key === "ArrowLeft") return (current - 1 + total) % total;
  if (key === "Home") return 0;
  if (key === "End") return total - 1;
  return null;
}

export function BfTabs({ label, items, value, onChange, distribution = "content" }: { label: string; items: BfTab[]; value: string; onChange: (value: string) => void; distribution?: "content" | "equal" }) {
  return (
    <div className={`bds-tabs bds-tabs--${distribution}`} role="tablist" aria-label={label}>
      {items.map((item, index) => (
        <button
          key={item.id}
          type="button"
          role="tab"
          aria-selected={value === item.id}
          tabIndex={value === item.id ? 0 : -1}
          onClick={() => onChange(item.id)}
          onKeyDown={(event: KeyboardEvent<HTMLButtonElement>) => {
            const target = nextIndex(event.key, index, items.length);
            if (target === null) return;
            event.preventDefault();
            onChange(items[target].id);
            event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("[role=tab]")[target]?.focus();
          }}
        >{item.label}</button>
      ))}
    </div>
  );
}
