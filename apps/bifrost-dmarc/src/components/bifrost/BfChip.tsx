import type { ReactNode } from "react";
import "./components.css";

type ChipTone = "neutral" | "success" | "warning" | "danger" | "info";

export function BfChip({ children, tone = "neutral" }: { children: ReactNode; tone?: ChipTone }) {
  return <span className={`bds-chip bds-chip--${tone}`}>{children}</span>;
}
