import { LoaderCircle } from "lucide-react";

export function LoadingVeil({ active, label = "Loading data" }: { active: boolean; label?: string }) {
  if (!active) return null;
  return (
    <div className="loading-veil" role="status" aria-live="polite">
      <LoaderCircle aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function LoadingRows({ rows = 4, label = "Loading results" }: { rows?: number; label?: string }) {
  return (
    <div className="loading-rows" role="status" aria-live="polite" aria-label={label}>
      {Array.from({ length: rows }, (_, index) => <i key={index} />)}
      <span className="sr-only">{label}</span>
    </div>
  );
}
