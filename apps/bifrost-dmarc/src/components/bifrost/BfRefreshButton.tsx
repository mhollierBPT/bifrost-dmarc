import { RefreshCw } from "lucide-react";
import type { ButtonHTMLAttributes } from "react";

import { BfIconButton } from "./BfButton";
import type { ButtonVariant } from "./types";

interface BfRefreshButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label" | "children"> {
  label: string;
  loading?: boolean;
  variant?: ButtonVariant;
}

export function BfRefreshButton({ label, loading = false, variant = "ghost", disabled, ...props }: BfRefreshButtonProps) {
  return (
    <BfIconButton
      {...props}
      label={label}
      icon={<RefreshCw className={loading ? "bds-spin" : undefined} />}
      variant={variant}
      disabled={disabled || loading}
      aria-busy={loading}
    />
  );
}
