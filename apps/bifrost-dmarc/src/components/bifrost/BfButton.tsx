import { forwardRef, type AnchorHTMLAttributes, type ButtonHTMLAttributes, type ReactNode } from "react";
import type { ButtonVariant } from "./types";
import "./components.css";

interface BfButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  icon?: ReactNode;
  trailingIcon?: ReactNode;
  size?: "default" | "compact";
}

interface BfButtonLinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  variant?: ButtonVariant;
  icon?: ReactNode;
  trailingIcon?: ReactNode;
  size?: "default" | "compact";
}

interface BfIconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label" | "children"> {
  label: string;
  icon: ReactNode;
  variant?: ButtonVariant;
  size?: "default" | "compact";
}

function buttonClassName(variant: ButtonVariant, size: "default" | "compact", className: string, iconOnly = false) {
  return [
    "bds-button",
    `bds-button--${variant}`,
    size === "compact" ? "bds-button--compact" : "",
    iconOnly ? "bds-button--icon" : "",
    className,
  ].filter(Boolean).join(" ");
}

function ButtonContents({ icon, trailingIcon, children }: { icon?: ReactNode; trailingIcon?: ReactNode; children: ReactNode }) {
  return <>
    {icon && <span className="bds-button__icon" aria-hidden="true">{icon}</span>}
    <span>{children}</span>
    {trailingIcon && <span className="bds-button__icon" aria-hidden="true">{trailingIcon}</span>}
  </>;
}

export function BfButton({ variant = "primary", size = "default", icon, trailingIcon, className = "", children, type = "button", ...props }: BfButtonProps) {
  return (
    <button type={type} className={buttonClassName(variant, size, className)} {...props}>
      <ButtonContents icon={icon} trailingIcon={trailingIcon}>{children}</ButtonContents>
    </button>
  );
}

export function BfButtonLink({ variant = "primary", size = "default", icon, trailingIcon, className = "", children, ...props }: BfButtonLinkProps) {
  return (
    <a className={buttonClassName(variant, size, className)} {...props}>
      <ButtonContents icon={icon} trailingIcon={trailingIcon}>{children}</ButtonContents>
    </a>
  );
}

export const BfIconButton = forwardRef<HTMLButtonElement, BfIconButtonProps>(function BfIconButton({ label, icon, variant = "ghost", size = "default", className = "", title = label, type = "button", ...props }, ref) {
  return (
    <button
      ref={ref}
      type={type}
      className={buttonClassName(variant, size, className, true)}
      aria-label={label}
      title={title}
      {...props}
    >
      <span className="bds-button__icon" aria-hidden="true">{icon}</span>
    </button>
  );
});
