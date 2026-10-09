import { X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { BfIconButton } from "./bifrost/BfButton";

interface DrawerProps {
  actions?: ReactNode;
  ariaLabel?: string;
  children: ReactNode;
  className?: string;
  onClose: () => void;
  subtitle?: ReactNode;
  title: ReactNode;
}

export function Drawer({ actions, ariaLabel, children, className = "", onClose, subtitle, title }: DrawerProps) {
  const titleId = useId();
  const closeButton = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCloseRef.current();
    };
    document.addEventListener("keydown", handleKeyDown);
    closeButton.current?.focus();
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus();
    };
  }, []);

  const root = document.getElementById("dmarc-drawer-root") ?? document.body;
  return createPortal(
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className={`drawer-panel ${className}`.trim()} role="dialog" aria-modal="true" aria-label={ariaLabel} aria-labelledby={ariaLabel ? undefined : titleId}>
        <header>
          <div><h2 id={ariaLabel ? undefined : titleId}>{title}</h2>{subtitle ? <p>{subtitle}</p> : null}</div>
          <div className="drawer-header-actions">
            {actions}
            <BfIconButton ref={closeButton} size="compact" label="Close Panel" icon={<X />} onClick={onClose} />
          </div>
        </header>
        <div className="drawer-content">{children}</div>
      </section>
    </div>,
    root,
  );
}
