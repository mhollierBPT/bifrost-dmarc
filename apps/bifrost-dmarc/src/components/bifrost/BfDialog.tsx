import { X } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useId, useRef } from "react";
import { BfIconButton } from "./BfButton";
import "./components.css";

export function BfDialog({ open, onOpenChange, title, description, children, footer }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: string; children: ReactNode; footer?: ReactNode }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    if (!open && dialog.open) {
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
    }
  }, [open]);

  return (
    <dialog ref={dialogRef} className="bds-dialog" aria-labelledby={titleId} aria-describedby={description ? descriptionId : undefined} onCancel={(event) => { event.preventDefault(); onOpenChange(false); }} onClose={() => onOpenChange(false)} onClick={(event) => { if (event.target === event.currentTarget) onOpenChange(false); }}>
      <div className="bds-dialog__surface">
        <header><div><h3 id={titleId}>{title}</h3>{description && <p id={descriptionId}>{description}</p>}</div><BfIconButton size="compact" label="Close Dialog" icon={<X size={18} />} onClick={() => onOpenChange(false)} /></header>
        <div className="bds-dialog__body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </dialog>
  );
}
