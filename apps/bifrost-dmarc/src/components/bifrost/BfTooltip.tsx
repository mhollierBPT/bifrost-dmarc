import { useId, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { overlayPortalRoot } from "./portal";
import "./components.css";

interface TooltipPosition {
  left: number;
  top?: number;
  bottom?: number;
  placement: "top" | "bottom";
  width: number;
}

export function BfTooltip({ content, children }: { content: string; children: ReactNode }) {
  const id = useId();
  const anchorRef = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<TooltipPosition>();

  useLayoutEffect(() => {
    if (!open) return;
    const updatePosition = () => {
      const anchor = anchorRef.current;
      if (!anchor) return;
      const bounds = anchor.getBoundingClientRect();
      const margin = 8;
      const gap = 7;
      const width = Math.min(280, window.innerWidth - margin * 2);
      const placement = bounds.top >= 88 ? "top" : "bottom";
      setPosition({
        left: Math.max(margin, Math.min(bounds.left + bounds.width / 2 - width / 2, window.innerWidth - width - margin)),
        top: placement === "bottom" ? bounds.bottom + gap : undefined,
        bottom: placement === "top" ? window.innerHeight - bounds.top + gap : undefined,
        placement,
        width,
      });
    };
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open]);

  const style = position ? ({
    left: position.left,
    top: position.top,
    bottom: position.bottom,
    width: position.width,
  } as CSSProperties) : undefined;

  return <>
    <span
      ref={anchorRef}
      className="bds-tooltip__anchor"
      tabIndex={0}
      aria-describedby={open ? id : undefined}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(event) => {
        if (event.key === "Escape") setOpen(false);
      }}
    >{children}</span>
    {open && typeof document !== "undefined" ? createPortal(
      <span id={id} className="bds-tooltip" role="tooltip" data-placement={position?.placement} style={style}>{content}</span>,
      overlayPortalRoot(anchorRef.current),
    ) : null}
  </>;
}
