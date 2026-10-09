import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { BfIconButton } from "./BfButton";
import "./components.css";

interface BfCopyFieldProps {
  label: string;
  value: string;
  className?: string;
  tone?: "default" | "managed";
}

export function BfCopyField({ label, value, className = "", tone = "default" }: BfCopyFieldProps) {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<number>();

  useEffect(() => () => {
    if (resetTimer.current) window.clearTimeout(resetTimer.current);
  }, []);

  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    if (resetTimer.current) window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className={["bds-copy-field", tone === "managed" ? "bds-copy-field--managed" : "", className].filter(Boolean).join(" ")}>
      <span className="bds-copy-field__label">{label}</span>
      <code className="bds-copy-field__value">{value}</code>
      <BfIconButton
        className="bds-copy-field__action"
        size="compact"
        label={copied ? `${label} Copied` : `Copy ${label}`}
        title={copied ? "Copied" : `Copy ${label}`}
        icon={copied ? <Check /> : <Copy />}
        onClick={copy}
      />
    </div>
  );
}
