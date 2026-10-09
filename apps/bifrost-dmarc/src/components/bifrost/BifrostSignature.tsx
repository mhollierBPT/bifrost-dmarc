import { BifrostMark } from "./BifrostMark";

export function BifrostSignature({ markSize = 42, product = "DMARC" }: { markSize?: number; product?: string }) {
  return (
    <>
      <BifrostMark size={markSize} />
      <span className="brand-signature__copy">
        <strong>Bifrost</strong>
        <small>{product}</small>
      </span>
    </>
  );
}
