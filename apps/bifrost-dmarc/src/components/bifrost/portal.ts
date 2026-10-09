export function overlayPortalRoot(anchor: Element | null): Element {
  return anchor?.closest("dialog[open]") ?? document.body;
}
