# Bifrost DMARC Design

## Direction

Bifrost DMARC is an operational ledger, not a marketing dashboard. The interface makes ownership, evidence, freshness, and the next safe action legible at a glance. It consumes the Bifrost Design System through its source registry while remaining a self-contained Bifrost Solution.

## Visual world

- Host-owned light and dark canvases use flat Bifrost paper surfaces separated by hairlines rather than floating cards.
- Cyan names decisions, focus, and current location. Cloudflare remains orange. A thin red-to-magenta bridge seam appears only where it communicates connection or progress.
- Surface, control, and feature geometry follows the 4/6/8px Bifrost radius scale. Status remains a flat text-and-square-signal label rather than a pill.
- Inter is the interface typeface, Prompt is reserved for page and brand moments, and JetBrains Mono carries DNS records and addresses.
- Dense `BfDataTable` surfaces are primary objects. Entire rows are keyboard and pointer targets; their independently portaled vertical-ellipsis menus remain usable inside constrained scrollers.

## Interaction

- First viewport order: purpose, external refresh action, coverage metrics, then searchable exception inventory.
- Long organization, source, and status sets use portaled searchable comboboxes; short fixed policy choices remain native fields.
- Generic actions use `BfButton`, `BfButtonLink`, `BfIconButton`, or `BfRefreshButton`; pages must not recreate their own button colors, sizing, focus, loading, disabled, or motion states. Raw buttons belong only inside encapsulated compound controls such as tables, comboboxes, tabs, switches, and the SPF mechanism selector.
- Loading is local to the surface being refreshed and uses stable skeletons or veils; existing data stays visible during background refresh.
- External Cloudflare state is deliberately refreshed. Bifrost table rows update live without a user refresh button.
- DNS changes use an automatic live comparison followed by explicit apply. Manual records are equally complete when a zone is unavailable; preview is never a separate user step.
- Motion follows the Bifrost “quiet machinery” timings: 120ms feedback, 220ms disclosure, 360ms route arrival, and 1600ms only for genuine progress. Reduced-motion preferences remove transitions and loops.

## Source provenance

Registry components were copied from `gobifrost/design-system` commit `f054a72` using `scripts/add.mjs`. The owned source lives under `apps/bifrost-dmarc/src/components/bifrost`; there is no runtime design-system dependency. Local product CSS may compose the components but must preserve their keyboard, focus, portal, theme, and reduced-motion contracts.

## Content

Use operational nouns and verbs: “Reconcile Cloudflare,” “Map Organization,” “Compare with DNS,” and “Update Cloudflare.” Explain exceptional states in terms of the decision the operator must make. Avoid vendor language after one-time data has become ordinary Bifrost inventory.
