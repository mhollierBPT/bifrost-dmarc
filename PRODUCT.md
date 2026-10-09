# Bifrost DMARC

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Bifrost DMARC is used by operators who manage email authentication across many organizations and domains. They work repeatedly in a dense operational interface and need to understand reporting coverage, identify authentication problems, reconcile Cloudflare ownership, and make guarded DNS changes without switching among vendor portals.

## Product Purpose

Bifrost DMARC replaces the operational parts of EasyDMARC with a distributable Bifrost Solution. It receives and aggregates DMARC reports, maps domains to Bifrost Organizations and Cloudflare accounts, investigates individual messages, and manages reviewed DMARC and SPF changes. Success means an operator can tell what is protected, what is missing, why a sender fails, and what safe action to take from one interface.

## Positioning

The product joins DMARC evidence, Bifrost organization context, and the customer's existing Cloudflare access. Unlike a standalone reporting vendor, it can turn a finding into an organization-aware, automatically compared, audited DNS action without introducing a second long-lived domain-management system.

## Operating Context

- Bifrost Organizations are the primary customer grouping.
- Cloudflare account and zone mappings establish which domains can be managed automatically.
- DMARC aggregate reports arrive through Resend and are stored at provider-report and result-combination granularity, not one row per message.
- EasyDMARC is a one-time source for current EasySPF configuration. Imported values become ordinary Bifrost-managed domain and SPF-source data; no EasyDMARC runtime integration ships.
- Operators review and apply DNS changes in Cloudflare. Unlinked or missing domains receive an exact manual record and a clear reconciliation state.

## Capabilities and Constraints

- The product is a portable Bifrost v2 Solution with install-scoped tables, workflows, connections, configs, events, and one role-restricted application.
- Report ingestion supports XML, gzip, and a single XML report in zip format with decompression and XML-entity safeguards.
- DNS mutations require a current Cloudflare read, duplicate-record refusal, an exact automatic comparison, explicit apply, and an audit row.
- Domain and source inventories must be searchable and useful at the current multi-client scale.
- The design-system repository is consumed through its shadcn-style source registry, not as a binary dependency. Bifrost DMARC owns the dependency-complete source it uses so exported Solutions remain self-contained.
- Managed SPF flattening must refuse unsupported or unsafe mechanisms rather than silently changing semantics.

## Brand Commitments

- Product name: Bifrost DMARC.
- The Bifrost Design System is the visual and interaction reference: quiet operating layer, restrained action and structural color, square surfaces, hairline structure, compact information density, host-controlled theming, and purposeful loading/disclosure motion.
- Copy is plain, direct, and operational. Status labels describe state; action labels name the operation.

## Evidence on Hand

- Current Bifrost DMARC Solution source, tests, fixtures, and delivery notes under this repository.
- A one-time EasyDMARC EasySPF snapshot was captured for the initial install. It is environment data to import and is not retained in portable product source.
- EasyDMARC reference screenshots and a validated `implementation.com` source configuration containing Detected Source, Microsoft 365, Avanan, MailChimp, and HubSpot.
- Bifrost Design System registry source from `gobifrost/design-system` commit `f054a72` and the sibling `design-system` checkout.

## Product Principles

1. Show the evidence and the next safe action together.
2. Treat mappings, freshness, and provenance as visible product state.
3. Prefer guarded direct management over hidden hosted indirection.
4. Keep operational density without sacrificing loading, error, empty, or permission states.
5. Store customer data as install data, never as portable Solution definition.

## Accessibility & Inclusion

Primary journeys must support keyboard operation, visible focus, semantic tables and dialogs, readable contrast in both Bifrost themes, reduced motion, and responsive use inside the constrained Bifrost app host.
