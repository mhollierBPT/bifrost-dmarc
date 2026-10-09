# Bifrost DMARC app

Standalone app for the Bifrost DMARC Solution.

```bash
npm install
npm run typecheck
npm test
npm run build
```

The platform builds and serves the app from the Solution-managed application
definition.

## Bifrost Design System

This app owns source copied from `gobifrost/design-system` commit `f054a72` under
`src/components/bifrost`. It deliberately has no runtime design-system package.
To review a future upstream component before replacing local source:

```bash
node /path/to/design-system/scripts/add.mjs data-table --root "$PWD"
```

Preserve the copied components' focus, keyboard, portal, host-theme, and
reduced-motion behavior when adapting them for DMARC-specific use.
