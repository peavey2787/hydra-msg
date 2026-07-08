# P11 — Mobile-first polish and accessibility

Status: milestone implementation note.

P11 improves the existing local browser GUI so it behaves more like a polished chat application and less like a test dashboard. This pass does not change HYDRA protocol semantics, app-domain persistence, GUI security policy, CLI behavior, or API routes.

## Scope

This milestone changed only the GUI presentation/accessibility layer and static-asset tests:

- `examples/hydra-app/src/gui/assets/index.html`
- `examples/hydra-app/src/gui/assets/app.css`
- `examples/hydra-app/src/gui/assets/app.js`
- `examples/hydra-app/src/gui/mod.rs`

## Mobile-first layout

The app keeps the existing desktop sidebar but improves narrow-screen behavior:

- navigation becomes horizontally scrollable on mobile;
- tab targets have larger touch-friendly sizing;
- forms and action buttons stretch to full width on narrow screens;
- chat list/thread layout collapses to one column;
- message bubbles use full width on narrow screens;
- terminals and message threads are bounded so they do not dominate small screens;
- long keys, fingerprints, join codes, and JSON output wrap safely.

## Accessibility improvements

The GUI now includes:

- skip link to jump past navigation;
- screen-reader-only live status region;
- navigation as a tablist with `role="tab"`, `aria-controls`, and `aria-selected`;
- content sections as `role="tabpanel"` regions;
- keyboard navigation for the tablist with arrow keys, Home, and End;
- visible focus indicators for buttons, inputs, textareas, selects, summaries, and focusable panels;
- `aria-live="polite"` status on setup, bootstrap review, contact review, config output, recovery status, recovery output, and app status surfaces;
- `prefers-reduced-motion` handling;
- improved contrast for muted text.

## Advanced disclosure consistency

P11 keeps the existing `details.advanced > summary` model and improves the visual consistency of Advanced sections. Advanced controls remain hidden by default and are not required for normal user flows.

## Production language cleanup

Normal dashboard copy now focuses on local encrypted chat. Developer/test controls remain available only behind the Advanced developer/test disclosure.

## Boundary audit

P11 is primarily UI polish. The relevant boundary values are viewport breakpoints and interactive target sizes:

- mobile layout breakpoint: `860px`;
- compact layout breakpoint: `520px`;
- normal input/button target minimum: `48px`;
- summary disclosure target minimum: `44px`.

These boundaries are represented in CSS and checked by a static-asset test. No protocol counters, replay windows, cryptographic constants, storage versions, or rejection thresholds were introduced.

## Non-goals

P11 does not add:

- production relay/mailbox behavior;
- protocol changes;
- new app-domain features;
- identity-vault behavior changes;
- storage behavior changes;
- final production-release claims.
