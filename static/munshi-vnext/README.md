# Munshi vNext: Signal Atlas preview

Isolated preview. No existing frontend, backend, test or config file was changed.

## Open it
1. `python generate_logs.py` and `python generate_logs.py --hard` (if `logs/` is missing)
2. `python app.py`
3. Open **http://127.0.0.1:5000/static/munshi-vnext/index.html**
Use **Ctrl+K** (Cmd+K on Mac) for the command palette.

## Files
`index.html` (landing + workspace shell; the terrain SVG is inlined so CSS can animate it), `styles.css`, `app.js`, `assets/munshi-mark.svg`, `assets/munshi-signal-terrain.svg` (static standalone version of the artwork; the live page uses layered inline SVG), `DATA-MAP.md`.

## Live effects (implemented)
Landing: layered terrain with animated signal-ocean contours, light trail travelling a route positioned away from the main headline, six clickable/focusable signal nodes linked to the stage labels and story chapters, refined SSH-intelligence eyebrow treatment, pointer spotlight and multi-layer parallax (fine pointers only), scroll-linked story rail, and a short fade when launching the workspace.
Workspace: animated charts and rate bars, structured selected-finding readout, consistent evidence-path nodes with halo and center states, signal-path graphic per finding (hover a Findings row to preview, linked evidence node in Investigate), bar and recent-list hover linking in Watch, evidence-line flash, timeline draw-in, status dot driven by real request state, screen-reader status line.
With `prefers-reduced-motion`, wave animation, drift, trail, spotlight and parallax are off and the artwork is shown static. Decorative wave dots and floating particles are intentionally omitted.

## Constraints
- Server CSP is `default-src 'self'`: no inline style attributes, no Google Fonts, no data: URIs. Type is system font stacks; no custom display typeface is bundled.
- Uploaded log text is rendered with text nodes only; `innerHTML` is not used.
- The hero product panel is labelled "Illustrative sample, not live data". Its IP is from the RFC 5737 documentation range.

## Status
Not opened in a browser and not tested. Only `node --check app.js` was run.
