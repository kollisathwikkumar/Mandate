# Mandate frontend design and integration lock

## Research grounding

- **String Tune Skill Hub (`string-tune.fiddle.digital/skill-hub`)**: adapt reveal-on-scroll, restrained parallax, progress cues, magnetic hover, and kinetic typography. Use these for hierarchy and feedback; do not copy the reference site or animate every control.
- **Monad Metropolis (`monad.xyz/developers/hackathons/metropolis`)**: adapt the black, high-contrast stage, large condensed display typography, grid geometry, and edge-framed dimensional blocks. Keep its energy, but use Mandate's requested violet/cyan restrained accents and original content/structure.
- **Mandate architecture and OpenAPI 3.1 (`MANDATE_ARCHITECTURE.md`, `backend/API_HANDOFF.md`, `/api/v1/openapi.json`)**: the UI mirrors the actual control-plane lifecycle, tenant boundaries, and supported actions. UI copy must not imply arbitrary contracts, valuation/oracle support, or that a preflight simulates or sends an on-chain transaction.
- **Attached Skill Hub screenshot**: confirms the requested movement vocabulary: reveal, parallax, progress, glide, cursor response, magnetic controls, spotlight, impulse, split text, and sequenced entrances.

## Decision ledger

| Decision | Source | Role retained | Rationale |
| --- | --- | --- | --- |
| Ink-black canvas, white typography, one violet primary accent | User brief + Metropolis | Clear, cinematic contrast | Connect to visual reference while protecting readability and trust. |
| Modular 3D geometry and fine grid | Metropolis + user brief | Dimensional environmental stage | Keeps the surface recognizable without copying its campaign artwork. |
| Scroll reveal on the marketing and developer-documentation narrative; 3D motion on overview, login, and developer docs | String Tune + Metropolis + user brief | Staged storytelling and dimensional depth | Keeps operational tables calm while giving high-intent reading surfaces a memorable motion cue. |
| Magnetic cursor response is limited to high-intent public CTAs and the SSO entry, capped at 4px and disabled for touch/reduced motion | String Tune Skill Hub | Lightweight, reversible action feedback | Avoids distracting motion on frequent operational controls and preserves keyboard activation. |
| Dense but calm console with crisp data rows and explicit states | API handoff + architecture | Accurate operational hierarchy | Dashboard metrics and actions come from API responses, not invented fixtures. |
| All meaningful controls are links, form submissions, or API-backed mutations | OpenAPI + API handoff | Predictable and testable behavior | No decorative dead-end buttons; unsupported capabilities are labeled. |
| `prefers-reduced-motion`, touch-safe behavior, and a static 3D fallback | Three.js craft guidance | Access and resilience | Background motion must never gate content or actions. |
| OIDC authorization-code + PKCE; no raw model/agent/AWS keys in browser logs | Backend auth contract + security requirements | Standards-based session | Frontend forwards scoped bearer tokens only; sensitive provider credentials submit directly to the backend over same-origin HTTPS in deployment. |

## Scope lock

- Implement the 20 architecture route templates from the root `MANDATE_ARCHITECTURE.md`.
- Share the authenticated app shell and keep each section's route/content intentional; dynamic IDs reuse templates.
- Use the local API proxy during development; leave AWS deployment out of this phase.
- Keep public product copy to verified capabilities: deterministic policy evaluation, human approvals, supported smart-account transfer subset, audit trail, and receipt/reconciliation boundaries.
