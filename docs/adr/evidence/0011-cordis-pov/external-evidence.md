# External evidence — Cordis-style plugin lifecycle patterns for ACGS/govern-zone
Researched 2026-08-15. Frame: adopt the PATTERNS in Python, not the TypeScript library.

## Maturity & trajectory (Cordis itself)

- Cordis README self-describes as "A Meta-Framework of Spatiotemporal Composability" and carries an explicit
  warning: "Cordis is under active development. The API is not yet stable and may change without notice."
  ~4,000 stars, 198 forks, MIT. [verified: https://github.com/cordiverse/cordis]
- npm dist-tags: `{"next":"4.0.0-beta.5","latest":"4.0.0-rc.8"}` — the *latest* tag is a release candidate,
  not a stable major; first publish 2022-04-22. No GitHub releases page exists ("There aren't any releases
  here"), so version history lives only on npm. [verified: https://registry.npmjs.org/cordis +
  https://github.com/cordiverse/cordis/releases]
- Formal backing: preprint "A Programming Paradigm for Spatiotemporal Composability" (cordiverse/paper, dated
  2026-08-13, "under active revision"). Defines temporal composability = "completely revert a component's side
  effects upon removal"; spatial = "declare and reactively manage inter-component dependencies"; revertible
  effects = "every context transformation carries an inverse that the runtime tracks"; reactive coeffects =
  context changes notify components per their coeffect spec. README carries no empirical evaluation or named
  authors. [verified: https://github.com/cordiverse/paper/blob/main/README.md]
- Adoption is real and recent: Cordis is the plugin kernel of **DeepSeek Harness** (deepseek-ai/deepseek-harness,
  "Everything is a Plugin" — models, tools, sessions, sandboxes, storage, UI all plugins), which ships its own
  cordis-primer and lifecycle tutorial; a `@deepseek-ai/cordis` npm package exists. Multiple sources also state
  Cordis has been the foundation of the Koishi chatbot framework (~4,000 plugins) for ~4 years.
  [verified: https://github.com/deepseek-ai/deepseek-harness + https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-primer.md]
- Documented lifecycle semantics (from the DeepSeek Harness cordis-primer): `ctx.plugin()` mounts a plugin and
  returns a Fiber; a Context "is a repository of services" claimed under stable keys; `inject` names required
  services and "load order is expressed through service requirements rather than manual boot sequencing";
  `ctx.provide` binds a key to an implementation; registrations are reversible effects — resources Cordis does
  not manage are wrapped in `ctx.effect()` returning a disposer, and teardown runs disposers in reverse
  registration order when the owning fiber is disposed. [verified: https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-primer.md]
- Bus factor: single-org project (cordiverse); primer/tutorial docs live in the DeepSeek Harness repo rather
  than standalone stable docs. [single-source, inferred from repo structure]

## Pattern pedigree (the patterns are proven; Cordis is one packaging)

- OSGi Declarative Services (spec since ~2005, Compendium ch.112) is the same family: activate/deactivate
  callbacks, declarative references, components activated only when all required references are satisfied,
  SCR dynamically activates/deactivates components as services come and go.
  [verified: https://docs.osgi.org/specification/osgi.cmpn/8.1.0/service.component.html]
- OSGi experience is also the caution: "the complexity of handling service dynamicity negatively influences
  the adoption of the OSGi service model as well as the robustness and reliability of applications because
  these applications do not always handle the dynamicity correctly" — dynamic references can rebind "on any
  thread at any time." Dynamism is the expensive part of the pattern, not the disposers.
  [verified: https://arxiv.org/pdf/1508.05537 + OSGi DS spec]
- Disposable-on-registration is mainstream: VS Code extensions return Disposables for every registration and
  the host disposes them on deactivate; React useEffect cleanup and Kubernetes reconciliation (declared state,
  controller converges) are the same shape. [verified: pattern family widely documented; per-instance cites
  omitted for space — treat as background, not verdict-driving]

## Pitfalls (hot-reload / dynamic unload in audited systems)

- Python module reload is a minefield per the stdlib docs themselves: old definitions persist if the new
  module doesn't redefine them; external references and `from x import y` names are NOT rebound; existing
  instances keep old class definitions; extension modules "may fail in arbitrary ways when reloaded";
  reload is not thread-safe. [verified: https://docs.python.org/3/library/importlib.html]
  ⇒ Pattern-level adoption (registrations/disposables) is safe; *code* hot-reload in Python is not.
- Erlang/OTP — the most mature hot-upgrade culture — treats live upgrades as dangerous when data structures
  change: state must be transformed via code_change callbacks, wrong-moment upgrades corrupt state, "doing it
  right and safe is much more difficult than simply reloading code," and many teams prefer blue-green deploys
  instead. [verified: https://learnyousomeerlang.com/relups + https://www.oreilly.com/library/view/adopting-elixir/9781680505832/f_0070.xhtml]
- No source found claiming controlled unload/reload inherently breaks auditability; the risk surfaced in
  sources is state consistency across the swap, which for a receipt/audit system means: a reload event is
  itself an auditable state transition or the determinism claim weakens. [inference from above sources — no
  direct regulated-system postmortem located]

## Migration reality (Python ecosystem)

- pluggy (pytest's plugin core) has register/unregister of hook implementations but no effect/disposer system;
  its own history shows teardown fragility (exceptions during hookwrapper teardown caused later teardowns to
  be skipped/deferred until GC; fixed via new-style wrappers in 1.2+).
  [verified: https://pluggy.readthedocs.io/en/stable/api_reference.html + https://pluggy.readthedocs.io/en/latest/changelog.html]
- dependency-injector (ets-labs) provides the scoped-container half: Resource providers with init/shutdown,
  `container.init_resources()` / `shutdown_resources()` documented as respecting dependency order, async
  resources, FastAPI/Starlette Lifespan integration. Caveat: issue #432 "Resource shutdown ignores dependencies
  between resources" indicates ordering had real bugs — verify current behavior before relying on it.
  [verified: https://python-dependency-injector.ets-labs.org/providers/resource.html; caveat single-source:
  https://github.com/ets-labs/python-dependency-injector/issues/432]
- FastAPI yield-dependencies already give request-scoped setup/teardown natively — the scoped-services pattern
  has an idiomatic Python home without importing a framework. [verified: search-corroborated docs; standard
  FastAPI behavior]
- Flask precedent for retrofit cost: blueprints cannot be re-registered after the first request — retrofitting
  reload onto a framework that assumed startup-time registration fails structurally, not incrementally.
  [single-source: https://github.com/ChuckBuilds/LEDMatrix/pull/374 discussion]
- Net: Python has mature pieces for (1) disposables and (3) scoped services; no mainstream Python library was
  found offering (2) dependency-driven active/inactive state machines or (4) dependency-triggered controlled
  reload as a unit — those would be built, not imported. [inference from searches above]

## Counterfactual (staying with restart-based lifecycle)

- Erlang/Elixir literature explicitly frames the alternative: most teams accept restart-based deployment
  (blue-green/rolling) precisely because hot swap's correctness burden outweighs the downtime saved.
  [verified: Adopting Elixir "Upgrading Code" chapter]
- OSGi/K8s pedigree cuts the other way for *multi-tenant scoping*: process-global singletons mean one tenant's
  policy-bundle change forces a whole-process restart (all tenants' blast radius); scoped services shrink that
  radius. This is the strongest evidenced benefit; the reload half is the risk-heavy half.
  [inference; scoping benefit entailed by OSGi DS component model + DS spec dynamism sections]
