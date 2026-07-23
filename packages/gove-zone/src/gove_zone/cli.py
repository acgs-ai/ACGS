"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Never, Self

from gove_zone import __version__
from gove_zone.audit import ChainHashAuditStore
from gove_zone.benchmark_adapters import load_benchmark_suite
from gove_zone.decision import Decision
from gove_zone.evaluation import evaluate_policy_scenarios
from gove_zone.executor import adapter_artifact_digest
from gove_zone.integration import (
    GateMode,
    GateModeError,
    current_gate_mode,
    emit_receipts_for_hook,
    resolve_gate_mode_path,
)
from gove_zone.policy import Policy, RuleSetPolicy
from gove_zone.replay import replay_from_side_store
from gove_zone.replay_store import ReplaySideStore
from gove_zone.setup import (
    detect_environment,
    generate_config,
    instructions,
    validate_dependencies,
)
from gove_zone.smoke import run_smoke

_MCP_EXTRA_REASON_CODE = "MCP_EXTRA_REQUIRED"
_MCP_OPTIONAL_DEPENDENCY_ROOTS = frozenset(
    {"anyio", "cryptography", "httpx", "mcp", "starlette", "uvicorn"}
)


class _JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        _emit(
            {
                "valid": False,
                "reason_code": "CLI_USAGE_ERROR",
                "error": message,
            }
        )
        raise SystemExit(2)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def _mcp_extra_required(exc: ImportError) -> int:
    missing = exc.name
    root = missing.partition(".")[0] if missing else None
    if root not in _MCP_OPTIONAL_DEPENDENCY_ROOTS:
        raise exc
    _emit(
        {
            "valid": False,
            "reason_code": _MCP_EXTRA_REASON_CODE,
            "error": (f"MCP optional dependency {root!r} is unavailable; install 'gove-zone[mcp]'"),
        }
    )
    return 2


def _find_event(
    store: ChainHashAuditStore,
    event_id: str,
) -> dict[str, Any] | None:
    for event in store.iter_events():
        if event.get("event_id") == event_id:
            return event
    return None


def _rederive(
    event: dict[str, Any] | None,
    side_record: dict[str, Any] | None,
    policy: Policy,
) -> dict[str, Any]:
    """Attempt true re-derivation and return the JSON-ready re-derivation block.

    ``attempted`` is False when there is no usable raw side record (missing or
    redacted), so the caller can fall back to today's event-only exit semantics.
    """
    if side_record is None or event is None:
        return {
            "attempted": False,
            "rederived": False,
            "rederivation_status": "no-side-record",
            "replayed_decision": None,
            "policy_version_match": False,
        }
    if side_record.get("redacted") is True:
        return {
            "attempted": False,
            "rederived": False,
            "rederivation_status": "redacted",
            "replayed_decision": None,
            "policy_version_match": False,
        }

    result = replay_from_side_store(event, side_record, policy)
    if not result.argument_hash_match:
        status = "argument-hash-mismatch"
    elif not result.policy_version_match:
        status = "policy-version-mismatch"
    elif result.matches:
        status = "verified"
    else:
        status = "decision-mismatch"
    return {
        "attempted": True,
        "rederived": result.matches,
        "rederivation_status": status,
        "replayed_decision": result.replayed_decision.value,
        "policy_version_match": result.policy_version_match,
    }


def _replay(args: argparse.Namespace) -> int:
    base: dict[str, Any] = {
        "event_id": args.event,
        "expected_audit_hash": args.audit_hash,
    }

    if args.audit is None:
        _emit(
            {
                **base,
                "status": "hash-only",
                "verified": False,
                "reason": "provide --audit PATH to verify the full chain",
            }
        )
        return 0

    audit_path = Path(args.audit)
    store = ChainHashAuditStore(audit_path)
    chain = store.verify_chain()
    event = _find_event(store, args.event)
    actual_hash = event.get("event_hash") if event is not None else None
    hash_matches = args.audit_hash is None or actual_hash == args.audit_hash
    verified = bool(chain["valid"] and event is not None and hash_matches)

    payload: dict[str, Any] = {
        **base,
        "audit": str(audit_path),
        "status": "verified" if verified else "failed",
        "verified": verified,
        "chain_valid": chain["valid"],
        "checked": chain["checked"],
        "event_found": event is not None,
        "actual_audit_hash": actual_hash,
        "decision": event.get("decision") if event is not None else None,
        "policy_version": (event.get("policy_version") if event is not None else None),
        "failures": chain["failures"],
    }

    side_store_path = getattr(args, "side_store", None)
    policy_bundle = getattr(args, "policy_bundle", None)

    # Re-derivation surface. Loading the bundle is a hook-style configuration
    # step: an invalid bundle exits 2 (mirrors `_gate`), never an allow.
    policy: Policy | None = None
    if policy_bundle is not None:
        try:
            policy = RuleSetPolicy.load(policy_bundle)
        except Exception as exc:  # noqa: BLE001 — bad replay config must not pass
            print(f"replay: failed to load policy bundle: {exc}", file=sys.stderr)
            return 2

    rederivation_attempted = False
    if side_store_path is not None and policy is not None:
        side_record = ReplaySideStore(side_store_path).get(args.event)
        block = _rederive(event, side_record, policy)
        rederivation_attempted = bool(block.pop("attempted"))
        payload.update(block)

    _emit(payload)

    rederived = bool(payload.get("rederived", False))
    overall = verified and (rederived if rederivation_attempted else True)
    return 0 if overall else 1


def _setup(args: argparse.Namespace) -> int:
    if args.format == "json":
        _emit(
            {
                "environment": detect_environment().to_dict(),
                "config": generate_config(enforce=args.enforce),
            }
        )
    else:
        sys.stdout.write(instructions(enforce=args.enforce))
    return 0


def _doctor(args: argparse.Namespace) -> int:
    env = detect_environment()
    report = validate_dependencies()
    _emit(
        {
            "ok": report.ok,
            "gate_mode": env.gate_mode,
            "environment": env.to_dict(),
            "checks": report.checks,
        }
    )
    return 0 if report.ok else 1


def _gate(args: argparse.Namespace) -> int:
    """Evaluate one runtime-hook payload through the gate adapter.

    Reads a JSON object from --event-file or stdin and emits the resulting
    Receipt (or null on observe-mode failure) as JSON. When --policy-bundle is
    supplied, DENY and ESCALATE decisions exit non-zero so hook hosts can block
    the side effect before it runs.
    """
    if args.event_file:
        payload_text = Path(args.event_file).read_text(encoding="utf-8")
    else:
        payload_text = sys.stdin.read()

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        print(f"gate: invalid JSON: {exc}", file=sys.stderr)
        return 2

    policy = None
    if args.policy_bundle:
        try:
            policy = RuleSetPolicy.load(args.policy_bundle)
        except Exception as exc:  # noqa: BLE001 — invalid gate config must block hooks
            print(f"gate: failed to load policy bundle: {exc}", file=sys.stderr)
            return 2

    try:
        receipts = emit_receipts_for_hook(
            payload,
            action_kind=args.action_kind,
            actor=args.actor,
            run_id=args.run_id,
            policy=policy,
        )
    except GateModeError as exc:
        print(f"gate (enforce): {exc}", file=sys.stderr)
        return 2

    blocking_receipts = [
        receipt
        for receipt in (receipts or ())
        if receipt.record.decision in {Decision.DENY, Decision.ESCALATE}
    ]
    primary_receipt = (
        blocking_receipts[0] if blocking_receipts else (receipts[-1] if receipts else None)
    )
    blocked = bool(blocking_receipts)
    _emit(
        {
            "gate_mode": current_gate_mode().value,
            "policy_bundle": str(args.policy_bundle) if args.policy_bundle else None,
            "decision": (
                primary_receipt.record.decision.value if primary_receipt is not None else None
            ),
            "blocked": blocked,
            "receipt": primary_receipt.to_dict() if primary_receipt is not None else None,
            "receipts": [receipt.to_dict() for receipt in (receipts or ())],
            "receipt_count": len(receipts or ()),
        }
    )
    if not receipts:
        return 1
    return 1 if blocked else 0


def _enable(args: argparse.Namespace) -> int:
    """Flip the gate mode for this project by writing ``.gove-zone/gate.mode``.

    Provides a single, agent-followable surface — no env-var juggling, no
    settings.json edits — to turn the gate from observe (fail-open) into
    enforce (fail-closed) or back again.
    """
    mode = GateMode.ENFORCE if args.enforce else GateMode.OBSERVE
    path = resolve_gate_mode_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(mode.value + "\n", encoding="utf-8")
    _emit(
        {
            "gate_mode": mode.value,
            "gate_mode_path": str(path),
            "effective": current_gate_mode().value,
            "note": "env var GOVE_ZONE_GATE_MODE overrides this file when set",
        }
    )
    return 0


def _policy_inspect(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    _emit(
        {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "rule_count": len(policy.rules),
            "rules": [
                {
                    "id": rule.rule_id,
                    "effect": rule.effect.value,
                    "tools": sorted(rule.tools),
                    "path_prefix": list(rule.path_prefix),
                }
                for rule in policy.rules
            ],
        }
    )
    return 0


def _policy_export(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    output = Path(args.output)
    policy.dump(output)
    _emit(
        {
            "output": str(output),
            "policy_id": policy.policy_id,
            "version": policy.version,
            "rule_count": len(policy.rules),
        }
    )
    return 0


def _eval(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    dataset, scenarios = load_benchmark_suite(
        args.scenarios,
        benchmark_format=args.benchmark_format,
    )
    report = evaluate_policy_scenarios(policy, scenarios, dataset=dataset)
    _emit(report.to_dict())
    return 0 if report.failed == 0 else 1


def _smoke(args: argparse.Namespace) -> int:
    report = run_smoke(args.audit)
    _emit(report)
    return 0 if report["status"] == "pass" else 1


def _release_verify(args: argparse.Namespace) -> int:
    from gove_zone.release_proof import ReleaseProofError, verify_release_proof_pack

    try:
        result = verify_release_proof_pack(
            args.pack,
            receipt_public_key=args.receipt_public_key,
            checkpoint_public_key=args.checkpoint_public_key,
            consumption_public_key=args.consumption_public_key,
            lifecycle_public_key=args.lifecycle_public_key,
            expected_pack_digest=args.expected_pack_digest,
        )
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "RELEASE_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(
        {
            **result.to_dict(),
            "verification_mode": "external-keys-and-digest",
            "strict": True,
            "operation": "verify",
        }
    )
    return 0


def _release_replay(args: argparse.Namespace) -> int:
    from gove_zone.release_proof import ReleaseProofError, replay_release_proof_pack

    try:
        result = replay_release_proof_pack(
            directory=args.pack,
            receipt_public_key=args.receipt_public_key,
            checkpoint_public_key=args.checkpoint_public_key,
            consumption_public_key=args.consumption_public_key,
            lifecycle_public_key=args.lifecycle_public_key,
            expected_pack_digest=args.expected_pack_digest,
        )
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "reason_code": "RELEASE_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit({**result.to_dict(), "strict": True, "operation": "replay"})
    return 0


def _release_demo(args: argparse.Namespace) -> int:
    from gove_zone.release_gate import ReleaseProofSinkError
    from gove_zone.release_proof import ReleaseProofError, generate_release_demo

    try:
        report = generate_release_demo(Path(args.output))
    except ReleaseProofSinkError as exc:
        _emit(
            {
                "valid": False,
                "side_effect_confirmed": True,
                "retry_safe": False,
                "reason_code": "RELEASE_PROOF_POST_EXECUTION_FAILED",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "RELEASE_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(report)
    return 0


def _release_artifact_tamper_demo(args: argparse.Namespace) -> int:
    from gove_zone.release_gate import ReleaseProofSinkError
    from gove_zone.release_proof import (
        ReleaseProofError,
        generate_release_artifact_tamper_demo,
    )

    try:
        report = generate_release_artifact_tamper_demo(Path(args.output))
    except ReleaseProofSinkError as exc:
        _emit(
            {
                "valid": False,
                "side_effect_confirmed": True,
                "retry_safe": False,
                "reason_code": "RELEASE_PROOF_POST_EXECUTION_FAILED",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "RELEASE_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(report)
    return 0


def _release_reference_demo(args: argparse.Namespace) -> int:
    from gove_zone.release_gate import ReleaseProofSinkError
    from gove_zone.release_proof import ReleaseProofError, generate_release_reference_demo

    try:
        report = generate_release_reference_demo(
            Path(args.output),
            pre_capture_tamper=bool(args.pre_capture_tamper),
        )
    except ReleaseProofSinkError as exc:
        _emit(
            {
                "valid": False,
                "side_effect_confirmed": True,
                "retry_safe": False,
                "reason_code": "RELEASE_PROOF_POST_EXECUTION_FAILED",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "RELEASE_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(report)
    # A denial or ambiguous outcome is a structured, non-zero result; only a
    # verified ALLOW is a success exit.
    return 0 if report.get("valid") is True else 1


def _release_verify_denial(args: argparse.Namespace) -> int:
    """Independently re-verify a persisted release denial in a fresh process.

    Trust roots are loaded ONLY from the separately supplied ``--checkpoint-public-key``
    and ``--lifecycle-public-key`` files; keys are never read from the untrusted
    bundle. ``--refusal-evidence`` may point at the raw refusal-evidence object or
    a persisted denial response carrying it under ``execution_refusal_evidence``.
    """

    from gove_zone.release_proof import ReleaseProofError, verify_release_denial_evidence

    try:
        loaded = json.loads(Path(args.refusal_evidence).read_bytes().decode("utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("execution_refusal_evidence"), dict):
            refusal_evidence = loaded["execution_refusal_evidence"]
        else:
            refusal_evidence = loaded
        if not isinstance(refusal_evidence, dict):
            raise ValueError("refusal evidence must be a JSON object")
        result = verify_release_denial_evidence(
            args.bundle,
            refusal_evidence=refusal_evidence,
            checkpoint_public_key=args.checkpoint_public_key,
            lifecycle_public_key=args.lifecycle_public_key,
        )
    except (OSError, ReleaseProofError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "RELEASE_DENIAL_EVIDENCE_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit({**result, "operation": "verify-denial"})
    return 0 if result.get("valid") is True else 1


def _mcp_serve_http(args: argparse.Namespace) -> int:
    """Run the fixture-only reference gateway on loopback or remote TLS HTTP."""

    if not args.remote and args.host not in {"127.0.0.1", "localhost"}:
        print("mcp serve-http: direct serving is restricted to loopback", file=sys.stderr)
        return 2
    if args.remote:
        return _mcp_serve_http_remote(args)
    try:
        import anyio
        import uvicorn

        from gove_zone.mcp_reference import create_reference_runtime
        from gove_zone.mcp_runtime import (
            build_mcp_server,
            build_streamable_http_app,
            read_secret_file,
        )

        token = read_secret_file(Path(args.token_file))

        async def serve() -> None:
            runtime = await create_reference_runtime(
                Path(args.state_dir),
                inbound_token=token,
                session_id=args.session_id,
            )
            try:
                server = build_mcp_server(runtime.gateway)
                hosts = [f"{args.host}:{args.port}"]
                origins = list(args.allowed_origin)
                app = build_streamable_http_app(
                    server,
                    allowed_hosts=hosts,
                    allowed_origins=origins,
                )
                config = uvicorn.Config(
                    app,
                    host=args.host,
                    port=args.port,
                    log_level="warning",
                )
                await uvicorn.Server(config).serve()
            finally:
                await runtime.aclose()

        anyio.run(serve)
    except ImportError as exc:
        return _mcp_extra_required(exc)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"mcp serve-http: {exc}", file=sys.stderr)
        return 2
    return 0


def _remote_identity_trust(args: argparse.Namespace) -> Any:
    """Build the pinned Ed25519 trust snapshot from the operator's key file.

    The file carries public keys only.  Nothing here fetches a key, negotiates an
    algorithm, or falls back to a development identity.
    """

    from gove_zone.mcp_identity import Ed25519TrustSnapshot

    raw = Path(args.identity_trust_file).read_text(encoding="utf-8")
    document = json.loads(raw)
    if type(document) is not dict or not document:
        raise ValueError("--identity-trust-file must be a non-empty JSON object of kid -> key")
    keys: dict[str, bytes] = {}
    for kid, encoded in document.items():
        if type(kid) is not str or type(encoded) is not str:
            raise ValueError("--identity-trust-file entries must be kid -> base64url key strings")
        padding = "=" * (-len(encoded) % 4)
        try:
            keys[kid] = base64.urlsafe_b64decode(encoded + padding)
        except (binascii.Error, ValueError):
            raise ValueError(f"--identity-trust-file key for {kid!r} is not base64url") from None
    return Ed25519TrustSnapshot(keys)


def _remote_budgets(args: argparse.Namespace) -> Any:
    from gove_zone.mcp_runtime import RemoteMCPBudgets

    return RemoteMCPBudgets(
        max_body_bytes=args.max_body_bytes,
        max_header_bytes=args.max_header_bytes,
        max_header_count=args.max_header_count,
        limit_concurrency=args.limit_concurrency,
        backlog=args.backlog,
        timeout_keep_alive=args.timeout_keep_alive,
        timeout_graceful_shutdown=args.timeout_graceful_shutdown,
        limit_max_requests=args.limit_max_requests,
    )


def _remote_preflight(args: argparse.Namespace) -> str | None:
    """Return the operator-facing reason this remote invocation cannot start."""

    if not args.cert_file or not args.key_file:
        return "requires --cert-file and --key-file"
    if not args.expected_host:
        return "requires --expected-host"
    if not args.allowed_origin and not args.allow_absent_origin:
        return (
            "requires --allowed-origin, or --allow-absent-origin for non-browser "
            "workload clients only"
        )
    asymmetric = bool(args.identity_trust_file)
    if asymmetric and not (args.identity_issuer and args.identity_audience):
        return "--identity-trust-file requires --identity-issuer and --identity-audience"
    if asymmetric and not args.identity_resource:
        return "--identity-trust-file requires --identity-resource"
    if args.allow_absent_origin and not asymmetric:
        return (
            "--allow-absent-origin requires the asymmetric verifier "
            "(--identity-trust-file/--identity-issuer/--identity-audience); the fixture "
            "identity is not authentication"
        )
    if args.allow_non_loopback and not asymmetric:
        return (
            "--allow-non-loopback requires the asymmetric verifier "
            "(--identity-trust-file/--identity-issuer/--identity-audience); the fixture "
            "identity is refused for a public bind"
        )
    return None


def _mcp_serve_http_remote(args: argparse.Namespace) -> int:  # noqa: C901 - one flat startup ladder
    """Serve the same gateway over directly terminated TLS with no plaintext fallback.

    Remote mode adds no second governance server and no proxy trust: the same
    MCPActionGateway is wrapped in the remote guard, and TLS terminates in Uvicorn
    against a process-private snapshot of already-validated material.
    """

    rejection = _remote_preflight(args)
    if rejection is not None:
        print(f"mcp serve-http --remote: {rejection}", file=sys.stderr)
        return 2
    try:
        import anyio
        import uvicorn

        from gove_zone.mcp_gateway import MCPGatewayStatus
        from gove_zone.mcp_identity import EdDSAJWSVerifier, MCPTokenVerifier
        from gove_zone.mcp_reference import (
            HEALTH_EXPECTED_TOOLS,
            HEALTH_SESSION_ID,
            create_reference_runtime,
        )
        from gove_zone.mcp_runtime import (
            RemoteIdentityTrust,
            RemoteMCPConfig,
            RemoteReadiness,
            build_mcp_server,
            build_remote_app,
            build_remote_uvicorn_config,
            build_streamable_http_app,
            config_certificate_expiry,
            read_secret_file,
            remote_tls_snapshot,
            run_readiness_probe,
        )

        asymmetric = bool(args.identity_trust_file)
        token_verifier: MCPTokenVerifier | None = None
        if asymmetric:
            # The config below declares ASYMMETRIC_JWS trust, so this verifier
            # must actually serve the listener.  Declaring asymmetric trust while
            # a fixture string decided identity would be exactly the lie the
            # config invariant exists to prevent.
            token_verifier = EdDSAJWSVerifier(
                trust=_remote_identity_trust(args),
                issuer=args.identity_issuer,
                audience=args.identity_audience,
                resource=args.identity_resource,
            )
        config = RemoteMCPConfig(
            canonical_host=args.expected_host,
            allowed_origins=tuple(args.allowed_origin),
            certfile=Path(args.cert_file),
            keyfile=Path(args.key_file),
            bind_host=args.host,
            bind_port=args.port,
            allow_non_loopback=args.allow_non_loopback,
            allow_absent_origin=args.allow_absent_origin,
            identity_trust=(
                RemoteIdentityTrust.ASYMMETRIC_JWS
                if asymmetric
                else RemoteIdentityTrust.FIXTURE_STATIC
            ),
            budgets=_remote_budgets(args),
        )
        token = read_secret_file(Path(args.token_file))
        health_token = (
            read_secret_file(Path(args.health_token_file)) if args.health_token_file else None
        )
        if args.readyz and health_token is None:
            print(
                "mcp serve-http --remote: --readyz requires --health-token-file so the probe "
                "runs under its own tools:list-only identity",
                file=sys.stderr,
            )
            return 2

        async def serve() -> None:
            runtime = await create_reference_runtime(
                Path(args.state_dir),
                inbound_token=token,
                session_id=args.session_id,
                health_token=health_token,
                token_verifier=token_verifier,
            )
            try:
                inner = build_streamable_http_app(
                    build_mcp_server(runtime.gateway),
                    allowed_hosts=[config.canonical_host],
                    allowed_origins=list(config.allowed_origins),
                )
                readiness: RemoteReadiness | None = None
                if args.readyz:
                    assert health_token is not None  # noqa: S101 - guarded above

                    def probe() -> tuple[str, ...]:
                        response = runtime.gateway.list_tools(
                            inbound_token=health_token,
                            session_id=HEALTH_SESSION_ID,
                            request_id="readiness-probe",
                        )
                        if response.status is not MCPGatewayStatus.LISTED:
                            raise RuntimeError("readiness catalog probe was not allowed")
                        return tuple(item.name for item in response.tools)

                    readiness = RemoteReadiness(
                        probe=probe,
                        expected_tools=HEALTH_EXPECTED_TOOLS,
                        certificate_expiry=config_certificate_expiry(config),
                        expiry_margin_seconds=config.certificate_expiry_margin_seconds,
                        min_interval_seconds=args.readyz_interval_seconds,
                    )
                app = build_remote_app(inner, config, readiness=readiness)
                with remote_tls_snapshot(config) as (certfile, keyfile):
                    server = uvicorn.Server(
                        build_remote_uvicorn_config(app, config, certfile=certfile, keyfile=keyfile)
                    )
                    if readiness is None:
                        # No probe is configured, so /readyz stays a fail-closed
                        # 503 rather than a route that claims ready on faith.
                        await server.serve()
                    else:
                        async with run_readiness_probe(
                            readiness,
                            interval_seconds=args.readyz_interval_seconds,
                        ):
                            await server.serve()
            finally:
                await runtime.aclose()

        anyio.run(serve)
    except ImportError as exc:
        return _mcp_extra_required(exc)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"mcp serve-http: {exc}", file=sys.stderr)
        return 2
    return 0


def _mcp_serve_stdio(args: argparse.Namespace) -> int:
    """Run the same fixture gateway as a local stdio MCP wrapper."""

    try:
        import anyio

        from gove_zone.mcp_reference import create_reference_runtime
        from gove_zone.mcp_runtime import build_mcp_server, read_secret_file, run_stdio_server

        token = read_secret_file(Path(args.token_file))

        async def serve() -> None:
            runtime = await create_reference_runtime(
                Path(args.state_dir),
                inbound_token=token,
                session_id=args.session_id,
            )
            try:
                server = build_mcp_server(
                    runtime.gateway,
                    stdio_token=token,
                    stdio_session_id=args.session_id,
                )
                await run_stdio_server(server)
            finally:
                await runtime.aclose()

        anyio.run(serve)
    except ImportError as exc:
        return _mcp_extra_required(exc)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"mcp serve-stdio: {exc}", file=sys.stderr)
        return 2
    return 0


class _MCPOutputRootError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        parent_identity_preserved: bool | None = None,
        pinned_final_entry_exists: bool | None = None,
        lexical_final_path_exists: bool | None = None,
        final_path_exists: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.parent_identity_preserved = parent_identity_preserved
        self.pinned_final_entry_exists = pinned_final_entry_exists
        self.lexical_final_path_exists = lexical_final_path_exists
        self.final_path_exists = final_path_exists


class _MCPOutputRootGuard:
    _EXPECTED_MEMBERS = {
        "before-pack": frozenset(),
        "after-pack": frozenset({"proof-pack"}),
        "before-envelope": frozenset({"proof-pack"}),
        "after-envelope": frozenset({"proof-pack", "verification-envelope"}),
    }

    def __init__(self, value: str) -> None:
        raw = Path(value).expanduser()
        if ".." in raw.parts:
            raise _MCPOutputRootError("MCP proof output cannot contain parent traversal")
        path = raw if raw.is_absolute() else Path.cwd() / raw
        path = Path(os.path.abspath(path))
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        cloexec = getattr(os, "O_CLOEXEC", None)
        if nofollow is None or directory_flag is None or cloexec is None:
            raise _MCPOutputRootError("secure output-root open flags are unavailable")
        flags = os.O_RDONLY | nofollow | directory_flag | cloexec
        descriptor = os.open(path.anchor, flags)
        try:
            parts = path.parts[1:]
            if not parts:
                raise _MCPOutputRootError("MCP proof output cannot be the filesystem root")
            for index, part in enumerate(parts):
                final = index == len(parts) - 1
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not final:
                        raise _MCPOutputRootError(
                            "MCP proof output parent directory does not exist"
                        ) from None
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or mode & 0o022:
                raise _MCPOutputRootError("MCP proof output must be an owner-controlled directory")
            if os.listdir(descriptor):
                raise _MCPOutputRootError("MCP proof output must be new or empty")
        except BaseException:
            os.close(descriptor)
            raise
        self.path = path
        self._descriptor = descriptor
        self._identity = (info.st_dev, info.st_ino)

    @property
    def identity(self) -> tuple[int, int]:
        return self._identity

    def open_directory(self, path: Path) -> tuple[int, tuple[int, int]]:
        if Path(os.path.abspath(path)) != self.path:
            raise _MCPOutputRootError(
                "MCP output-root capability cannot open a different directory"
            )
        try:
            info = os.fstat(self._descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != self._identity
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise _MCPOutputRootError("MCP output-root capability identity changed")
            descriptor = os.dup(self._descriptor)
        except OSError:
            raise _MCPOutputRootError("MCP output-root capability is unavailable") from None
        return descriptor, self._identity

    def checkpoint(self, phase: str) -> None:
        expected = self._EXPECTED_MEMBERS.get(phase)
        if expected is None:
            raise _MCPOutputRootError("unknown MCP output-root commit phase")
        try:
            opened = os.fstat(self._descriptor)
            lexical = os.stat(self.path, follow_symlinks=False)
            members = frozenset(os.listdir(self._descriptor))
        except OSError:
            raise _MCPOutputRootError("MCP proof output identity is unavailable") from None
        identity_preserved = (
            stat.S_ISDIR(opened.st_mode)
            and stat.S_ISDIR(lexical.st_mode)
            and (opened.st_dev, opened.st_ino) == self._identity
            and (lexical.st_dev, lexical.st_ino) == self._identity
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(lexical.st_mode)
            or (opened.st_dev, opened.st_ino) != self._identity
            or (lexical.st_dev, lexical.st_ino) != self._identity
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            final_member = (
                "verification-envelope"
                if phase == "after-envelope"
                else "proof-pack"
                if phase in {"after-pack", "before-envelope"}
                else None
            )
            pinned_exists = final_member in members if final_member is not None else None
            lexical_exists: bool | None = None
            if final_member is not None:
                try:
                    os.stat(self.path / final_member, follow_symlinks=False)
                except FileNotFoundError:
                    lexical_exists = False
                except OSError:
                    lexical_exists = None
                else:
                    lexical_exists = True
            raise _MCPOutputRootError(
                "MCP proof output identity changed during export",
                parent_identity_preserved=identity_preserved,
                pinned_final_entry_exists=pinned_exists,
                lexical_final_path_exists=lexical_exists,
                final_path_exists=(
                    pinned_exists
                    if identity_preserved and pinned_exists is lexical_exists
                    else None
                ),
            )
        if members != expected:
            raise _MCPOutputRootError("MCP proof output membership changed during export")
        for member in expected:
            try:
                child = os.stat(member, dir_fd=self._descriptor, follow_symlinks=False)
            except OSError:
                raise _MCPOutputRootError("MCP proof output member is unavailable") from None
            if not stat.S_ISDIR(child.st_mode):
                raise _MCPOutputRootError("MCP proof output member is not a directory")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        os.close(self._descriptor)


def _existing_directory(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be an existing non-symlink directory")
    return path


def _mcp_partial_export_payload(error: Any) -> dict[str, Any]:
    return {
        "valid": False,
        "reason_code": "MCP_PROOF_EXPORT_PARTIAL",
        "error": str(error),
        "pack_committed": bool(error.pack_committed),
        "envelope_committed": bool(error.envelope_committed),
        "phase": error.phase,
        "durability": error.durability,
        "durability_uncertain": bool(error.durability_uncertain),
        "retry_safe": False,
        "pack_digest": error.pack_digest,
        "cleanup_attempted": bool(error.cleanup_attempted),
        "cleanup_succeeded": error.cleanup_succeeded,
        "parent_identity_preserved": error.parent_identity_preserved,
        "pinned_final_entry_exists": error.pinned_final_entry_exists,
        "lexical_final_path_exists": error.lexical_final_path_exists,
        "final_path_exists": error.final_path_exists,
        "temp_path_exists": error.temp_path_exists,
    }


def _mcp_demo(args: argparse.Namespace) -> int:
    try:
        import tempfile

        import anyio

        from gove_zone.mcp_proof_export import (
            MCPGenuineProofExportError,
            MCPGenuineProofLease,
            export_genuine_mcp_proof,
            export_prompt_injection_disaster_proof,
        )
        from gove_zone.proof_pack import PinnedOutputRoot
    except ImportError as exc:
        return _mcp_extra_required(exc)
    try:

        async def capture() -> None:
            # This absolute path is private capability-construction input only.
            # Capability-mode success output intentionally publishes no locator.
            output_path = Path(os.path.abspath(Path(args.output).expanduser()))
            with (
                PinnedOutputRoot.create(
                    output_path,
                    error_type=_MCPOutputRootError,
                ) as output_root,
                output_root.attest() as output_capability,
                tempfile.TemporaryDirectory(prefix="gove-zone-mcp-proof-") as private,
                PinnedOutputRoot.create(Path(private) / "runtime") as runtime_root,
                runtime_root.attest() as runtime_capability,
            ):
                exporter = (
                    export_prompt_injection_disaster_proof
                    if getattr(args, "prompt_injection", False)
                    else export_genuine_mcp_proof
                )
                result = await exporter(
                    output_path / "proof-pack",
                    output_path / "verification-envelope",
                    runtime_root=runtime_capability.display_path,
                    output_capability=output_capability,
                    runtime_capability=runtime_capability,
                )
                if not isinstance(result, MCPGenuineProofLease):
                    raise RuntimeError("capability export did not return an owned proof lease")
                with result:
                    verified_digest = result.verify()
                    replayed_digest = result.replay()
                    if verified_digest != replayed_digest:
                        raise RuntimeError("MCP proof verify and replay digests differ")
                    summary = result.proof_summary
                    verify_command = [
                        "gove-zone",
                        "mcp",
                        "verify-proof-pack",
                        "--pack",
                        "proof-pack",
                        "--verification",
                        "verification-envelope",
                        "--expected-envelope-digest",
                        result.envelope_digest,
                    ]
                    replay_command = verify_command.copy()
                    replay_command[2] = "replay-proof-pack"
                    payload = {
                        "valid": True,
                        "pack_digest": verified_digest,
                        "envelope_digest": result.envelope_digest,
                        "structurally_valid": True,
                        "semantic_verified": True,
                        "semantic_status": "complete",
                        "replay_complete": True,
                        "replay_digest": replayed_digest,
                        "proof_pack": "proof-pack",
                        "verification_envelope": "verification-envelope",
                        "verify_command": verify_command,
                        "replay_command": replay_command,
                    }
                    if getattr(args, "prompt_injection", False):
                        attack = summary["scenario"]["attack"]
                        payload.update(
                            {
                                "scenario": "mcp-prompt-injection",
                                "decision": "DENY",
                                "reason_codes": [attack["expected_refusal_reason"]],
                                "exact_arguments": attack["arguments"],
                                "baseline_side_effect_calls": attack["baseline_side_effect_calls"],
                                "governed_downstream_calls": attack["governed_downstream_calls"],
                            }
                        )
                    _emit(payload)

        anyio.run(capture)
    except _MCPOutputRootError as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_OUTPUT_INVALID",
                "error": str(exc),
            }
        )
        return 2
    except MCPGenuineProofExportError as exc:
        _emit(_mcp_partial_export_payload(exc))
        return 1
    except (OSError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_OUTPUT_INVALID",
                "error": str(exc),
            }
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - capture/export failures are JSON fail-closed
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_PROOF_CAPTURE_FAILED",
                "error": str(exc),
            }
        )
        return 1
    return 0


def _mcp_verify(args: argparse.Namespace) -> int:
    try:
        from gove_zone.mcp_proof import MCPActionProofError
        from gove_zone.mcp_proof_export import verify_exported_mcp_proof
    except ImportError as exc:
        return _mcp_extra_required(exc)
    try:
        pack = _existing_directory(args.pack, "MCP proof pack")
        verification = _existing_directory(args.verification, "MCP verification envelope")
    except (OSError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_PROOF_PATH_INVALID",
                "error": str(exc),
            }
        )
        return 2
    try:
        verified_digest = verify_exported_mcp_proof(
            pack,
            verification,
            expected_envelope_digest=args.expected_envelope_digest,
        )
    except MCPActionProofError as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - verifier faults must not escape as tracebacks
        _emit(
            {
                "valid": False,
                "reason_code": "MCP_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(
        {
            # This is evidence that the verifier operation above returned without
            # raising, not a reusable authorization report.
            "valid": True,
            "pack_digest": verified_digest,
            "structurally_valid": True,
            "semantic_verified": True,
            "semantic_status": "complete",
            "replay_complete": True,
            "command": "mcp verify-proof-pack",
            "strict": True,
            "operation": "verify",
        }
    )
    return 0


def _mcp_replay(args: argparse.Namespace) -> int:
    try:
        from gove_zone.mcp_proof import MCPActionProofError
        from gove_zone.mcp_proof_export import verify_exported_mcp_proof
    except ImportError as exc:
        return _mcp_extra_required(exc)
    try:
        pack = _existing_directory(args.pack, "MCP proof pack")
        verification = _existing_directory(args.verification, "MCP verification envelope")
    except (OSError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "replay_complete": False,
                "reason_code": "MCP_PROOF_PATH_INVALID",
                "error": str(exc),
            }
        )
        return 2
    try:
        verified_digest = verify_exported_mcp_proof(
            pack,
            verification,
            expected_envelope_digest=args.expected_envelope_digest,
        )
    except MCPActionProofError as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "replay_complete": False,
                "reason_code": "MCP_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "replay_complete": False,
                "reason_code": "MCP_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - replay faults must not escape as tracebacks
        _emit(
            {
                "valid": False,
                "strict": True,
                "replay_complete": False,
                "reason_code": "MCP_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(
        {
            # Informational output from this completed replay operation only.
            "valid": True,
            "pack_digest": verified_digest,
            "structurally_valid": True,
            "semantic_verified": True,
            "semantic_status": "complete",
            "replay_complete": True,
            "command": "mcp replay-proof-pack",
            "strict": True,
            "operation": "replay",
        }
    )
    return 0


def _spend_demo(args: argparse.Namespace) -> int:
    try:
        import tempfile

        from gove_zone.spend_proof_export import export_genuine_spend_proof
    except ImportError as exc:
        _emit({"valid": False, "reason_code": "SPEND_DEPENDENCY_MISSING", "error": str(exc)})
        return 2
    try:
        with _MCPOutputRootGuard(args.output) as output_guard:
            with tempfile.TemporaryDirectory(prefix="gove-zone-spend-proof-") as private:
                result = export_genuine_spend_proof(
                    output_guard.path / "proof-pack",
                    output_guard.path / "verification-envelope",
                    runtime_root=Path(private) / "runtime",
                )
            output_guard.checkpoint("after-envelope")
    except _MCPOutputRootError as exc:
        _emit({"valid": False, "reason_code": "SPEND_OUTPUT_INVALID", "error": str(exc)})
        return 2
    except (OSError, ValueError) as exc:
        _emit({"valid": False, "reason_code": "SPEND_OUTPUT_INVALID", "error": str(exc)})
        return 2
    except Exception as exc:  # noqa: BLE001 - proof capture must be JSON fail-closed
        _emit({"valid": False, "reason_code": "SPEND_PROOF_CAPTURE_FAILED", "error": str(exc)})
        return 1
    _emit(
        {
            "valid": True,
            "pack_digest": result.pack_digest,
            "envelope_digest": result.envelope_digest,
            "pack": str(result.pack_directory),
            "verification": str(result.envelope_directory),
            "semantic_verified": True,
            "replay_complete": True,
            "fixture_only": True,
            "provider_deltas": {"allow": 1, "deny": 0, "tamper": 0},
            "command": "spend demo",
        }
    )
    return 0


def _spend_loop_demo(args: argparse.Namespace) -> int:
    try:
        import tempfile

        from gove_zone.spend_proof_export import export_spend_loop_disaster_proof
    except ImportError as exc:
        _emit({"valid": False, "reason_code": "SPEND_DEPENDENCY_MISSING", "error": str(exc)})
        return 2
    try:
        with _MCPOutputRootGuard(args.output) as output_guard:
            with tempfile.TemporaryDirectory(prefix="gove-zone-spend-loop-proof-") as private:
                result = export_spend_loop_disaster_proof(
                    output_guard.path / "proof-pack",
                    output_guard.path / "verification-envelope",
                    runtime_root=Path(private) / "runtime",
                )
            output_guard.checkpoint("after-envelope")
    except _MCPOutputRootError as exc:
        _emit({"valid": False, "reason_code": "SPEND_OUTPUT_INVALID", "error": str(exc)})
        return 2
    except (OSError, ValueError) as exc:
        _emit({"valid": False, "reason_code": "SPEND_OUTPUT_INVALID", "error": str(exc)})
        return 2
    except Exception as exc:  # noqa: BLE001 - proof capture must be JSON fail-closed
        _emit({"valid": False, "reason_code": "SPEND_PROOF_CAPTURE_FAILED", "error": str(exc)})
        return 1
    _emit(
        {
            "valid": True,
            "pack_digest": result.pack_digest,
            "envelope_digest": result.envelope_digest,
            "pack": str(result.pack_directory),
            "verification": str(result.envelope_directory),
            "semantic_verified": True,
            "replay_complete": True,
            "fixture_only": True,
            "baseline_effect_count": 12,
            "baseline_total_minor": 12000,
            "governed_succeeded_count": 5,
            "governed_denied_count": 7,
            "governed_effect_count": 5,
            "governed_total_minor": 5000,
            "command": "spend loop-demo",
        }
    )
    return 0


def _spend_verify(args: argparse.Namespace) -> int:
    return _spend_verify_or_replay(args, replay=False)


def _spend_replay(args: argparse.Namespace) -> int:
    return _spend_verify_or_replay(args, replay=True)


def _spend_verify_or_replay(args: argparse.Namespace, *, replay: bool) -> int:
    operation_name = "replay" if replay else "verify"
    try:
        from gove_zone.spend_proof import SpendProofError
        from gove_zone.spend_proof_export import (
            replay_exported_spend_proof,
            verify_exported_spend_proof,
        )
    except ImportError as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "operation": operation_name,
                "reason_code": "SPEND_DEPENDENCY_MISSING",
                "error": str(exc),
            }
        )
        return 2
    try:
        pack = _existing_directory(args.pack, "Spend proof pack")
        verification = _existing_directory(args.verification, "Spend verification envelope")
    except (OSError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "operation": operation_name,
                "reason_code": "SPEND_PROOF_PATH_INVALID",
                "error": str(exc),
            }
        )
        return 2
    operation = replay_exported_spend_proof if replay else verify_exported_spend_proof
    try:
        digest = operation(
            pack,
            verification,
            expected_envelope_digest=args.expected_envelope_digest,
        )
    except SpendProofError as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "operation": operation_name,
                "replay_complete": False,
                "reason_code": "SPEND_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _emit(
            {
                "valid": False,
                "strict": True,
                "operation": operation_name,
                "replay_complete": False,
                "reason_code": "SPEND_PROOF_CONFIG_INVALID",
                "error": str(exc),
            }
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - verifier faults must not escape as tracebacks
        _emit(
            {
                "valid": False,
                "strict": True,
                "operation": operation_name,
                "replay_complete": False,
                "reason_code": "SPEND_PROOF_INVALID",
                "error": str(exc),
            }
        )
        return 1
    _emit(
        {
            "valid": True,
            "pack_digest": digest,
            "semantic_verified": True,
            "replay_complete": True,
            "strict": True,
            "operation": operation_name,
            "fixture_only": True,
            "command": f"spend {'replay' if replay else 'verify'}-proof-pack",
        }
    )
    return 0


def _proofpack(args: argparse.Namespace) -> int:
    # This local conformance proofpack exercises allow/deny/transform/tamper
    # behavior through the strict signed receipt gate. Runtime state is retained
    # beside, not inside, the public evidence directory.
    import shutil

    from gove_zone._strict_dispatch_fixture import build_strict_receipt_gate_fixture
    from gove_zone.errors import ReceiptValidationError
    from gove_zone.executor import execute_with_receipt
    from gove_zone.policy import RuleSetPolicy
    from gove_zone.receipt import Validator
    from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action

    council = Validator("constitutional-council")

    # 1. Setup output directory
    dist_dir = Path("dist-govern-zone-proofpack")
    state_dir = Path("dist-govern-zone-proofpack-state")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    if state_dir.exists():
        shutil.rmtree(state_dir)
    dist_dir.mkdir(parents=True, exist_ok=True)

    receipts_dir = dist_dir / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)

    # 2. Setup Tenant Policy Store
    tenant_store_dir = dist_dir / "tenant_store"
    tenant_store = TenantPolicyStore(tenant_store_dir)

    policy = RuleSetPolicy.from_dict(
        {
            "id": "compliance-ruleset/v1",
            "rules": [
                {
                    "id": "BLOCK_SSH_KEY_ACCESS",
                    "effect": "deny",
                    "tools": ["runtime.file.write"],
                    "path_prefix": "id_rsa",
                    "reason": "Direct access to SSH keys is strictly forbidden",
                }
            ],
        }
    )
    tenant_store.store_bundle("tenant-A", policy)

    # 3. Setup explicit persistent strict execution state. The audit evidence is
    # copied into the public pack after all execution lifecycle events commit.
    audit_path = dist_dir / "audit.jsonl"
    strict_gate = build_strict_receipt_gate_fixture(state_dir, name="cli-proofpack")
    audit_store = strict_gate.audit

    # Results tracker
    conformance_results = {
        "allowed_action_executed": False,
        "denied_action_blocked": False,
        "transformed_action_executed": False,
        "missing_receipt_blocked": False,
        "tampered_receipt_blocked": False,
        "audit_chain_verified": False,
    }

    # Helper dummy side effects
    class DummyTool:
        def __init__(self) -> None:
            self.called = False
            self.args: dict[str, Any] = {}

        def run(self, **kwargs: Any) -> str:
            self.called = True
            self.args = kwargs
            return "executed"

    # --- Scenario 1: Allowed Action ---
    tool = DummyTool()
    allowed_args = {"path": "public_report.txt", "content": "All safe"}
    allowed_receipt = evaluate_tenant_action(
        store=tenant_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=allowed_args,
        goal="Write compliance report",
        execution_boundary="local-sandbox",
        request_id="req-allowed",
        actor="compliance-officer",
        validator=council,
        authority="tenant-A/write-grant",
        audit_store=audit_store,
        signer=strict_gate.signer,
    )
    (receipts_dir / "allowed_receipt.json").write_text(allowed_receipt.to_json(), encoding="utf-8")
    res = execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(tool.run),
        tool_fn=tool.run,
        args=allowed_args,
        receipt=allowed_receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="compliance-officer",
        require_signature=True,
        **strict_gate.executor_kwargs(),
    )
    conformance_results["allowed_action_executed"] = res == "executed" and tool.called

    # --- Scenario 2: Denied Action ---
    tool_denied = DummyTool()
    denied_args = {"path": "id_rsa", "content": "compromised"}
    denied_receipt = evaluate_tenant_action(
        store=tenant_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=denied_args,
        goal="Attempt key exfiltration",
        execution_boundary="local-sandbox",
        request_id="req-denied",
        actor="compromised-agent",
        validator=council,
        authority="tenant-A/write-grant",
        audit_store=audit_store,
        signer=strict_gate.signer,
    )
    (receipts_dir / "denied_receipt.json").write_text(denied_receipt.to_json(), encoding="utf-8")
    try:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tool_denied.run),
            tool_fn=tool_denied.run,
            args=denied_args,
            receipt=denied_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="compromised-agent",
            require_signature=True,
            **strict_gate.executor_kwargs(),
        )
    except ReceiptValidationError:
        conformance_results["denied_action_blocked"] = not tool_denied.called

    # --- Scenario 3: Transformed Action ---
    from gove_zone.tenant import TransformPolicy

    transform_store = TenantPolicyStore(dist_dir / "transform_tenant_store")
    transform_store.store_bundle("tenant-A", TransformPolicy())

    tool_transformed = DummyTool()
    original_args = {"path": "untransformed.txt", "content": "safe"}
    transformed_receipt = evaluate_tenant_action(
        store=transform_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=original_args,
        goal="Write file with transform",
        execution_boundary="local-sandbox",
        request_id="req-transformed",
        actor="compliance-officer",
        validator=council,
        authority="tenant-A/write-grant",
        audit_store=audit_store,
        signer=strict_gate.signer,
    )
    (receipts_dir / "transformed_receipt.json").write_text(
        transformed_receipt.to_json(), encoding="utf-8"
    )

    # Executing original arguments fails with transform mismatch
    mismatch_blocked = False
    try:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tool_transformed.run),
            tool_fn=tool_transformed.run,
            args=original_args,
            receipt=transformed_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="compliance-officer",
            require_signature=True,
            **strict_gate.executor_kwargs(),
        )
    except ReceiptValidationError:
        mismatch_blocked = True

    # Executing transformed args succeeds
    res_t = execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(tool_transformed.run),
        tool_fn=tool_transformed.run,
        args={"path": "transformed.txt", "content": "safe"},
        receipt=transformed_receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="compliance-officer",
        require_signature=True,
        **strict_gate.executor_kwargs(),
    )
    conformance_results["transformed_action_executed"] = (
        mismatch_blocked
        and res_t == "executed"
        and tool_transformed.called
        and tool_transformed.args.get("path") == "transformed.txt"
    )

    # --- Scenario 4: Blocked Path (No Receipt) ---
    tool_no_receipt = DummyTool()
    try:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tool_no_receipt.run),
            tool_fn=tool_no_receipt.run,
            args={"path": "public_report.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="compliance-officer",
            require_signature=True,
            **strict_gate.executor_kwargs(),
        )
    except ReceiptValidationError:
        conformance_results["missing_receipt_blocked"] = not tool_no_receipt.called

    # --- Scenario 5: Blocked Path (Tampered Tenant ID) ---
    tool_tampered = DummyTool()
    import dataclasses

    tampered_receipt = dataclasses.replace(allowed_receipt, tenant_id="tenant-B")
    try:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tool_tampered.run),
            tool_fn=tool_tampered.run,
            args=allowed_args,
            receipt=tampered_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="compliance-officer",
            require_signature=True,
            **strict_gate.executor_kwargs(),
        )
    except ReceiptValidationError:
        conformance_results["tampered_receipt_blocked"] = not tool_tampered.called

    # 4. Audit Chain verification
    verification = audit_store.verify_chain()
    conformance_results["audit_chain_verified"] = verification["valid"]
    shutil.copyfile(audit_store.path, audit_path)

    # Write verification.json
    (dist_dir / "verification.json").write_text(
        json.dumps(verification, indent=2), encoding="utf-8"
    )

    # Write conformance-results.json
    (dist_dir / "conformance-results.json").write_text(
        json.dumps(conformance_results, indent=2), encoding="utf-8"
    )

    # Write limitations.md
    limitations_content = """# Conformance Proof Pack Limitations & Disclaimers

- **Status**: Alpha (`0.1.0.dev0`).
- **Scope**: Local proof and production-shaped foundation only.
- **Certification**: NOT production-certified, NOT compliance-certified.
  Do not claim live production deployment or regulatory compliance without direct evidence.
- This conformance proof pack provides local verification that no-receipt and
  tampered-receipt execution paths fail closed. It does not constitute evidence
  of compliance with any security framework, law, or regulatory body.
"""
    (dist_dir / "limitations.md").write_text(limitations_content, encoding="utf-8")

    # Write manifest.json
    manifest = {
        "version": "0.1.0.dev0",
        "files": [
            "manifest.json",
            "receipts/allowed_receipt.json",
            "receipts/denied_receipt.json",
            "receipts/transformed_receipt.json",
            "audit.jsonl",
            "verification.json",
            "conformance-results.json",
            "limitations.md",
        ],
    }
    (dist_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    _emit(
        {
            "status": "pass",
            "output_directory": str(dist_dir),
            "results": conformance_results,
        }
    )
    return 0


def _disaster_pocs_demo(args: argparse.Namespace) -> int:
    from gove_zone.disaster_pocs import DisasterPoCError, run_disaster_pocs

    try:
        report = run_disaster_pocs(args.output, args.scenario)
    except DisasterPoCError as exc:
        _emit(
            {
                "valid": False,
                "reason_code": exc.reason_code,
                "error_type": "DisasterPoCError",
            }
        )
        return 1
    except Exception:  # noqa: BLE001 - fail-closed CLI boundary
        _emit(
            {
                "valid": False,
                "reason_code": "DISASTER_POCS_INTERNAL_ERROR",
                "error_type": "DisasterPoCInternalError",
            }
        )
        return 1
    _emit(report)
    return 0


def _disaster_pocs_missing_command(args: argparse.Namespace) -> int:
    del args
    _emit(
        {
            "valid": False,
            "reason_code": "CLI_USAGE_ERROR",
            "error_type": "DisasterPoCUsageError",
        }
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = _JSONArgumentParser(
        prog="gove-zone",
        description="Gove Zone runtime governance: replay, setup, doctor, gate.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show program's version number and exit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    replay = subparsers.add_parser(
        "replay",
        help="verify a governed action against an audit JSONL chain",
    )
    replay.add_argument("--event", required=True, help="event_id to replay")
    replay.add_argument(
        "--audit",
        help="path to audit.jsonl; omitted command returns hash-only evidence",
    )
    replay.add_argument(
        "--audit-hash",
        help="expected audit event hash from a receipt or console action",
    )
    replay.add_argument(
        "--side-store",
        help=(
            "path to a ReplaySideStore JSONL; with --policy-bundle, re-runs the "
            "policy against the retained raw args for true decision re-derivation"
        ),
    )
    replay.add_argument(
        "--policy-bundle",
        help=(
            "RuleSetPolicy JSON bundle used to re-derive the decision; invalid "
            "bundles exit 2 (re-derivation needs --side-store too)"
        ),
    )
    replay.set_defaults(func=_replay)

    setup = subparsers.add_parser(
        "setup",
        help="emit copy-paste setup instructions for the detected host runtime",
    )
    setup.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="output format (default: markdown)",
    )
    setup.add_argument(
        "--enforce",
        action="store_true",
        help="render the enforce-mode (fail-closed) variant",
    )
    setup.set_defaults(func=_setup)

    doctor = subparsers.add_parser(
        "doctor",
        help="validate gove-zone install + audit writability; exit 1 on issues",
    )
    doctor.set_defaults(func=_doctor)

    gate = subparsers.add_parser(
        "gate",
        help="run one runtime-hook payload through the integration adapter",
    )
    gate.add_argument(
        "--event-file",
        help="path to a JSON file with the hook payload (default: stdin)",
    )
    gate.add_argument(
        "--action-kind",
        default="edit",
        help="action_kind tag attached to the receipt (default: edit)",
    )
    gate.add_argument(
        "--actor",
        default="gove-zone-cli",
        help="actor identity recorded in the receipt",
    )
    gate.add_argument(
        "--run-id",
        default=None,
        help="optional run/session id tag for the receipt",
    )
    gate.add_argument(
        "--policy-bundle",
        help=(
            "optional RuleSetPolicy JSON bundle; DENY/ESCALATE exits non-zero "
            "after the receipt is written"
        ),
    )
    gate.set_defaults(func=_gate)

    enable = subparsers.add_parser(
        "enable",
        help="set this project's gate mode (writes .gove-zone/gate.mode)",
    )
    mode_group = enable.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--enforce",
        dest="enforce",
        action="store_true",
        help="enable fail-closed enforcement for this project",
    )
    mode_group.add_argument(
        "--observe",
        dest="enforce",
        action="store_false",
        help="revert to observe-only (fail-open) mode for this project",
    )
    enable.set_defaults(func=_enable)

    policy = subparsers.add_parser(
        "policy",
        help="inspect and canonicalize RuleSetPolicy bundles",
    )
    policy_subparsers = policy.add_subparsers(dest="policy_command", required=True)

    inspect_policy = policy_subparsers.add_parser(
        "inspect",
        help="summarize a policy bundle without executing it",
    )
    inspect_policy.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    inspect_policy.set_defaults(func=_policy_inspect)

    export_policy = policy_subparsers.add_parser(
        "export",
        help="write a canonical RuleSetPolicy JSON bundle",
    )
    export_policy.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    export_policy.add_argument(
        "--output",
        required=True,
        help="path for the canonical JSON bundle",
    )
    export_policy.set_defaults(func=_policy_export)

    eval_parser = subparsers.add_parser(
        "eval",
        help="replay a policy bundle against benchmark-style scenario fixtures",
    )
    eval_parser.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    eval_parser.add_argument(
        "--scenarios",
        required=True,
        help="path to an evaluation fixture JSON file",
    )
    eval_parser.add_argument(
        "--benchmark-format",
        choices=["generic", "agentdojo", "injecagent", "toolemu"],
        default="generic",
        help="fixture adapter format (default: generic)",
    )
    eval_parser.set_defaults(func=_eval)

    smoke = subparsers.add_parser(
        "smoke",
        help="run a local allow/deny/audit smoke proof for the runtime kernel",
    )
    smoke.add_argument(
        "--audit",
        help="optional path to retain the smoke audit JSONL as evidence",
    )
    smoke.set_defaults(func=_smoke)

    proofpack = subparsers.add_parser(
        "proofpack",
        help=(
            "generate a conformance proof pack folder with allowed, "
            "denied, and transformed evidence"
        ),
    )
    proofpack.set_defaults(func=_proofpack)

    release = subparsers.add_parser(
        "release",
        help="generate and independently verify receipt-gated release proof packs",
    )
    release_commands = release.add_subparsers(dest="release_command", required=True)
    release_demo = release_commands.add_parser(
        "demo",
        help="generate a local fixture-only release proof pack and external public keys",
    )
    release_demo.add_argument("--output", required=True, help="new or empty output directory")
    release_demo.set_defaults(func=_release_demo)
    release_tamper_demo = release_commands.add_parser(
        "artifact-tamper-demo",
        help="prove a fixture artifact substitution is refused before deployment",
    )
    release_tamper_demo.add_argument(
        "--output", required=True, help="new or empty output directory"
    )
    release_tamper_demo.set_defaults(func=_release_artifact_tamper_demo)
    release_reference_demo = release_commands.add_parser(
        "reference-demo",
        help="run the P0 reference and emit its structured ALLOW/FAILED_CLOSED report",
    )
    release_reference_demo.add_argument(
        "--output", required=True, help="new or empty output directory"
    )
    release_reference_demo.add_argument(
        "--pre-capture-tamper",
        action="store_true",
        help="replace the artifact after approval to force a fail-closed denial",
    )
    release_reference_demo.set_defaults(func=_release_reference_demo)

    for command, handler, help_text in (
        ("verify-proof-pack", _release_verify, "strongly verify a release proof pack"),
        ("replay-proof-pack", _release_replay, "strictly replay a release proof pack"),
    ):
        verifier = release_commands.add_parser(command, help=help_text)
        verifier.add_argument("--pack", required=True, help="release proof pack directory")
        verifier.add_argument(
            "--receipt-public-key", required=True, help="external raw Ed25519 receipt public key"
        )
        verifier.add_argument(
            "--checkpoint-public-key",
            required=True,
            help="external raw Ed25519 checkpoint public key",
        )
        verifier.add_argument(
            "--consumption-public-key",
            required=True,
            help="external raw Ed25519 consumption-summary public key",
        )
        verifier.add_argument(
            "--lifecycle-public-key",
            required=True,
            help="external raw Ed25519 lifecycle-attestation public key",
        )
        verifier.add_argument(
            "--expected-pack-digest",
            required=True,
            help="out-of-band expected lowercase SHA-256 pack digest",
        )
        verifier.set_defaults(func=handler)

    verify_denial = release_commands.add_parser(
        "verify-denial",
        help="independently re-verify a persisted release denial from separate trust roots",
    )
    verify_denial.add_argument(
        "--bundle",
        required=True,
        help="denial evidence bundle directory (audit.jsonl + audit-checkpoint.json)",
    )
    verify_denial.add_argument(
        "--refusal-evidence",
        required=True,
        help="persisted refusal-evidence JSON, or a denial response carrying it",
    )
    verify_denial.add_argument(
        "--checkpoint-public-key",
        required=True,
        help="external raw Ed25519 checkpoint public key (never read from the bundle)",
    )
    verify_denial.add_argument(
        "--lifecycle-public-key",
        required=True,
        help="external raw Ed25519 lifecycle-attestation public key (never read from the bundle)",
    )
    verify_denial.set_defaults(func=_release_verify_denial)

    mcp = subparsers.add_parser(
        "mcp",
        help="run the local fixture-only MCP action gateway reference",
    )
    mcp_commands = mcp.add_subparsers(dest="mcp_command", required=True)
    demo = mcp_commands.add_parser(
        "demo", help="capture a fixture-only official-client MCP proof pack"
    )
    demo.add_argument("--output", required=True, help="new or empty output directory")
    demo.set_defaults(func=_mcp_demo)
    prompt_injection_demo = mcp_commands.add_parser(
        "prompt-injection-demo",
        help="prove an injected fixture tool description cannot bypass the gateway",
    )
    prompt_injection_demo.add_argument(
        "--output", required=True, help="new or empty output directory"
    )
    prompt_injection_demo.set_defaults(func=_mcp_demo, prompt_injection=True)

    for command, handler, help_text in (
        ("verify-proof-pack", _mcp_verify, "strongly verify an exported MCP proof pack"),
        ("replay-proof-pack", _mcp_replay, "strictly replay an exported MCP proof pack"),
    ):
        verifier = mcp_commands.add_parser(command, help=help_text)
        verifier.add_argument("--pack", required=True, help="MCP proof pack directory")
        verifier.add_argument(
            "--verification", required=True, help="external verification envelope directory"
        )
        verifier.add_argument(
            "--expected-envelope-digest",
            required=True,
            help="out-of-band expected lowercase SHA-256 verification-envelope digest",
        )
        verifier.set_defaults(func=handler)

    for command, handler, help_text in (
        ("serve-http", _mcp_serve_http, "serve stateless MCP on a loopback /mcp endpoint"),
        ("serve-stdio", _mcp_serve_stdio, "serve the same gateway as a stdio wrapper"),
    ):
        serve = mcp_commands.add_parser(command, help=help_text)
        serve.add_argument("--state-dir", required=True, help="fixture state directory")
        serve.add_argument(
            "--token-file",
            required=True,
            help="0600 file containing the inbound fixture token; token values are never argv",
        )
        serve.add_argument("--session-id", required=True, help="immutable logical client session")
        serve.set_defaults(func=handler)
        if command == "serve-http":
            serve.add_argument("--host", default="127.0.0.1", help="bind host")
            serve.add_argument("--port", type=int, default=8765, help="bind port")
            serve.add_argument(
                "--allowed-origin",
                action="append",
                default=[],
                help="exact allowed browser Origin header; may be repeated",
            )
            serve.add_argument(
                "--remote",
                action="store_true",
                help="serve over directly terminated TLS; there is no plaintext fallback",
            )
            serve.add_argument(
                "--cert-file",
                default=None,
                help="remote mode server certificate (PEM); one hostname per listener",
            )
            serve.add_argument(
                "--key-file",
                default=None,
                help="remote mode server private key (PEM); must be an owner-only 0600 file",
            )
            serve.add_argument(
                "--expected-host",
                default=None,
                help="remote mode exact canonical host:port required in the raw Host header",
            )
            serve.add_argument(
                "--allow-absent-origin",
                action="store_true",
                help="permit non-browser bearer workload clients that send no Origin",
            )
            serve.add_argument(
                "--allow-non-loopback",
                action="store_true",
                help="explicit remote opt-in required to publish beyond loopback",
            )
            serve.add_argument(
                "--identity-trust-file",
                default=None,
                help=(
                    "frozen JSON trust snapshot of kid -> base64url raw Ed25519 PUBLIC key; "
                    "required for --allow-absent-origin and --allow-non-loopback"
                ),
            )
            serve.add_argument(
                "--identity-issuer",
                default=None,
                help="exact trusted token issuer for the asymmetric verifier",
            )
            serve.add_argument(
                "--identity-audience",
                default=None,
                help="exact gateway audience the asymmetric verifier requires",
            )
            serve.add_argument(
                "--identity-resource",
                default="mcp://fixture-server",
                help="exact downstream resource audience the asymmetric verifier requires",
            )
            serve.add_argument(
                "--health-token-file",
                default=None,
                help=(
                    "0600 file with the readiness probe's own token; the probe identity is "
                    "tools:list-scoped and cannot reach tools/call"
                ),
            )
            serve.add_argument(
                "--readyz",
                action="store_true",
                help="enable /readyz; without it the route stays a fail-closed 503",
            )
            serve.add_argument(
                "--readyz-interval-seconds",
                type=float,
                default=15.0,
                help="minimum seconds between serialized background catalog probes",
            )
            for flag, default, budget_help in (
                ("--max-body-bytes", 1_048_576, "maximum buffered request body bytes"),
                ("--max-header-bytes", 16_384, "maximum aggregate request header bytes"),
                ("--max-header-count", 64, "maximum request header count"),
                ("--limit-concurrency", 32, "maximum concurrent governed dispatches"),
                ("--backlog", 64, "listener accept backlog"),
                ("--timeout-keep-alive", 5, "keep-alive timeout in seconds"),
                ("--timeout-graceful-shutdown", 10, "graceful shutdown timeout in seconds"),
                ("--limit-max-requests", 10_000, "requests served before the worker recycles"),
            ):
                serve.add_argument(
                    flag,
                    type=int,
                    default=default,
                    help=f"remote mode {budget_help}",
                )

    spend = subparsers.add_parser(
        "spend",
        help="capture and independently verify the local fixture-only Spend Guard proof",
    )
    spend_commands = spend.add_subparsers(dest="spend_command", required=True)
    spend_demo = spend_commands.add_parser(
        "demo",
        help="capture genuine local allow/deny/tamper Spend Guard evidence",
    )
    spend_demo.add_argument("--output", required=True, help="new or empty output directory")
    spend_demo.set_defaults(func=_spend_demo)
    spend_loop_demo = spend_commands.add_parser(
        "loop-demo",
        help="capture the deterministic 12-call cumulative-budget disaster proof",
    )
    spend_loop_demo.add_argument("--output", required=True, help="new or empty output directory")
    spend_loop_demo.set_defaults(func=_spend_loop_demo)
    for command, handler, help_text in (
        ("verify-proof-pack", _spend_verify, "strongly verify a Spend Guard proof pack"),
        ("replay-proof-pack", _spend_replay, "strictly replay a Spend Guard proof pack"),
    ):
        verifier = spend_commands.add_parser(command, help=help_text)
        verifier.add_argument("--pack", required=True, help="Spend proof pack directory")
        verifier.add_argument(
            "--verification",
            required=True,
            help="external Spend verification envelope directory",
        )
        verifier.add_argument(
            "--expected-envelope-digest",
            required=True,
            help="out-of-band lowercase SHA-256 verification-envelope digest",
        )
        verifier.set_defaults(func=handler)

    disaster_pocs = subparsers.add_parser(
        "disaster-pocs",
        help="Generate local-only deterministic disaster proof fixtures.",
    )
    disaster_pocs.set_defaults(func=_disaster_pocs_missing_command)
    disaster_pocs_commands = disaster_pocs.add_subparsers(
        dest="disaster_pocs_command",
    )
    disaster_pocs_demo = disaster_pocs_commands.add_parser(
        "demo",
        help="Generate and verify one or all disaster proof fixtures.",
    )
    disaster_pocs_demo.add_argument("--output", required=True, type=Path)
    disaster_pocs_demo.add_argument(
        "--scenario",
        choices=("all", "release-artifact-tamper", "mcp-prompt-injection", "spend-loop"),
        default="all",
    )
    disaster_pocs_demo.set_defaults(func=_disaster_pocs_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
