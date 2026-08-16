"""Receipt-gated release authorization at the final deployment boundary.

This module is a product adapter over the shared side-effect membrane.  It
does not define another receipt, policy evaluator, audit format, or replay
store.  A :class:`ReleaseGate` creates one fully-bound
:class:`~gove_zone.authorization.SideEffectRequest` and immediately routes the
result through :class:`~gove_zone.side_effect_kernel.ReceiptGatedSideEffectExecutor`.
The deployment adapter is registered inside that executor and is never handed
an authorization for later, out-of-band use.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

from gove_zone.authorization import (
    EvidenceRef,
    ExecutionReasonCode,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    deep_copy_json,
    strict_json_hash,
)
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.path_capability import ImmutableArtifactSnapshot
from gove_zone.policy import Policy, PolicyArtifactSnapshot, new_event_id
from gove_zone.receipt import safe_result_hash
from gove_zone.side_effect_kernel import (
    AdapterOutcome,
    ImmutableArtifactRequirement,
    PreAdapterDigestBinding,
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.tool import ToolCall

RELEASE_GATE_SERVER_ID = "acgs-release-gate"
RELEASE_GATE_TOOL = "deployment-adapter"
RELEASE_GATE_OPERATION = "release.deploy"
RELEASE_GATE_EXECUTION_BOUNDARY = "acgs-release-gate"
RELEASE_GATE_SIDE_EFFECT_CLASS = "production-deployment"
# The deployment route's receipted digest argument, and the keyword the proven
# snapshot reaches the adapter under. The snapshot parameter is deliberately
# outside ``ReleaseDeployment.canonical_arguments``: the receipt keeps binding
# ``artifact_digest`` and nothing else.
RELEASE_ARTIFACT_ARGUMENT = "artifact_digest"
RELEASE_ARTIFACT_SNAPSHOT_PARAMETER = "artifact_snapshot"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_BRANCH_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9_-])?\Z")
_RELEASE_ARGUMENT_KEYS = frozenset(
    {
        "repository",
        "ref",
        "branch",
        "commit_sha",
        "workflow_identity",
        "artifact_digest",
        "environment",
        "deployment_target",
        "required_evidence_set",
        "required_evidence_digest",
        "approval_identity",
    }
)
_EVIDENCE_REFERENCE_KEYS = frozenset(
    {"evidence_id", "evidence_type", "digest", "issuer", "issued_at", "expires_at"}
)
_EVIDENCE_SUBJECT_KEYS = frozenset(
    {"repository", "ref", "commit_sha", "artifact_digest", "workflow_identity"}
)
_EVIDENCE_CLAIM_KEYS = frozenset(
    {"evidence", "subject", "verifier_id", "signature", "claim_digest"}
)


def _text(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must be valid UTF-8") from None
    return value


def _sha256(value: object, field_name: str) -> str:
    text = _text(value, field_name)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return text


def _unique_sorted_texts(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{field_name} must be a sequence of strings")
    normalized = tuple(sorted(_text(value, field_name) for value in values))
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must contain unique values")
    return normalized


def _validate_repository(repository: str) -> str:
    repository = _text(repository, "repository")
    if (
        repository.startswith("/")
        or repository.endswith("/")
        or "//" in repository
        or ".." in repository.split("/")
        or any(character.isspace() for character in repository)
    ):
        raise ValueError("repository must be a canonical repository identifier")
    return repository


def _validate_branch(branch: str) -> str:
    branch = _text(branch, "branch")
    if (
        _BRANCH_RE.fullmatch(branch) is None
        or ".." in branch
        or "//" in branch
        or branch.endswith(".lock")
    ):
        raise ValueError("branch must be a canonical branch name")
    return branch


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceClaim:
    """Content-addressed evidence attestation bound to one exact release.

    ``signature`` remains opaque here: authenticity is established by the
    trusted policy artifact approving this claim's exact digest, issuer, and
    verifier key identifier. No secret or parallel verifier is introduced.
    """

    evidence: EvidenceRef
    repository: str
    ref: str
    commit_sha: str
    artifact_digest: str
    workflow_identity: str
    verifier_id: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, EvidenceRef):
            raise TypeError("evidence must be an EvidenceRef")
        normalized_evidence = EvidenceRef(**cast(dict[str, str], self.evidence.to_dict()))
        repository = _validate_repository(self.repository)
        ref = _text(self.ref, "ref")
        commit_sha = _text(self.commit_sha, "commit_sha")
        if _COMMIT_RE.fullmatch(commit_sha) is None:
            raise ValueError("commit_sha must be a lowercase 40- or 64-hex object id")

        object.__setattr__(self, "evidence", normalized_evidence)
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "ref", ref)
        object.__setattr__(self, "commit_sha", commit_sha)
        object.__setattr__(
            self,
            "artifact_digest",
            _sha256(self.artifact_digest, "artifact_digest"),
        )
        object.__setattr__(
            self,
            "workflow_identity",
            _text(self.workflow_identity, "workflow_identity"),
        )
        object.__setattr__(self, "verifier_id", _text(self.verifier_id, "verifier_id"))
        object.__setattr__(self, "signature", _text(self.signature, "signature"))

    def _claim_payload(self) -> dict[str, Any]:
        return {
            "evidence": self.evidence.to_dict(),
            "subject": {
                "repository": self.repository,
                "ref": self.ref,
                "commit_sha": self.commit_sha,
                "artifact_digest": self.artifact_digest,
                "workflow_identity": self.workflow_identity,
            },
            "verifier_id": self.verifier_id,
            "signature": self.signature,
        }

    @property
    def claim_digest(self) -> str:
        return strict_json_hash(self._claim_payload())

    def to_dict(self) -> dict[str, Any]:
        return {**self._claim_payload(), "claim_digest": self.claim_digest}


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceRequirement:
    """Exact trusted-policy approval for one evidence type and claim."""

    evidence_type: str
    approved_claim_digest: str
    approved_issuer: str
    approved_verifier_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_type", _text(self.evidence_type, "evidence_type"))
        object.__setattr__(
            self,
            "approved_claim_digest",
            _sha256(self.approved_claim_digest, "approved_claim_digest"),
        )
        object.__setattr__(
            self,
            "approved_issuer",
            _text(self.approved_issuer, "approved_issuer"),
        )
        object.__setattr__(
            self,
            "approved_verifier_id",
            _text(self.approved_verifier_id, "approved_verifier_id"),
        )

    @classmethod
    def from_claim(cls, claim: ReleaseEvidenceClaim) -> ReleaseEvidenceRequirement:
        if not isinstance(claim, ReleaseEvidenceClaim):
            raise TypeError("claim must be ReleaseEvidenceClaim")
        return cls(
            evidence_type=claim.evidence.evidence_type,
            approved_claim_digest=claim.claim_digest,
            approved_issuer=claim.evidence.issuer,
            approved_verifier_id=claim.verifier_id,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_type": self.evidence_type,
            "approved_claim_digest": self.approved_claim_digest,
            "approved_issuer": self.approved_issuer,
            "approved_verifier_id": self.approved_verifier_id,
        }


def _evidence_arguments(
    evidence: Sequence[ReleaseEvidenceClaim],
) -> list[dict[str, Any]]:
    return [
        item.to_dict() for item in sorted(evidence, key=lambda item: item.evidence.evidence_type)
    ]


@dataclass(frozen=True, slots=True)
class ReleaseDeployment:
    """Immutable deployment intent whose complete arguments are receipted."""

    repository: str
    ref: str
    branch: str
    commit_sha: str
    workflow_identity: str
    artifact_digest: str
    environment: str
    deployment_target: str
    approval_identity: str
    evidence: tuple[ReleaseEvidenceClaim, ...]

    def __post_init__(self) -> None:
        repository = _validate_repository(self.repository)
        branch = _validate_branch(self.branch)
        ref = _text(self.ref, "ref")
        if ref != f"refs/heads/{branch}":
            raise ValueError("ref must identify the immutable deployment branch")
        commit_sha = _text(self.commit_sha, "commit_sha")
        if _COMMIT_RE.fullmatch(commit_sha) is None:
            raise ValueError("commit_sha must be a lowercase 40- or 64-hex object id")
        artifact_digest = _sha256(self.artifact_digest, "artifact_digest")
        evidence = tuple(self.evidence)
        if not evidence or any(not isinstance(item, ReleaseEvidenceClaim) for item in evidence):
            raise TypeError("evidence must contain at least one ReleaseEvidenceClaim")
        evidence_types = [item.evidence.evidence_type for item in evidence]
        if len(set(evidence_types)) != len(evidence_types):
            raise ValueError("release evidence types must be unique")

        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "branch", branch)
        object.__setattr__(self, "ref", ref)
        object.__setattr__(self, "commit_sha", commit_sha)
        object.__setattr__(
            self, "workflow_identity", _text(self.workflow_identity, "workflow_identity")
        )
        object.__setattr__(self, "artifact_digest", artifact_digest)
        object.__setattr__(self, "environment", _text(self.environment, "environment"))
        object.__setattr__(
            self, "deployment_target", _text(self.deployment_target, "deployment_target")
        )
        object.__setattr__(
            self, "approval_identity", _text(self.approval_identity, "approval_identity")
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=lambda item: item.evidence.evidence_type)),
        )

    @property
    def required_evidence_digest(self) -> str:
        return strict_json_hash(_evidence_arguments(self.evidence))

    def canonical_arguments(self) -> dict[str, Any]:
        """Return the only argument object allowed to reach the adapter."""

        evidence_set = _evidence_arguments(self.evidence)
        return {
            "repository": self.repository,
            "ref": self.ref,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "workflow_identity": self.workflow_identity,
            "artifact_digest": self.artifact_digest,
            "environment": self.environment,
            "deployment_target": self.deployment_target,
            "required_evidence_set": evidence_set,
            "required_evidence_digest": strict_json_hash(evidence_set),
            "approval_identity": self.approval_identity,
        }


@dataclass(frozen=True, slots=True)
class ReleaseGateRequirements:
    """Content-addressed P0 policy requirements for release authorization."""

    required_evidence_claims: tuple[ReleaseEvidenceRequirement, ...]
    environment_targets: Mapping[str, Sequence[str]]
    production_branches: tuple[str, ...] = ("main",)
    production_environment: str = "production"
    allowed_repositories: tuple[str, ...] = ()
    allowed_workflow_identities: tuple[str, ...] = ()
    require_separation_of_duties: bool = True

    def __post_init__(self) -> None:
        claims = tuple(self.required_evidence_claims)
        if not claims or any(not isinstance(item, ReleaseEvidenceRequirement) for item in claims):
            raise TypeError(
                "required_evidence_claims must contain ReleaseEvidenceRequirement values"
            )
        claim_types = [item.evidence_type for item in claims]
        if len(set(claim_types)) != len(claim_types):
            raise ValueError("required evidence types must be unique")
        claims = tuple(sorted(claims, key=lambda item: item.evidence_type))

        if not isinstance(self.environment_targets, Mapping) or not self.environment_targets:
            raise TypeError("environment_targets must be a non-empty mapping")
        targets: dict[str, tuple[str, ...]] = {}
        for environment, allowed_targets in self.environment_targets.items():
            safe_environment = _text(environment, "environment")
            if safe_environment in targets:
                raise ValueError("environment target keys must be unique")
            normalized_targets = _unique_sorted_texts(
                allowed_targets,
                f"environment_targets[{safe_environment}]",
            )
            if not normalized_targets:
                raise ValueError("every environment must allow at least one immutable target")
            targets[safe_environment] = normalized_targets
        branches = _unique_sorted_texts(self.production_branches, "production_branches")
        if not branches:
            raise ValueError("production_branches must not be empty")
        branches = tuple(_validate_branch(branch) for branch in branches)
        production = _text(self.production_environment, "production_environment")
        if production not in targets:
            raise ValueError("production_environment must have an allowed target mapping")
        if type(self.require_separation_of_duties) is not bool:
            raise TypeError("require_separation_of_duties must be a bool")

        object.__setattr__(self, "required_evidence_claims", claims)
        object.__setattr__(
            self,
            "environment_targets",
            MappingProxyType(dict(sorted(targets.items()))),
        )
        object.__setattr__(self, "production_branches", branches)
        object.__setattr__(self, "production_environment", production)
        object.__setattr__(
            self,
            "allowed_repositories",
            tuple(
                _validate_repository(repository)
                for repository in _unique_sorted_texts(
                    self.allowed_repositories, "allowed_repositories"
                )
            ),
        )
        object.__setattr__(
            self,
            "allowed_workflow_identities",
            _unique_sorted_texts(self.allowed_workflow_identities, "allowed_workflow_identities"),
        )

    @property
    def required_evidence_by_type(self) -> Mapping[str, ReleaseEvidenceRequirement]:
        return MappingProxyType(
            {item.evidence_type: item for item in self.required_evidence_claims}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_evidence_claims": [item.to_dict() for item in self.required_evidence_claims],
            "environment_targets": {
                environment: list(targets)
                for environment, targets in self.environment_targets.items()
            },
            "production_branches": list(self.production_branches),
            "production_environment": self.production_environment,
            "allowed_repositories": list(self.allowed_repositories),
            "allowed_workflow_identities": list(self.allowed_workflow_identities),
            "require_separation_of_duties": self.require_separation_of_duties,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReleaseGateRequirements:
        """Rebuild the exact requirements from their canonical policy object."""

        if type(value) is not dict:
            raise TypeError("release gate requirements must be a JSON object")
        expected = {
            "required_evidence_claims",
            "environment_targets",
            "production_branches",
            "production_environment",
            "allowed_repositories",
            "allowed_workflow_identities",
            "require_separation_of_duties",
        }
        if set(value) != expected:
            raise ValueError("release gate requirements have an incompatible shape")

        raw_claims = value["required_evidence_claims"]
        if type(raw_claims) is not list or not raw_claims:
            raise TypeError("required_evidence_claims must be a non-empty list")
        claim_keys = {
            "evidence_type",
            "approved_claim_digest",
            "approved_issuer",
            "approved_verifier_id",
        }
        claims: list[ReleaseEvidenceRequirement] = []
        for raw_claim in raw_claims:
            if type(raw_claim) is not dict or set(raw_claim) != claim_keys:
                raise ValueError("release evidence requirement has an incompatible shape")
            claims.append(ReleaseEvidenceRequirement(**cast(dict[str, str], raw_claim)))

        raw_targets = value["environment_targets"]
        if type(raw_targets) is not dict:
            raise TypeError("environment_targets must be a JSON object")
        targets: dict[str, tuple[str, ...]] = {}
        for environment, raw_allowed in raw_targets.items():
            if type(environment) is not str or type(raw_allowed) is not list:
                raise TypeError("environment target entries must contain string lists")
            if any(type(item) is not str for item in raw_allowed):
                raise TypeError("environment target values must be strings")
            targets[environment] = tuple(cast(list[str], raw_allowed))

        sequences: dict[str, tuple[str, ...]] = {}
        for field_name in (
            "production_branches",
            "allowed_repositories",
            "allowed_workflow_identities",
        ):
            raw_sequence = value[field_name]
            if type(raw_sequence) is not list or any(
                type(item) is not str for item in raw_sequence
            ):
                raise TypeError(f"{field_name} must be a list of strings")
            sequences[field_name] = tuple(cast(list[str], raw_sequence))

        separation = value["require_separation_of_duties"]
        if type(separation) is not bool:
            raise TypeError("require_separation_of_duties must be a bool")
        return cls(
            required_evidence_claims=tuple(claims),
            environment_targets=targets,
            production_branches=sequences["production_branches"],
            production_environment=_text(value["production_environment"], "production_environment"),
            allowed_repositories=sequences["allowed_repositories"],
            allowed_workflow_identities=sequences["allowed_workflow_identities"],
            require_separation_of_duties=separation,
        )


@dataclass(frozen=True, slots=True)
class ReleaseProofContext:
    """Post-consumption evidence provided to an optional in-process sink.

    The context is not a wire schema.  A proof exporter must select only safe
    public evidence and must never serialize the executable authorization or
    its secret-bound reserved fields.
    """

    request: SideEffectRequest
    authorization: SideEffectAuthorization
    result_digest: str


class ReleaseProofSinkError(RuntimeError):
    """Evidence emission failed after the deployment was confirmed successful.

    Callers must not reinterpret this as a failed deployment or retry the
    side effect.  The explicit marker makes the post-side-effect state
    machine-readable to CLI and integration adapters.
    """

    side_effect_confirmed = True
    retry_safe = False


class ReleaseGatePolicy(Policy):
    """Deterministic P0 policy evaluated by the shared authorization kernel."""

    def __init__(
        self,
        requirements: ReleaseGateRequirements,
        *,
        version: str = "acgs-release-gate/v1",
    ) -> None:
        if not isinstance(requirements, ReleaseGateRequirements):
            raise TypeError("requirements must be ReleaseGateRequirements")
        self._requirements = requirements
        self._version = _text(version, "version")

    @property
    def version(self) -> str:
        return self._version

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        requirements = ReleaseGateRequirements(
            required_evidence_claims=tuple(
                ReleaseEvidenceRequirement(**item.to_dict())
                for item in self._requirements.required_evidence_claims
            ),
            environment_targets={
                environment: tuple(targets)
                for environment, targets in self._requirements.environment_targets.items()
            },
            production_branches=self._requirements.production_branches,
            production_environment=self._requirements.production_environment,
            allowed_repositories=self._requirements.allowed_repositories,
            allowed_workflow_identities=self._requirements.allowed_workflow_identities,
            require_separation_of_duties=self._requirements.require_separation_of_duties,
        )
        evaluator = ReleaseGatePolicy(requirements, version=self.version)
        return PolicyArtifactSnapshot.from_artifact(
            {
                "kind": "acgs.release-gate-policy",
                "version": self.version,
                "requirements": self._requirements.to_dict(),
            },
            evaluator=evaluator,
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        try:
            arguments = _validated_release_arguments(call.args)
        except (TypeError, ValueError):
            return self._deny(call, "RELEASE_INVALID_ARGUMENTS", "invalid release arguments")
        requirements = self._requirements
        if call.name != RELEASE_GATE_OPERATION:
            return self._deny(call, "RELEASE_WRONG_OPERATION", "release operation is not allowed")
        environment = cast(str, arguments["environment"])
        deployment_target = cast(str, arguments["deployment_target"])
        allowed_targets = requirements.environment_targets.get(environment)
        if allowed_targets is None:
            return self._deny(call, "RELEASE_ENVIRONMENT_DENIED", "environment is not allowed")
        if deployment_target not in allowed_targets:
            return self._deny(
                call,
                "RELEASE_TARGET_DENIED",
                "deployment target is not allowed for the environment",
            )
        if (
            environment == requirements.production_environment
            and arguments["branch"] not in requirements.production_branches
        ):
            return self._deny(
                call,
                "RELEASE_PRODUCTION_REF_DENIED",
                "production branch is not allowed",
            )
        if (
            requirements.allowed_repositories
            and arguments["repository"] not in requirements.allowed_repositories
        ):
            return self._deny(call, "RELEASE_REPOSITORY_DENIED", "repository is not allowed")
        if (
            requirements.allowed_workflow_identities
            and arguments["workflow_identity"] not in requirements.allowed_workflow_identities
        ):
            return self._deny(call, "RELEASE_WORKFLOW_DENIED", "workflow identity is not allowed")

        evidence_set = cast(list[dict[str, Any]], arguments["required_evidence_set"])
        try:
            claims = tuple(_claim_from_argument(item) for item in evidence_set)
        except (TypeError, ValueError):
            return self._deny(
                call,
                "RELEASE_EVIDENCE_CLAIM_INVALID",
                "release evidence claim is malformed",
            )
        claims_by_type = {item.evidence.evidence_type: item for item in claims}
        required = requirements.required_evidence_by_type
        if set(claims_by_type) != set(required):
            return self._deny(
                call,
                "RELEASE_REQUIRED_CHECK_MISSING",
                "the exact required release evidence set is missing",
            )
        expected_subject = (
            arguments["repository"],
            arguments["ref"],
            arguments["commit_sha"],
            arguments["artifact_digest"],
            arguments["workflow_identity"],
        )
        for evidence_type, requirement in required.items():
            claim = claims_by_type[evidence_type]
            if (
                claim.repository,
                claim.ref,
                claim.commit_sha,
                claim.artifact_digest,
                claim.workflow_identity,
            ) != expected_subject:
                return self._deny(
                    call,
                    "RELEASE_EVIDENCE_SUBJECT_MISMATCH",
                    "release evidence is bound to another release",
                )
            if (
                claim.claim_digest != requirement.approved_claim_digest
                or claim.evidence.issuer != requirement.approved_issuer
                or claim.verifier_id != requirement.approved_verifier_id
            ):
                return self._deny(
                    call,
                    "RELEASE_EVIDENCE_NOT_APPROVED",
                    "release evidence is not approved by the policy artifact",
                )
        if (
            requirements.require_separation_of_duties
            and arguments["approval_identity"] == call.actor
        ):
            return self._deny(
                call,
                "RELEASE_SELF_APPROVAL_DENIED",
                "release actor cannot approve its own deployment",
            )
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("RELEASE_REQUIREMENTS_SATISFIED",),
            reason="release requirements satisfied",
        )

    def _deny(self, call: ToolCall, rule: str, reason: str) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=(rule,),
            reason=reason,
        )


def _claim_from_argument(value: object) -> ReleaseEvidenceClaim:
    if type(value) is not dict or set(value) != _EVIDENCE_CLAIM_KEYS:
        raise ValueError("release evidence claim has an incompatible shape")
    item = cast(dict[str, object], value)
    raw_evidence = item["evidence"]
    if type(raw_evidence) is not dict or set(raw_evidence) != _EVIDENCE_REFERENCE_KEYS:
        raise ValueError("release evidence reference has an incompatible shape")
    evidence_values = cast(dict[str, object], raw_evidence)
    evidence = EvidenceRef(
        evidence_id=_text(evidence_values["evidence_id"], "evidence_id"),
        evidence_type=_text(evidence_values["evidence_type"], "evidence_type"),
        digest=_sha256(evidence_values["digest"], "evidence.digest"),
        issuer=_text(evidence_values["issuer"], "evidence.issuer"),
        issued_at=_text(evidence_values["issued_at"], "evidence.issued_at"),
        expires_at=_text(evidence_values["expires_at"], "evidence.expires_at"),
    )
    raw_subject = item["subject"]
    if type(raw_subject) is not dict or set(raw_subject) != _EVIDENCE_SUBJECT_KEYS:
        raise ValueError("release evidence subject has an incompatible shape")
    subject = cast(dict[str, object], raw_subject)
    claim = ReleaseEvidenceClaim(
        evidence=evidence,
        repository=_text(subject["repository"], "subject.repository"),
        ref=_text(subject["ref"], "subject.ref"),
        commit_sha=_text(subject["commit_sha"], "subject.commit_sha"),
        artifact_digest=_text(subject["artifact_digest"], "subject.artifact_digest"),
        workflow_identity=_text(subject["workflow_identity"], "subject.workflow_identity"),
        verifier_id=_text(item["verifier_id"], "verifier_id"),
        signature=_text(item["signature"], "signature"),
    )
    claimed_digest = _sha256(item["claim_digest"], "claim_digest")
    if claimed_digest != claim.claim_digest:
        raise ValueError("release evidence claim digest is inconsistent")
    return claim


def _validated_release_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    plain = deep_copy_json(dict(arguments))
    if type(plain) is not dict or set(plain) != _RELEASE_ARGUMENT_KEYS:
        raise ValueError("release arguments have an incompatible shape")
    values = cast(dict[str, Any], plain)
    values["repository"] = _validate_repository(values["repository"])
    values["branch"] = _validate_branch(values["branch"])
    values["ref"] = _text(values["ref"], "ref")
    if values["ref"] != f"refs/heads/{values['branch']}":
        raise ValueError("release ref and branch do not match")
    commit_sha = _text(values["commit_sha"], "commit_sha")
    if _COMMIT_RE.fullmatch(commit_sha) is None:
        raise ValueError("release commit is not immutable")
    values["commit_sha"] = commit_sha
    values["workflow_identity"] = _text(values["workflow_identity"], "workflow_identity")
    values["artifact_digest"] = _sha256(values["artifact_digest"], "artifact_digest")
    values["environment"] = _text(values["environment"], "environment")
    values["deployment_target"] = _text(values["deployment_target"], "deployment_target")
    values["approval_identity"] = _text(values["approval_identity"], "approval_identity")
    evidence_set = values["required_evidence_set"]
    if type(evidence_set) is not list or not evidence_set:
        raise ValueError("required_evidence_set must be a non-empty list")
    claims = [_claim_from_argument(item) for item in evidence_set]
    normalized_evidence = [item.to_dict() for item in claims]
    if normalized_evidence != sorted(
        normalized_evidence,
        key=lambda item: cast(dict[str, str], item["evidence"])["evidence_type"],
    ):
        raise ValueError("required evidence must be canonically ordered")
    evidence_types = [item.evidence.evidence_type for item in claims]
    if len(set(evidence_types)) != len(evidence_types):
        raise ValueError("required evidence types must be unique")
    values["required_evidence_set"] = normalized_evidence
    expected_digest = strict_json_hash(normalized_evidence)
    if _sha256(values["required_evidence_digest"], "required_evidence_digest") != expected_digest:
        raise ValueError("required evidence digest does not match its set")
    values["required_evidence_digest"] = expected_digest
    return values


class ReleaseGate:
    """One-shot release service that cannot yield an out-of-band permission."""

    def __init__(
        self,
        *,
        authorizer: SideEffectAuthorizationKernel,
        executor: ReceiptGatedSideEffectExecutor,
        deployment_adapter: Callable[..., AdapterOutcome],
        proof_sink: Callable[[ReleaseProofContext], None] | None = None,
    ) -> None:
        if not isinstance(authorizer, SideEffectAuthorizationKernel):
            raise TypeError("authorizer must be SideEffectAuthorizationKernel")
        if not isinstance(executor, ReceiptGatedSideEffectExecutor):
            raise TypeError("executor must be ReceiptGatedSideEffectExecutor")
        if not callable(deployment_adapter):
            raise TypeError("deployment_adapter must be callable")
        if proof_sink is not None and not callable(proof_sink):
            raise TypeError("proof_sink must be callable")
        self._authorizer = authorizer
        self._executor = executor
        self._proof_sink = proof_sink
        # Publish the adapter and its immutable-artifact requirement as one
        # atomic operation under the executor's registry lock. A concurrent
        # execute that freezes the registry can therefore never observe this
        # route with an adapter but no artifact requirement — the exact
        # interposition that previously let a deployment run with
        # ``snapshot_bytes_consumed=0``. The two-step registration path can no
        # longer produce that state (register_artifact_requirement refuses once
        # the adapter is published), and it is not used here.
        self._executor.register_route(
            RELEASE_GATE_SERVER_ID,
            RELEASE_GATE_TOOL,
            RELEASE_GATE_OPERATION,
            deployment_adapter,
            artifact_requirement=ImmutableArtifactRequirement(
                argument_name=RELEASE_ARTIFACT_ARGUMENT,
                snapshot_parameter=RELEASE_ARTIFACT_SNAPSHOT_PARAMETER,
            ),
        )

    def _pre_minted_binding(
        self,
        artifact_snapshot: ImmutableArtifactSnapshot | None,
    ) -> PreAdapterDigestBinding | None:
        """Wrap a caller pre-captured snapshot as a data-only pre-adapter binding.

        Passing a snapshot is the advanced API: the caller captured it earlier
        through the kernel-owned factory. Its digest is still re-verified inside
        the executor at the last controllable boundary. The ReleaseGate never
        captures a source itself and never validates the artifact here — a
        missing snapshot *and* missing source is not a pre-execute error but is
        forwarded so the executor fails closed with verifiable refusal evidence.
        """

        if artifact_snapshot is None:
            return None
        return PreAdapterDigestBinding(
            argument_name=RELEASE_ARTIFACT_ARGUMENT,
            snapshot=artifact_snapshot,
        )

    def deploy(
        self,
        deployment: ReleaseDeployment,
        *,
        artifact_snapshot: ImmutableArtifactSnapshot | None = None,
        artifact_source: Any = None,
        request_id: str,
        tenant_id: str,
        actor_id: str,
        actor_role: str,
        authority: str,
        policy_ref: ResolvedPolicyRef,
        requested_at: str,
        observed_at: str,
        nonce: str,
        idempotency_key: str,
        authentication_context: Mapping[str, Any],
    ) -> Any:
        """Authorize and execute one deployment without returning a receipt."""

        if not isinstance(deployment, ReleaseDeployment):
            raise TypeError("deployment must be ReleaseDeployment")
        artifact_binding = self._pre_minted_binding(artifact_snapshot)
        request = SideEffectRequest(
            request_id=request_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            authority=authority,
            server_id=RELEASE_GATE_SERVER_ID,
            tool=RELEASE_GATE_TOOL,
            operation=RELEASE_GATE_OPERATION,
            resource=deployment.repository,
            environment=deployment.environment,
            execution_boundary=RELEASE_GATE_EXECUTION_BOUNDARY,
            policy_ref=policy_ref,
            requested_at=requested_at,
            nonce=nonce,
            idempotency_key=idempotency_key,
            args=deployment.canonical_arguments(),
            evidence=tuple(item.evidence for item in deployment.evidence),
            side_effect_class=RELEASE_GATE_SIDE_EFFECT_CLASS,
            goal="deploy the approved immutable release artifact",
        )
        authorization = self._authorizer.authorize(request)
        binding = authorization.reserved_binding
        if authorization.executable and binding.get("validator_id") != deployment.approval_identity:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        context = SideEffectExecutionContext(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            actor_id=request.actor_id,
            actor_role=request.actor_role,
            authority=request.authority,
            server_id=request.server_id,
            tool=request.tool,
            operation=request.operation,
            resource=request.resource,
            environment=request.environment,
            execution_boundary=request.execution_boundary,
            policy_ref=request.policy_ref,
            observed_at=observed_at,
            authentication_context=authentication_context,
        )
        result = self._executor.execute(
            authorization,
            context,
            nonce=nonce,
            idempotency_key=idempotency_key,
            artifact_binding=artifact_binding,
            artifact_source=artifact_source,
        )
        if self._proof_sink is not None:
            try:
                self._proof_sink(
                    ReleaseProofContext(
                        request=request,
                        authorization=authorization,
                        result_digest=safe_result_hash(result),
                    )
                )
            except Exception as exc:
                raise ReleaseProofSinkError(
                    "deployment confirmed; proof export failed; DO NOT RETRY"
                ) from exc
        return result
