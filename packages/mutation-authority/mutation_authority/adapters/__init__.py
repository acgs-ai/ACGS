"""Runtime adapters: the integration surface of the Mutation Authority layer.

Runtimes (gove-zone executor, CI jobs, agent harnesses) call
``MutationGateway.request_mutation`` instead of touching the filesystem.
"""

from .runtime import AuthorityContext, GatewayResult, MutationGateway

__all__ = ["AuthorityContext", "GatewayResult", "MutationGateway"]
