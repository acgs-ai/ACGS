import { registerWorker } from "iii-sdk";

type GovernancePayload = {
  subject: string;
  action: string;
  resource: string;
};

type GovernanceDecision = {
  decision: "allow" | "deny";
  reason: string;
  mode: "experimental";
};

const worker = registerWorker(process.env.III_URL ?? "ws://localhost:49134", {
  workerName: "caller-worker",
});

worker.registerFunction(
  "governance::evaluate_request",
  async (payload: GovernancePayload): Promise<GovernanceDecision> => {
    return worker.trigger({
      function_id: "governance::evaluate_policy",
      payload,
    }) as Promise<GovernanceDecision>;
  },
);

worker.registerFunction(
  "http::evaluate_request",
  async (payload: { body: GovernancePayload }) => {
    const result = await worker.trigger({
      function_id: "governance::evaluate_request",
      payload: payload.body,
    }) as GovernanceDecision;

    return {
      status_code: 200,
      body: result,
      headers: { "Content-Type": "application/json" },
    };
  },
);

worker.registerTrigger({
  type: "http",
  function_id: "http::evaluate_request",
  config: {
    api_path: "/governance/evaluate",
    http_method: "POST",
  },
});
