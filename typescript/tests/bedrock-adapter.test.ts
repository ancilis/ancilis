import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import {
  BedrockActionProducer,
  type BedrockInvocation,
} from "../src/ancilis/producers/bedrock.js";
import { ProducerType, type ActionProducer } from "../src/ancilis/producers/index.js";

function makeConfig(): ResolvedConfig {
  return loadConfig({
    raw: {
      agent: { name: "bedrock-agent" },
      security: { mode: "audit" },
    },
  });
}

function makeProducer(store?: EvidenceStore): BedrockActionProducer {
  const config = makeConfig();
  return new BedrockActionProducer(
    config,
    new Engine(config),
    undefined,
    store ?? new EvidenceStore(config, { inMemory: true }),
  );
}

describe("BedrockActionProducer", () => {
  it("satisfies the producer protocol and root export without AWS SDK imports", () => {
    const producer: ActionProducer = makeProducer();
    const root = ancilis as Record<string, unknown>;

    expect(producer.producerType).toBe(ProducerType.FRAMEWORK);
    expect(root.BedrockActionProducer).toBe(BedrockActionProducer);
  });

  it("normalizes InvokeModel Claude usage metadata without persisting request secrets", () => {
    const producer = makeProducer();
    const invocation: BedrockInvocation = {
      operation: "InvokeModel",
      modelId: "anthropic.claude-3-5-sonnet-20240620-v1:0",
      region: "us-east-1",
      requestBody: {
        anthropic_version: "bedrock-2023-05-31",
        messages: [{ role: "user", content: "sensitive prompt" }],
        max_tokens: 64,
      },
      responseBody: {
        id: "msg_123",
        type: "message",
        usage: { input_tokens: 12, output_tokens: 34 },
      },
      httpStatus: 200,
      requestId: "req-123",
      latencyMs: 87.5,
      headers: {
        Authorization: "AWS4-HMAC-SHA256 Credential=AKIASECRET/20260419/us-east-1/bedrock/aws4_request",
        "X-Amz-Security-Token": "session-token-secret",
      },
      agentId: "bedrock-agent",
    };

    const action = producer.translate(invocation);
    const raw = action.parameters.raw;

    expect(action.tool.name).toBe("aws-bedrock:InvokeModel");
    expect(action.tool.server).toBe("bedrock-runtime.us-east-1.amazonaws.com");
    expect(action.actionType).toBe("api_request");
    expect(action.producerType).toBe("framework");
    expect(raw.provider).toBe("aws-bedrock");
    expect(raw.operation).toBe("InvokeModel");
    expect(raw.model_id).toBe("anthropic.claude-3-5-sonnet-20240620-v1:0");
    expect(raw.region).toBe("us-east-1");
    expect(raw.http_status).toBe(200);
    expect(raw.latency_ms).toBe(87.5);
    expect(raw.request_id).toBe("req-123");
    expect(raw.input_tokens).toBe(12);
    expect(raw.output_tokens).toBe(34);
    expect(raw.auth_mode).toBe("session");
    expect(raw.deployment).toMatchObject({
      provider: "aws-bedrock",
      region: "us-east-1",
      model_id: "anthropic.claude-3-5-sonnet-20240620-v1:0",
      model_family: "anthropic.claude",
    });
    expect(raw.request).toMatchObject({
      body_present: true,
      body_keys: ["anthropic_version", "max_tokens", "messages"],
    });
    expect(JSON.stringify(raw)).not.toContain("sensitive prompt");
    expect(JSON.stringify(raw)).not.toContain("AKIASECRET");
    expect(JSON.stringify(raw)).not.toContain("session-token-secret");
  });

  it("accepts AWS SDK v3-style envelopes and inference profile ARNs", () => {
    const producer = makeProducer();
    const modelArn =
      "arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0";

    const action = producer.translate({
      operationName: "InvokeModel",
      input: {
        modelId: modelArn,
        body: JSON.stringify({ inputText: "private customer prompt" }),
      },
      output: {
        $metadata: {
          requestId: "aws-request-456",
          httpStatusCode: 200,
        },
        body: Buffer.from(JSON.stringify({
          inputTextTokenCount: 8,
          results: [{ tokenCount: 21, outputText: "private output" }],
        })),
      },
      regionName: "us-west-2",
      latencyMs: 102,
      agent: "bedrock-agent",
    });
    const raw = action.parameters.raw;

    expect(raw.model_id).toBe(modelArn);
    expect(raw.request_id).toBe("aws-request-456");
    expect(raw.http_status).toBe(200);
    expect(raw.input_tokens).toBe(8);
    expect(raw.output_tokens).toBe(21);
    expect(raw.deployment).toMatchObject({
      inference_profile_arn: modelArn,
      model_family: "anthropic.claude",
    });
    expect(JSON.stringify(raw)).not.toContain("private customer prompt");
    expect(JSON.stringify(raw)).not.toContain("private output");
  });

  it("records streaming usage metadata without buffering streamed content", () => {
    const producer = makeProducer();

    const action = producer.translate({
      operation: "InvokeModelWithResponseStream",
      modelId: "amazon.titan-text-premier-v1:0",
      region: "us-east-2",
      requestBody: { inputText: "stream prompt secret" },
      streamChunks: [
        { chunk: { bytes: Buffer.from(JSON.stringify({ outputText: "streamed secret text" })) } },
        {
          metadata: {
            usage: { input_tokens: 4, output_tokens: 9 },
            requestId: "stream-request-789",
          },
        },
      ],
      responseMetadata: { HTTPStatusCode: 200 },
      latencyMs: 250,
      agentId: "bedrock-agent",
    });
    const raw = action.parameters.raw;

    expect(raw.operation).toBe("InvokeModelWithResponseStream");
    expect(raw.streaming).toBe(true);
    expect(raw.stream).toMatchObject({ chunk_count: 2 });
    expect(raw.input_tokens).toBe(4);
    expect(raw.output_tokens).toBe(9);
    expect(raw.request_id).toBe("stream-request-789");
    expect(raw.deployment).toMatchObject({ model_family: "amazon.titan" });
    expect(JSON.stringify(raw)).not.toContain("stream prompt secret");
    expect(JSON.stringify(raw)).not.toContain("streamed secret text");
  });

  it("redacts credentials and signed request material from persisted payloads", () => {
    const producer = makeProducer();

    const action = producer.translate({
      operation: "InvokeModel",
      modelId: "anthropic.claude-3-haiku-20240307-v1:0",
      region: "us-east-1",
      body: { prompt: "hello" },
      responseBody: { usage: { input_tokens: 1, output_tokens: 2 } },
      headers: {
        authorization: "AWS4-HMAC-SHA256 Credential=AKIASECRET",
        "x-amz-security-token": "token-secret",
      },
      credentials: {
        aws_access_key_id: "AKIASECRET",
        aws_secret_access_key: "not-for-evidence",
        aws_session_token: "token-secret",
      },
      canonical_request: "POST\n/model\nsecret-signature-material",
      signed_headers: "authorization;x-amz-security-token",
      authMode: "AKIASECRET",
    });

    const serialized = JSON.stringify(action.parameters.raw).toLowerCase();
    expect(action.parameters.raw.auth_mode).toBe("session");
    expect(serialized).not.toContain("akia");
    expect(serialized).not.toContain("not-for-evidence");
    expect(serialized).not.toContain("token-secret");
    expect(serialized).not.toContain("authorization");
    expect(serialized).not.toContain("canonical_request");
    expect(serialized).not.toContain("signed_headers");
  });

  it("stores observed Bedrock evaluations with a concise evidence summary", async () => {
    const config = makeConfig();
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new BedrockActionProducer(config, new Engine(config), undefined, store);

    const observation = await producer.observe({
      operation: "InvokeModel",
      modelId: "anthropic.claude-3-haiku-20240307-v1:0",
      region: "us-east-1",
      responseBody: { usage: { input_tokens: 1, output_tokens: 2 } },
    });

    expect(observation.action.tool.name).toBe("aws-bedrock:InvokeModel");
    expect(observation.evaluation.sourceType).toBe("framework");
    expect(observation.evidence.toolName).toBe("aws-bedrock:InvokeModel");
    expect(observation.evidence.outputSummary).toContain(
      "aws-bedrock InvokeModel anthropic.claude-3-haiku-20240307-v1:0",
    );
  });
});
