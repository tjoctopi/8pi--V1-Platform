"""AWS Bedrock (Anthropic Claude) client for the Model Gateway.

Uses the boto3 default credential chain (EC2/ECS IAM role, ~/.aws profile, or
AWS_* environment variables) — no API key is stored in the app. Configure via:
  AWS_REGION        (default: us-east-1)
  BEDROCK_MODEL_ID  (default: us.anthropic.claude-opus-4-8 — Claude Opus 4.8 US geo profile)

The runtime needs the IAM permissions:
  bedrock:InvokeModel · bedrock:InvokeModelWithResponseStream
and model access enabled for the chosen model in the target region.
"""
import os
import boto3
from botocore.config import Config

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-opus-4-8")

_client = None


def get_client():
    global _client
    if _client is None:
        _client = boto3.client(
            "bedrock-runtime",
            region_name=AWS_REGION,
            config=Config(retries={"max_attempts": 2, "mode": "standard"},
                          connect_timeout=10, read_timeout=300),
        )
    return _client


def _messages(user_text):
    return [{"role": "user", "content": [{"text": user_text or ""}]}]


def _kwargs(system_msg, user_text, max_tokens, temperature):
    # NOTE: Claude Opus 4.8 on Bedrock rejects `temperature` in inferenceConfig
    # (ValidationException). We omit it (temperature kept in the signature for
    # backwards compatibility but not sent).
    kw = {
        "modelId": BEDROCK_MODEL_ID,
        "messages": _messages(user_text),
        "inferenceConfig": {"maxTokens": int(max_tokens or 512)},
    }
    if system_msg:
        kw["system"] = [{"text": system_msg}]
    return kw


def converse_text(system_msg, user_text, max_tokens=512, temperature=0.3):
    """Synchronous Converse call. Returns the assistant text. Raises on failure."""
    resp = get_client().converse(**_kwargs(system_msg, user_text, max_tokens, temperature))
    blocks = resp["output"]["message"]["content"]
    return "".join(b.get("text", "") for b in blocks if "text" in b)


def converse_stream(system_msg, user_text, max_tokens=1024, temperature=0.4):
    """Streaming ConverseStream call. Returns the boto3 response whose ['stream']
    yields events; iterate 'contentBlockDelta' -> delta['text']. Raises on failure."""
    return get_client().converse_stream(**_kwargs(system_msg, user_text, max_tokens, temperature))
