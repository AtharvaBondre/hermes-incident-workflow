# Model costing and token accounting

This document defines how to answer "what does this cost per day?" without
guessing. Use it for pilot planning and for customer-pack readiness reviews.

Pricing changes over time. Refresh the source pricing pages before quoting a
customer.

## Current public model prices

Rates below are USD per 1 million tokens, checked on 24 August 2026.

### OpenAI API, standard processing

Source: `https://developers.openai.com/api/docs/pricing`

| Model | Input | Cached input | Cache write | Output |
|---|---:|---:|---:|---:|
| `gpt-5.6-sol` | $4.00 | $0.40 | $5.00 | $20.00 |
| `gpt-5.6-terra` | $2.00 | $0.20 | $2.50 | $12.00 |
| `gpt-5.6-luna` | $0.20 | $0.02 | $0.25 | $1.20 |
| `gpt-5.5`, prompts < 272k tokens | $5.00 | $0.50 | n/a | $30.00 |
| `gpt-5.5-pro`, prompts < 272k tokens | $30.00 | n/a | n/a | $180.00 |
| `gpt-5.4` | $2.50 | $0.25 | n/a | $15.00 |
| `gpt-5.4-mini` | $0.75 | $0.075 | n/a | $4.50 |
| `gpt-5.4-nano` | $0.20 | $0.02 | n/a | $1.25 |
| `gpt-5.4-pro`, prompts < 272k tokens | $30.00 | n/a | n/a | $180.00 |
| `gpt-5.2` | $1.75 | $0.175 | n/a | $14.00 |
| `gpt-5.2-pro` | $21.00 | n/a | n/a | $168.00 |
| `gpt-5.1` | $1.25 | $0.125 | n/a | $10.00 |
| `gpt-5` | $1.25 | $0.125 | n/a | $10.00 |
| `gpt-5-mini` | $0.25 | $0.025 | n/a | $2.00 |
| `gpt-5-nano` | $0.05 | $0.005 | n/a | $0.40 |
| `gpt-5-pro` | $15.00 | n/a | n/a | $120.00 |
| `gpt-4.1` | $2.00 | $0.50 | n/a | $8.00 |
| `gpt-4.1-mini` | $0.40 | $0.10 | n/a | $1.60 |
| `gpt-4.1-nano` | $0.10 | $0.025 | n/a | $0.40 |

OpenAI's pricing page notes that regional processing may add a 10 percent uplift
for eligible models, OpenAI models billed through Amazon Bedrock may differ from
direct OpenAI pricing, and GPT-5.6 Sol promotional pricing is available at least
through 21 November 2026.

### Anthropic API

Source: `https://docs.anthropic.com/en/docs/about-claude/pricing.md`

| Model | Input | 5-minute cache write | 1-hour cache write | Cache hit | Output |
|---|---:|---:|---:|---:|---:|
| Claude Opus 5 | $5.00 | $6.25 | $10.00 | $0.50 | $25.00 |
| Claude Opus 4.8 | $5.00 | $6.25 | $10.00 | $0.50 | $25.00 |
| Claude Sonnet 5 | $2.00 | $2.50 | $4.00 | $0.20 | $10.00 |
| Claude Sonnet 4.6 | $3.00 | $3.75 | $6.00 | $0.30 | $15.00 |
| Claude Haiku 4.5 | $1.00 | $1.25 | $2.00 | $0.10 | $5.00 |

For Anthropic-native usage records, calculate cost from the response `usage`
object:

```text
claude_cost_usd =
  input_tokens                 / 1_000_000 * input_price
+ cache_creation_input_tokens  / 1_000_000 * cache_write_price
+ cache_read_input_tokens      / 1_000_000 * cache_hit_price
+ output_tokens                / 1_000_000 * output_price
```

Use the 5-minute or 1-hour cache-write price that matches the configured
`cache_control` TTL. If no cache is configured, set both cache token fields to
zero.

Example only, not a measured POC result: for a run with `100,000` input tokens,
`10,000` output tokens, and no cache:

| Model | Calculation | Cost |
|---|---|---:|
| Claude Opus 5 | `100000/1M*$5 + 10000/1M*$25` | $0.75 |
| Claude Sonnet 5 | `100000/1M*$2 + 10000/1M*$10` | $0.30 |
| Claude Sonnet 4.6 | `100000/1M*$3 + 10000/1M*$15` | $0.45 |
| Claude Haiku 4.5 | `100000/1M*$1 + 10000/1M*$5` | $0.15 |

### Google Gemini API, standard paid tier

Source: `https://ai.google.dev/gemini-api/docs/pricing`

| Model | Input | Cached input | Output |
|---|---:|---:|---:|
| `gemini-3.1-pro-preview`, prompts <= 200k tokens | $2.00 | $0.20 | $12.00 |
| `gemini-3.1-pro-preview`, prompts > 200k tokens | $4.00 | $0.40 | $18.00 |
| `gemini-2.5-pro`, prompts <= 200k tokens | $1.25 | $0.125 | $10.00 |
| `gemini-2.5-pro`, prompts > 200k tokens | $2.50 | $0.25 | $15.00 |
| `gemini-2.5-flash` | $0.30 | $0.03 | $2.50 |
| `gemini-2.5-flash-lite` | $0.10 | $0.01 | $0.40 |

Google output prices include thinking tokens for the listed models. Context
cache storage and grounding/search fees are separate line items.

## Cost formula

For one incident run:

```text
model_cost_usd =
  input_tokens       / 1_000_000 * input_price
+ cached_input_tokens / 1_000_000 * cached_input_price
+ cache_write_tokens  / 1_000_000 * cache_write_price
+ output_tokens      / 1_000_000 * output_price
```

Then:

```text
daily_model_cost_usd = incidents_per_day * average_model_cost_per_incident
daily_total_cost_usd = daily_model_cost_usd + worker_compute + connector/API overhead
```

Do not use elapsed seconds as a proxy for model billing. Hosted model billing is
token-based unless the selected provider contract says otherwise.

## Recorded POC usage

The public repository's deterministic fixture runs use the fixture provider or a
local scripted provider. They do not make paid model requests and therefore have
no billable model token usage.

For an explicitly authorized real-model run, the controller reads only the
selected disposable Hermes session tree and retains exact provider-reported
`input_tokens`, `cache_read_tokens`, `cache_write_tokens`, `output_tokens`, and
`reasoning_tokens` buckets per attempt. `reasoning_tokens` is recorded as a
subset of output and is not added to `total_tokens` a second time. Closeout also
writes an aggregate across every attempted session. If Hermes does not report
pricing, both cost fields remain `null`; unknown pricing is never presented as
zero-dollar usage.

A private customer qualification may run a real model. If that run predates
token/cost capture, its retained execution evidence can still prove model,
session, attempt count, tool calls, timings, patch, tests, and cleanup, but it
cannot prove exact billable token cost.

Exact billable tokens and exact provider cost were **not retained** for this
kind of historical run unless the run artifact includes provider usage:

- `input_tokens`
- `output_tokens`
- `cached_input_tokens` or `cache_read_tokens`
- `cache_write_tokens`
- `actual_cost_usd` or provider invoice ID

Therefore exact historical cost cannot be reconstructed from local run timing or
chat transcript text alone. Any dollar number for such a run is an estimate
unless it is backed by provider usage counters or billing export.

## What to capture in the next metered run

Every real-model qualification run should retain a cost packet:

```json
{
  "schema_version": 1,
  "session_id": "example-session-id",
  "api_call_count": 2,
  "input_tokens": 100,
  "cache_read_tokens": 300,
  "cache_write_tokens": 7,
  "output_tokens": 20,
  "reasoning_tokens": 5,
  "total_tokens": 427,
  "reasoning_tokens_are_subset_of_output": true,
  "estimated_cost_usd": null,
  "actual_cost_usd": null,
  "routes": [
    {
      "session_id": "example-session-id",
      "model": "model-id",
      "billing_provider": "provider-id",
      "billing_mode": "provider",
      "task": "candidate",
      "api_call_count": 2,
      "input_tokens": 100,
      "cache_read_tokens": 300,
      "cache_write_tokens": 7,
      "output_tokens": 20,
      "reasoning_tokens": 5,
      "total_tokens": 427,
      "estimated_cost_usd": null,
      "actual_cost_usd": null,
      "cost_status": "unknown",
      "cost_source": "none"
    }
  ]
}
```

Acceptance rule for cost reporting:

- If provider usage fields are present, report the exact provider-reported token
  buckets. Report cost only when the provider supplied a usable price source or
  an invoice-backed actual value.
- If only provider invoice or Azure/OpenAI billing export is present, report the
  invoice-backed actual cost and mark token split as unavailable.
- If neither usage nor invoice data exists, do not quote an exact historical
  cost. Run a metered qualification first.

## Customer-facing answer shape

Use this wording until a metered qualification run is available:

```text
We have exact execution evidence for the current local POC, but the retained
Hermes artifact did not capture provider token counters. I do not want to give
you a guessed daily cost.

For the next qualification run, we will retain input/output/cache token counts
and compute exact per-run model cost against the selected provider rate card.
Then the daily cost is:

  incidents per day × measured cost per incident + worker/connector overhead

For model comparison, the current direct API rates are:
gpt-5.6-sol $4/M input and $20/M output,
gpt-5.6-terra $2/M input and $12/M output,
gpt-5.6-luna $0.20/M input and $1.20/M output.

The practical next step is to run one metered incident through the model/provider
you approve and share the exact token/cost report from that run.
```
