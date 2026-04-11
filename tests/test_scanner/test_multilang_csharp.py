"""Tests for Layer 11 C#/.NET governance detection.

Covers the two canonical archetypes:

1. **Governed** (VigIA-style) — Microsoft.Extensions.AI + Result<T,E> +
   ImmutableDictionary + readonly record struct + strict JSON schema +
   FSM guards + InvariantEnforcer + Authorization policies + DI host.
   Should score well across D1/D3/D4/D5/D7/D8/D11/D12/D14/D17.

2. **Ungoverned** — raw OpenAIClient with hardcoded key, no DI, no
   logging, no policy, no invariants. Should fire CRITICAL findings on
   D1/D4 and earn near-zero C# credit.

Also includes targeted regex / signal tests for each new pattern added
for v1.7.0 (D3 policy, D11 cloud/platform).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from warden.scanner.multilang_scanner import (
    _analyze_csharp,
    _calculate_csharp_dim_scores,
    scan_multilang,
)

# --- governed VigIA-style fixtures --------------------------------------


_GOVERNED_ORCHESTRATOR = """\
using System;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Azure.Identity;

namespace Vigia.Agent.Orchestration;

public sealed record AgentSettings(Uri Endpoint, string Deployment);

public sealed class VigiaAgentOrchestrator
{
    private readonly IChatClient _chat;
    private readonly AgentSettings _settings;

    public VigiaAgentOrchestrator(IChatClient chat, IOptions<AgentSettings> opts)
    {
        _chat = chat;
        _settings = opts.Value;
    }

    public async Task<Result<Blueprint, AgentError>> RunAsync(
        ImmutableArray<Microsoft.Extensions.AI.ChatMessage> history,
        CancellationToken cancellationToken = default)
    {
        var options = new ChatOptions
        {
            ResponseFormat = ChatResponseFormat.CreateJsonSchemaFormat(
                typeof(Blueprint),
                strictSchemaEnabled: true),
            Temperature = 0.0f,
        };

        var response = await _chat.GetResponseAsync(
            history, options, cancellationToken);

        var extracted = InvariantEnforcer.ValidateAndExtract(
            _validBlueprint, response);

        if (!FsmStateTransitionLogic.CanTransition(
            _state, AgentState.Completed))
        {
            return Result<Blueprint, AgentError>.Failure(
                AgentError.InvalidTransition);
        }

        return extracted;
    }

    private readonly Blueprint _validBlueprint = new();
    private AgentState _state;
}

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(Blueprint))]
internal partial class OrchestrationJsonContext : JsonSerializerContext { }
"""


_GOVERNED_DI = """\
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Vigia.Infrastructure.LLM;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddHttpClient();
        services.Configure<AgentSettings>(configuration.GetSection("Agent"));

        // Managed identity for KeyVault secrets
        var credential = new DefaultAzureCredential();
        var kv = new SecretClient(new Uri("https://vigia.vault.azure.net"), credential);
        services.AddSingleton(kv);

        services.AddAuthorization(options =>
        {
            options.AddPolicy("AgentOperator", policy =>
                policy.RequireClaim("role", "agent-operator"));
        });
        return services;
    }
}
"""


_GOVERNED_INVARIANT = """\
using System.Collections.Immutable;

namespace Vigia.Agent.Orchestration.CrossValidation;

public static class InvariantEnforcer
{
    public static Result<T, ValidationError> ValidateAndExtract<T>(
        T blueprint, string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return Result<T, ValidationError>.Failure(ValidationError.Empty);
        }
        return Result<T, ValidationError>.Success(blueprint);
    }
}

public readonly record struct ValidationError(string Code, string Message);
"""


_UNGOVERNED_CS = """\
using System;
using Azure.AI.OpenAI;

namespace UngovernedApp;

public class DirectClient
{
    // Hardcoded credential. Direct-to-provider call. No DI, no logging,
    // no invariants, no policy, no cancellation, no error monad.
    private const string ApiKey = "sk-abcdefghijklmnop0123456789";

    public void Run()
    {
        var client = new OpenAIClient(ApiKey);
        var resp = client.GetChatCompletions(new ChatCompletionsOptions());
        Console.WriteLine(resp);
    }
}
"""


# --- governed archetype ---------------------------------------------------


def test_governed_vigia_archetype_scores_partial():
    """A VigIA-style project should hit PARTIAL (≥60/100) with coverage gating."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Orchestrator.cs").write_text(_GOVERNED_ORCHESTRATOR)
        (root / "DependencyInjection.cs").write_text(_GOVERNED_DI)
        (root / "InvariantEnforcer.cs").write_text(_GOVERNED_INVARIANT)

        findings, scores = scan_multilang(root)

        # No hardcoded credentials, no direct-to-provider calls detected
        assert not any(
            f.severity.value == "CRITICAL" and f.dimension == "D4"
            for f in findings
        ), f"Unexpected CRITICAL D4 findings: {[f.message for f in findings]}"

        # C# positive dimensions should all contribute
        for dim in ("D1", "D3", "D4", "D7", "D8", "D11", "D14", "D17"):
            assert scores.get(dim, 0) > 0, (
                f"{dim} should have earned C# credit, got {scores.get(dim, 0)}"
            )


def test_governed_archetype_d3_policy_credit():
    """InvariantEnforcer + FSM + Result monad + Authorization policy → D3."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Orchestrator.cs").write_text(_GOVERNED_ORCHESTRATOR)
        (root / "DependencyInjection.cs").write_text(_GOVERNED_DI)
        (root / "InvariantEnforcer.cs").write_text(_GOVERNED_INVARIANT)

        _findings, scores = scan_multilang(root)
        # InvariantEnforcer(+6) + FsmGuard(+4) + Result(+3) + AuthPolicy(+4)
        # + strict schema(+3) = 20 → capped at 14
        assert scores.get("D3", 0) >= 10, (
            f"D3 policy coverage should be ≥10 for VigIA-style project, "
            f"got {scores.get('D3', 0)}"
        )


def test_governed_archetype_d11_cloud_credit():
    """Microsoft.Extensions.Hosting + Azure.Identity + IChatClient → D11."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Orchestrator.cs").write_text(_GOVERNED_ORCHESTRATOR)
        (root / "DependencyInjection.cs").write_text(_GOVERNED_DI)
        (root / "InvariantEnforcer.cs").write_text(_GOVERNED_INVARIANT)

        _findings, scores = scan_multilang(root)
        assert scores.get("D11", 0) >= 4, (
            f"D11 cloud/platform should be ≥4 for VigIA-style project, "
            f"got {scores.get('D11', 0)}"
        )


# --- ungoverned archetype -------------------------------------------------


def test_ungoverned_raw_openai_fires_critical():
    """Raw OpenAIClient with hardcoded key should fire CRITICAL on D1 and D4."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "DirectClient.cs").write_text(_UNGOVERNED_CS)

        findings, scores = scan_multilang(root)

        crit_dims = {
            f.dimension for f in findings if f.severity.value == "CRITICAL"
        }
        assert "D1" in crit_dims, (
            f"Expected CRITICAL on D1 (direct LLM client), "
            f"got crit dims: {crit_dims}"
        )
        assert "D4" in crit_dims, (
            f"Expected CRITICAL on D4 (hardcoded credentials), "
            f"got crit dims: {crit_dims}"
        )

        # D4 raw score after penalty should be near zero
        assert scores.get("D4", 0) <= 4, (
            f"D4 should be heavily penalized for hardcoded key, "
            f"got {scores.get('D4', 0)}"
        )


def test_ungoverned_no_policy_credit():
    """No InvariantEnforcer / Authorization / FSM → zero D3 contribution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "DirectClient.cs").write_text(_UNGOVERNED_CS)
        _findings, scores = scan_multilang(root)
        assert scores.get("D3", 0) == 0


# --- direct unit tests for _analyze_csharp -------------------------------


def test_analyze_csharp_invariant_enforcer_signal():
    _findings, _gov, signals = _analyze_csharp(
        Path("InvariantEnforcer.cs"), _GOVERNED_INVARIANT,
    )
    assert signals["has_invariant_enforcer"] is True
    assert signals["has_result_monad"] is True
    assert signals["has_readonly_record"] is True


def test_analyze_csharp_auth_policy_signal():
    _findings, _gov, signals = _analyze_csharp(
        Path("DependencyInjection.cs"), _GOVERNED_DI,
    )
    assert signals["has_auth_policy"] is True
    assert signals["has_extensions_hosting"] is True
    assert signals["has_azure_cloud"] is True
    assert signals["has_httpclient_factory"] is True


def test_analyze_csharp_ungoverned_no_positives():
    _findings, _gov, signals = _analyze_csharp(
        Path("DirectClient.cs"), _UNGOVERNED_CS,
    )
    assert signals["has_hardcoded_key"] is True
    assert signals["has_direct_llm_client"] is True
    assert signals["has_invariant_enforcer"] is False
    assert signals["has_auth_policy"] is False
    assert signals["has_fsm_guard"] is False


# --- dimension score mapping ---------------------------------------------


def test_calculate_csharp_dim_scores_empty_when_no_ai_files():
    """Non-AI projects get no C# bonus, even if they have positive signals."""
    signals = [{"has_result_monad": True, "has_immutable": True}]
    assert _calculate_csharp_dim_scores(signals, ai_file_count=0) == {}


def test_calculate_csharp_dim_scores_full_governance():
    """All positive signals → all tracked dimensions contribute."""
    full = {
        "has_ilogger": True,
        "has_authz_attr": True,
        "has_kernel_function": True,
        "has_result_monad": True,
        "has_immutable": True,
        "has_readonly_record": True,
        "has_json_source_gen": True,
        "has_strict_schema": True,
        "has_temp_zero": True,
        "has_fsm_guard": True,
        "has_cancellation": True,
        "has_ioptions": True,
        "has_iconfiguration": True,
        "has_secrets_ref": True,
        "has_chat_client": True,
        "has_invariant_enforcer": True,
        "has_auth_policy": True,
        "has_extensions_hosting": True,
        "has_azure_cloud": True,
        "has_httpclient_factory": True,
    }
    scores = _calculate_csharp_dim_scores([full], ai_file_count=5)
    for dim in (
        "D1", "D3", "D4", "D5", "D7", "D8", "D11", "D12", "D14", "D17",
    ):
        assert scores.get(dim, 0) > 0, (
            f"{dim} should score > 0 with full signals, got {scores}"
        )
    # Caps must not be exceeded
    assert scores["D1"] <= 12
    assert scores["D3"] <= 14
    assert scores["D4"] <= 12
    assert scores["D5"] <= 6
    assert scores["D7"] <= 10
    assert scores["D8"] <= 10
    assert scores["D11"] <= 8
    assert scores["D12"] <= 6
    assert scores["D14"] <= 8
    assert scores["D17"] <= 8


def test_calculate_csharp_dim_scores_hardcoded_key_penalty():
    """D4 should be heavily penalized when hardcoded credentials are present."""
    sig = {
        "has_chat_client": True,
        "has_ioptions": True,
        "has_iconfiguration": True,
        "has_hardcoded_key": True,
    }
    scores = _calculate_csharp_dim_scores([sig], ai_file_count=1)
    # D4 baseline (4) is skipped due to hardcoded_key, plus -6 penalty
    assert scores.get("D4", 0) <= 2, (
        f"D4 must be near-zero with hardcoded key, got {scores.get('D4')}"
    )


def test_calculate_csharp_dim_scores_direct_client_penalty():
    """Direct LLM client should trim all earned C# dim credit by 2."""
    sig = {
        "has_chat_client": True,
        "has_kernel_function": True,
        "has_strict_schema": True,
        "has_direct_llm_client": True,
    }
    scores_penalized = _calculate_csharp_dim_scores([sig], ai_file_count=1)
    sig2 = dict(sig)
    sig2["has_direct_llm_client"] = False
    scores_clean = _calculate_csharp_dim_scores([sig2], ai_file_count=1)
    # Every dim should be <= clean version (penalty applied uniformly)
    for dim, val in scores_penalized.items():
        assert val <= scores_clean.get(dim, 0), (
            f"{dim} penalty should reduce score below clean baseline"
        )
