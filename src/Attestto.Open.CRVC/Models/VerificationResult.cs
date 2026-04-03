namespace Attestto.Open.CRVC;

/// <summary>Verification result.</summary>
public sealed class VerificationResult
{
    public required bool Valid { get; init; }
    public required IReadOnlyList<VerificationCheck> Checks { get; init; }
    public required IReadOnlyList<string> Errors { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
}

/// <summary>Individual verification check.</summary>
public sealed class VerificationCheck
{
    public required string Check { get; init; }
    public required bool Passed { get; init; }
    public string? Message { get; init; }
}
