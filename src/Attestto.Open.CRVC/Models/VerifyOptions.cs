namespace Attestto.Open.CRVC;

/// <summary>Options for verifying a credential.</summary>
public sealed class VerifyOptions
{
    /// <summary>Check expiration date. Default: true.</summary>
    public bool CheckExpiration { get; init; } = true;

    /// <summary>Check credential status (revocation). Default: false.</summary>
    public bool CheckStatus { get; init; }

    /// <summary>Expected credential type.</summary>
    public string? ExpectedType { get; init; }

    /// <summary>Expected issuer DID.</summary>
    public string? ExpectedIssuer { get; init; }
}
