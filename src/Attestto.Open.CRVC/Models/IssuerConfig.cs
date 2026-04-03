namespace Attestto.Open.CRVC;

/// <summary>Issuer configuration.</summary>
public sealed class IssuerConfig
{
    /// <summary>DID of the issuer (e.g. did:web:cosevi.attestto.id).</summary>
    public required string Did { get; init; }

    /// <summary>Private key for signing (Ed25519 or P-256).</summary>
    public required byte[] PrivateKey { get; init; }

    /// <summary>Key algorithm. Default: Ed25519.</summary>
    public SigningAlgorithm Algorithm { get; init; } = SigningAlgorithm.Ed25519;

    /// <summary>Key ID fragment (e.g. #key-1).</summary>
    public string KeyId { get; init; } = "#key-1";
}
