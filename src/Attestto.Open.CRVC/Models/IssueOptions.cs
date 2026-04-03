namespace Attestto.Open.CRVC;

/// <summary>Options for issuing a credential.</summary>
public sealed class IssueOptions
{
    /// <summary>Credential type.</summary>
    public required string Type { get; init; }

    /// <summary>DID of the subject (holder).</summary>
    public required string SubjectDid { get; init; }

    /// <summary>Credential subject data (matches the schema for the type).</summary>
    public Dictionary<string, object> Claims { get; init; } = new();

    /// <summary>Optional expiration date (ISO 8601).</summary>
    public string? ExpirationDate { get; init; }

    /// <summary>Optional credential status for revocation.</summary>
    public CredentialStatus? CredentialStatus { get; init; }

    /// <summary>Optional credential ID (auto-generated if not provided).</summary>
    public string? Id { get; init; }
}
