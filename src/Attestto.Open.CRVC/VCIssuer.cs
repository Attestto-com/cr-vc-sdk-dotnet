namespace Attestto.Open.CRVC;

/// <summary>
/// Create and sign Verifiable Credentials.
/// </summary>
public sealed class VCIssuer
{
    private readonly IssuerConfig _config;
    private readonly ISigner _signer;

    public VCIssuer(IssuerConfig config) : this(config, new DefaultSigner()) { }

    public VCIssuer(IssuerConfig config, ISigner signer)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentException.ThrowIfNullOrWhiteSpace(config.Did);

        if (config.PrivateKey is null || config.PrivateKey.Length == 0)
            throw new ArgumentException("PrivateKey must not be empty.", nameof(config));

        _config = config;
        _signer = signer;
    }

    /// <summary>Get the issuer DID.</summary>
    public string Did => _config.Did;

    /// <summary>Issue a signed Verifiable Credential.</summary>
    public Task<VerifiableCredential> IssueAsync(IssueOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!CredentialType.PropertyMap.TryGetValue(options.Type, out var propertyName))
            throw new ArgumentException($"Unknown credential type: {options.Type}");

        var credentialSubject = BuildCredentialSubject(options, propertyName);

        var credential = new VerifiableCredential
        {
            Context = [VCConstants.W3CVcContext, VCConstants.CrDrivingContext],
            Id = options.Id ?? $"urn:uuid:{Guid.NewGuid()}",
            Type = ["VerifiableCredential", options.Type],
            Issuer = _config.Did,
            IssuanceDate = DateTime.UtcNow.ToString("o"),
            CredentialSubject = credentialSubject,
            ExpirationDate = options.ExpirationDate,
            CredentialStatus = options.CredentialStatus,
        };

        credential.Proof = CreateProof(credential);
        return Task.FromResult(credential);
    }

    private static Dictionary<string, object> BuildCredentialSubject(IssueOptions options, string propertyName)
    {
        var subject = new Dictionary<string, object> { ["id"] = options.SubjectDid };

        if (options.Claims.ContainsKey(propertyName))
        {
            foreach (var kvp in options.Claims)
                subject[kvp.Key] = kvp.Value;
        }
        else
        {
            subject[propertyName] = options.Claims;
        }

        return subject;
    }

    private Proof CreateProof(VerifiableCredential credential)
    {
        var message = VCConstants.SerializeForSigning(credential);
        var signature = _signer.Sign(message, _config.PrivateKey, _config.Algorithm);

        return new Proof
        {
            Type = _config.Algorithm == SigningAlgorithm.Ed25519
                ? "Ed25519Signature2020"
                : "EcdsaSecp256r1Signature2019",
            Created = DateTime.UtcNow.ToString("o"),
            VerificationMethod = $"{_config.Did}{_config.KeyId}",
            ProofPurpose = "assertionMethod",
            ProofValue = CryptoKeys.ToBase64Url(signature),
        };
    }
}
