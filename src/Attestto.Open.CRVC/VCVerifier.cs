namespace Attestto.Open.CRVC;

/// <summary>
/// Resolves a public key from a DID and key ID.
/// Returns null if the key cannot be resolved.
/// </summary>
public delegate Task<ResolvedKey?> PublicKeyResolver(string did, string keyId);

/// <summary>Resolved public key with its algorithm.</summary>
public record ResolvedKey(byte[] PublicKey, SigningAlgorithm Algorithm);

/// <summary>
/// Verify Verifiable Credentials.
/// </summary>
public sealed class VCVerifier
{
    private readonly PublicKeyResolver? _resolvePublicKey;
    private readonly ISigner _signer;

    public VCVerifier(PublicKeyResolver? resolvePublicKey = null)
        : this(resolvePublicKey, new DefaultSigner()) { }

    public VCVerifier(PublicKeyResolver? resolvePublicKey, ISigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        _resolvePublicKey = resolvePublicKey;
        _signer = signer;
    }

    /// <summary>Verify a Verifiable Credential.</summary>
    public async Task<VerificationResult> VerifyAsync(
        VerifiableCredential credential,
        VerifyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        options ??= new VerifyOptions();

        var checks = new List<VerificationCheck>();
        var errors = new List<string>();
        var warnings = new List<string>();

        CheckStructure(credential, checks, errors);
        CheckContext(credential, checks, errors);

        if (options.ExpectedType is not null)
            CheckExpectedType(credential, options.ExpectedType, checks, errors);

        if (options.ExpectedIssuer is not null)
            CheckExpectedIssuer(credential, options.ExpectedIssuer, checks, errors);

        if (options.CheckExpiration)
            CheckExpiration(credential, checks, errors, warnings);

        CheckIssuanceDate(credential, checks, errors);
        await CheckProofIfPresent(credential, checks, errors, warnings);

        if (options.CheckStatus && credential.CredentialStatus is not null)
            warnings.Add("Status check requested but StatusList2021 verification not yet implemented");

        return new VerificationResult
        {
            Valid = errors.Count == 0,
            Checks = checks,
            Errors = errors,
            Warnings = warnings,
        };
    }

    /// <summary>Verify a credential with a known public key (no resolver needed).</summary>
    public Task<VerificationResult> VerifyWithKeyAsync(
        VerifiableCredential credential,
        byte[] publicKey,
        SigningAlgorithm algorithm = SigningAlgorithm.Ed25519,
        VerifyOptions? options = null)
    {
        PublicKeyResolver resolver = (_, _) =>
            Task.FromResult<ResolvedKey?>(new ResolvedKey(publicKey, algorithm));

        var verifier = new VCVerifier(resolver, _signer);
        return verifier.VerifyAsync(credential, options);
    }

    private async Task CheckProofIfPresent(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors,
        List<string> warnings)
    {
        if (credential.Proof is not null && _resolvePublicKey is not null)
            await VerifyProofSignature(credential, checks, errors);
        else if (credential.Proof is not null)
            warnings.Add("Proof present but no public key resolver configured — signature not verified");
        else
            warnings.Add("No proof present — credential is unsigned");
    }

    private async Task VerifyProofSignature(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors)
    {
        var (did, keyId) = ParseVerificationMethod(credential.Proof!.VerificationMethod);

        var resolved = await _resolvePublicKey!(did, keyId);
        if (resolved is null)
        {
            checks.Add(new VerificationCheck { Check = "proof.keyResolution", Passed = false, Message = $"Could not resolve key for {did}" });
            errors.Add($"Could not resolve public key for {credential.Proof.VerificationMethod}");
            return;
        }

        checks.Add(new VerificationCheck { Check = "proof.keyResolution", Passed = true });

        var message = VCConstants.SerializeForSigning(credential);
        var signature = CryptoKeys.FromBase64Url(credential.Proof.ProofValue ?? "");
        var isValid = _signer.Verify(message, signature, resolved.PublicKey, resolved.Algorithm);

        checks.Add(new VerificationCheck { Check = "proof.signature", Passed = isValid });
        if (!isValid) errors.Add("Invalid signature");
    }

    private static (string did, string keyId) ParseVerificationMethod(string verificationMethod)
    {
        var hashIndex = verificationMethod.LastIndexOf('#');
        var did = hashIndex > 0 ? verificationMethod[..hashIndex] : verificationMethod;
        var keyId = hashIndex > 0 ? verificationMethod[hashIndex..] : "#key-1";
        return (did, keyId);
    }

    private static void CheckStructure(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors)
    {
        AddCheck(checks, errors, "structure.context",
            credential.Context.Count > 0, "Missing or invalid @context");

        AddCheck(checks, errors, "structure.type",
            credential.Type.Contains("VerifiableCredential"), "Missing VerifiableCredential in type array");

        AddCheck(checks, errors, "structure.issuer",
            !string.IsNullOrEmpty(credential.Issuer) && credential.Issuer.StartsWith("did:"),
            "Missing or invalid issuer DID");

        AddCheck(checks, errors, "structure.subject",
            credential.CredentialSubject.ContainsKey("id"), "Missing credentialSubject.id");

        AddCheck(checks, errors, "structure.issuanceDate",
            !string.IsNullOrEmpty(credential.IssuanceDate), "Missing issuanceDate");
    }

    private static void CheckContext(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors)
    {
        AddCheck(checks, errors, "context.w3c",
            credential.Context.Contains(VCConstants.W3CVcContext),
            $"Missing W3C VC context: {VCConstants.W3CVcContext}");

        AddCheck(checks, errors, "context.cr-driving",
            credential.Context.Contains(VCConstants.CrDrivingContext),
            $"Missing CR driving context: {VCConstants.CrDrivingContext}");
    }

    private static void CheckExpectedType(
        VerifiableCredential credential, string expectedType,
        List<VerificationCheck> checks, List<string> errors)
    {
        var passed = credential.Type.Contains(expectedType);
        checks.Add(new VerificationCheck { Check = "type.expected", Passed = passed, Message = expectedType });
        if (!passed) errors.Add($"Expected credential type \"{expectedType}\" not found");
    }

    private static void CheckExpectedIssuer(
        VerifiableCredential credential, string expectedIssuer,
        List<VerificationCheck> checks, List<string> errors)
    {
        var passed = credential.Issuer == expectedIssuer;
        checks.Add(new VerificationCheck { Check = "issuer.expected", Passed = passed, Message = expectedIssuer });
        if (!passed) errors.Add($"Expected issuer \"{expectedIssuer}\", got \"{credential.Issuer}\"");
    }

    private static void CheckExpiration(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors,
        List<string> warnings)
    {
        if (credential.ExpirationDate is null)
        {
            checks.Add(new VerificationCheck { Check = "expiration", Passed = true, Message = "No expiration date set" });
            return;
        }

        var expiry = DateTime.Parse(credential.ExpirationDate, null, System.Globalization.DateTimeStyles.RoundtripKind);
        var now = DateTime.UtcNow;
        var isValid = expiry > now;

        checks.Add(new VerificationCheck { Check = "expiration", Passed = isValid, Message = credential.ExpirationDate });
        if (!isValid) errors.Add($"Credential expired on {credential.ExpirationDate}");

        if (isValid && (expiry - now).TotalDays < 30)
            warnings.Add($"Credential expires soon: {credential.ExpirationDate}");
    }

    private static void CheckIssuanceDate(
        VerifiableCredential credential,
        List<VerificationCheck> checks,
        List<string> errors)
    {
        if (string.IsNullOrEmpty(credential.IssuanceDate)) return;

        var issued = DateTime.Parse(credential.IssuanceDate, null, System.Globalization.DateTimeStyles.RoundtripKind);
        var isValid = issued <= DateTime.UtcNow + TimeSpan.FromMinutes(5);

        checks.Add(new VerificationCheck { Check = "issuanceDate.notFuture", Passed = isValid });
        if (!isValid) errors.Add($"Credential issuance date is in the future: {credential.IssuanceDate}");
    }

    private static void AddCheck(
        List<VerificationCheck> checks, List<string> errors,
        string checkName, bool passed, string errorMessage)
    {
        checks.Add(new VerificationCheck { Check = checkName, Passed = passed });
        if (!passed) errors.Add(errorMessage);
    }
}
