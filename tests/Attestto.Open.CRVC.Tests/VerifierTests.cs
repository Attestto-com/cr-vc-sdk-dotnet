using Attestto.Open.CRVC;

namespace Attestto.Open.CRVC.Tests;

public class VerifierTests
{
    private readonly KeyPair _keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
    private readonly VCIssuer _testIssuer;

    public VerifierTests()
    {
        _testIssuer = new VCIssuer(new IssuerConfig
        {
            Did = "did:web:cosevi.attestto.id",
            PrivateKey = _keys.PrivateKey,
        });
    }

    [Fact]
    public async Task Verifies_Valid_Credential_With_Known_PublicKey()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            ExpirationDate = "2032-04-01T23:59:59Z",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-2026-045678",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
                ["points"] = 12,
            },
        });

        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, _keys.PublicKey, SigningAlgorithm.Ed25519, new VerifyOptions
        {
            ExpectedType = CredentialType.DrivingLicense,
            ExpectedIssuer = "did:web:cosevi.attestto.id",
        });

        Assert.True(result.Valid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task Detects_Tampered_Credential()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-2026-045678",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        // Tamper: change a claim value
        if (vc.CredentialSubject["license"] is Dictionary<string, object> license)
            license["status"] = "suspended";
        else
            vc.CredentialSubject["license"] = new Dictionary<string, object> { ["status"] = "suspended" };

        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, _keys.PublicKey, SigningAlgorithm.Ed25519);

        Assert.False(result.Valid);
        Assert.Contains("Invalid signature", result.Errors);
    }

    [Fact]
    public async Task Detects_Wrong_Issuer()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, _keys.PublicKey, SigningAlgorithm.Ed25519, new VerifyOptions
        {
            ExpectedIssuer = "did:web:fake-issuer.example.com",
        });

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("Expected issuer"));
    }

    [Fact]
    public async Task Detects_Wrong_CredentialType()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, _keys.PublicKey, SigningAlgorithm.Ed25519, new VerifyOptions
        {
            ExpectedType = CredentialType.MedicalFitnessCredential,
        });

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("Expected credential type"));
    }

    [Fact]
    public async Task Detects_Expired_Credential()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            ExpirationDate = "2020-01-01T00:00:00Z",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, _keys.PublicKey, SigningAlgorithm.Ed25519);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("expired"));
    }

    [Fact]
    public async Task Warns_When_No_Resolver_Configured()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        var verifier = new VCVerifier();
        var result = await verifier.VerifyAsync(vc);

        Assert.Contains(result.Warnings, w => w.Contains("not verified"));
    }

    [Fact]
    public async Task Verifies_With_PublicKey_Resolver()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.TheoreticalTestResult,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["status"] = "approved",
                ["score"] = 88,
                ["passingScore"] = 70,
                ["category"] = "B",
                ["modality"] = "online",
                ["testCenterDID"] = "did:web:academia.attestto.id",
                ["examVersionHash"] = "sha256:abc",
            },
        });

        PublicKeyResolver resolver = (did, _) =>
        {
            if (did == "did:web:cosevi.attestto.id")
                return Task.FromResult<ResolvedKey?>(new ResolvedKey(_keys.PublicKey, SigningAlgorithm.Ed25519));
            return Task.FromResult<ResolvedKey?>(null);
        };

        var verifier = new VCVerifier(resolver);
        var result = await verifier.VerifyAsync(vc, new VerifyOptions
        {
            ExpectedType = CredentialType.TheoreticalTestResult,
        });

        Assert.True(result.Valid);
    }

    [Fact]
    public async Task Fails_When_PublicKey_Cannot_Be_Resolved()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        PublicKeyResolver resolver = (_, _) => Task.FromResult<ResolvedKey?>(null);
        var verifier = new VCVerifier(resolver);
        var result = await verifier.VerifyAsync(vc);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("Could not resolve"));
    }

    [Fact]
    public async Task Detects_Wrong_SigningKey()
    {
        var vc = await _testIssuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        var wrongKeys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        var verifier = new VCVerifier();
        var result = await verifier.VerifyWithKeyAsync(vc, wrongKeys.PublicKey, SigningAlgorithm.Ed25519);

        Assert.False(result.Valid);
        Assert.Contains("Invalid signature", result.Errors);
    }

    [Fact]
    public async Task Validates_Malformed_Credential()
    {
        var malformed = new VerifiableCredential
        {
            Context = [],
            Type = ["NotAVC"],
            Issuer = "not-a-did",
            CredentialSubject = new Dictionary<string, object>(),
        };

        var verifier = new VCVerifier();
        var result = await verifier.VerifyAsync(malformed);

        Assert.False(result.Valid);
        Assert.True(result.Errors.Count >= 3);
    }
}
