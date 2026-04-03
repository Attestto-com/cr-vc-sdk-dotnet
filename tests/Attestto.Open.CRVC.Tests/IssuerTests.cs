using Attestto.Open.CRVC;

namespace Attestto.Open.CRVC.Tests;

public class IssuerTests
{
    private readonly KeyPair _keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
    private readonly VCIssuer _issuer;

    public IssuerTests()
    {
        _issuer = new VCIssuer(new IssuerConfig
        {
            Did = "did:web:cosevi.attestto.id",
            PrivateKey = _keys.PrivateKey,
        });
    }

    [Fact]
    public async Task Issues_DrivingLicense_Credential()
    {
        var vc = await _issuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-2026-045678",
                ["categories"] = new[] { "B", "A1" },
                ["issueDate"] = "2026-04-01",
                ["expiresAt"] = "2032-04-01",
                ["status"] = "active",
                ["points"] = 12,
                ["issuingAuthority"] = "did:web:cosevi.attestto.id",
            },
        });

        Assert.Contains("VerifiableCredential", vc.Type);
        Assert.Contains("DrivingLicense", vc.Type);
        Assert.Equal("did:web:cosevi.attestto.id", vc.Issuer);
        Assert.Equal("did:web:maria.attestto.id", vc.CredentialSubject["id"].ToString());
        Assert.True(vc.CredentialSubject.ContainsKey("license"));
        Assert.NotNull(vc.Proof);
        Assert.Equal("Ed25519Signature2020", vc.Proof!.Type);
        Assert.Equal("did:web:cosevi.attestto.id#key-1", vc.Proof.VerificationMethod);
        Assert.Contains("https://schemas.attestto.org/cr/driving/v1", vc.Context);
    }

    [Fact]
    public async Task Issues_TheoreticalTestResult_Credential()
    {
        var dgev = new VCIssuer(new IssuerConfig
        {
            Did = "did:web:dgev.attestto.id",
            PrivateKey = CryptoKeys.GenerateKeyPair().PrivateKey,
        });

        var vc = await dgev.IssueAsync(new IssueOptions
        {
            Type = CredentialType.TheoreticalTestResult,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["status"] = "approved",
                ["score"] = 88,
                ["passingScore"] = 70,
                ["category"] = "B",
                ["testDate"] = "2026-03-15T14:00:00Z",
                ["modality"] = "online",
                ["testCenterDID"] = "did:web:academia-tica.attestto.id",
                ["examVersionHash"] = "sha256:abc123",
            },
        });

        Assert.Contains("TheoreticalTestResult", vc.Type);
        Assert.True(vc.CredentialSubject.ContainsKey("theoreticalTest"));
    }

    [Fact]
    public async Task Issues_PracticalTestResult_Credential()
    {
        var vc = await _issuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.PracticalTestResult,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["status"] = "approved",
                ["category"] = "B",
                ["testDate"] = "2026-03-20T14:00:00Z",
                ["evaluatorDID"] = "did:web:evaluador.attestto.id",
                ["testCenterDID"] = "did:web:sede-dgev.attestto.id",
                ["vehiclePlate"] = "SJO-012",
            },
        });

        Assert.Contains("PracticalTestResult", vc.Type);
        Assert.True(vc.CredentialSubject.ContainsKey("practicalTest"));
    }

    [Fact]
    public async Task Issues_MedicalFitnessCredential()
    {
        var clinic = new VCIssuer(new IssuerConfig
        {
            Did = "did:web:clinica-salud.attestto.id",
            PrivateKey = CryptoKeys.GenerateKeyPair().PrivateKey,
        });

        var vc = await clinic.IssueAsync(new IssueOptions
        {
            Type = CredentialType.MedicalFitnessCredential,
            SubjectDid = "did:web:maria.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["status"] = "fit",
                ["categories"] = new[] { "B", "A1" },
                ["issuedDate"] = "2026-03-05",
                ["expiresAt"] = "2027-03-05T23:59:59Z",
                ["physicianDID"] = "did:web:dra-vargas.attestto.id",
                ["clinicDID"] = "did:web:clinica-salud.attestto.id",
            },
        });

        Assert.Contains("MedicalFitnessCredential", vc.Type);
        Assert.True(vc.CredentialSubject.ContainsKey("fitness"));
    }

    [Fact]
    public async Task Generates_Unique_CredentialIds()
    {
        var opts = new IssueOptions
        {
            Type = CredentialType.DriverIdentity,
            SubjectDid = "did:web:test.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["nationalIdType"] = "cedula",
                ["nationalIdRef"] = "****-5678",
            },
        };

        var vc1 = await _issuer.IssueAsync(opts);
        var vc2 = await _issuer.IssueAsync(opts);

        Assert.NotEqual(vc1.Id, vc2.Id);
        Assert.StartsWith("urn:uuid:", vc1.Id);
    }

    [Fact]
    public async Task Includes_ExpirationDate_When_Provided()
    {
        var vc = await _issuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:test.attestto.id",
            ExpirationDate = "2032-04-01T23:59:59Z",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
        });

        Assert.Equal("2032-04-01T23:59:59Z", vc.ExpirationDate);
    }

    [Fact]
    public async Task Includes_CredentialStatus_When_Provided()
    {
        var vc = await _issuer.IssueAsync(new IssueOptions
        {
            Type = CredentialType.DrivingLicense,
            SubjectDid = "did:web:test.attestto.id",
            Claims = new Dictionary<string, object>
            {
                ["licenseNumber"] = "CR-TEST",
                ["categories"] = new[] { "B" },
                ["status"] = "active",
            },
            CredentialStatus = new CredentialStatus
            {
                Id = "https://status.attestto.org/cr/credentials/status/1#4567",
                Type = "StatusList2021Entry",
                StatusPurpose = "revocation",
                StatusListIndex = "4567",
                StatusListCredential = "https://status.attestto.org/cr/credentials/status-list/1",
            },
        });

        Assert.NotNull(vc.CredentialStatus);
        Assert.Equal("StatusList2021Entry", vc.CredentialStatus!.Type);
    }

    [Fact]
    public async Task Throws_On_Unknown_CredentialType()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _issuer.IssueAsync(new IssueOptions
            {
                Type = "UnknownType",
                SubjectDid = "did:web:test.attestto.id",
            })
        );
    }

    [Fact]
    public async Task Issues_All_11_CredentialTypes()
    {
        foreach (var type in CredentialType.All)
        {
            var vc = await _issuer.IssueAsync(new IssueOptions
            {
                Type = type,
                SubjectDid = "did:web:test.attestto.id",
                Claims = new Dictionary<string, object> { ["testField"] = "value" },
            });
            Assert.Contains(type, vc.Type);
        }
    }

    [Fact]
    public void Throws_On_Empty_Did()
    {
        Assert.Throws<ArgumentException>(() => new VCIssuer(new IssuerConfig
        {
            Did = "",
            PrivateKey = CryptoKeys.GenerateKeyPair().PrivateKey,
        }));
    }

    [Fact]
    public void Throws_On_Empty_PrivateKey()
    {
        Assert.Throws<ArgumentException>(() => new VCIssuer(new IssuerConfig
        {
            Did = "did:web:test.attestto.id",
            PrivateKey = [],
        }));
    }
}
