# Attestto.Open.CRVC

.NET SDK for issuing and verifying Verifiable Credentials in the Costa Rica SSI driving ecosystem.

## Install

```bash
dotnet add package Attestto.Open.CRVC
```

## Quick Start

### Issue a credential (consultorio example)

```csharp
using Attestto.Open.CRVC;

var keys = CryptoKeys.GenerateKeyPair();
var issuer = new VCIssuer(new IssuerConfig
{
    Did = "did:web:clinica-salud.attestto.id",
    PrivateKey = keys.PrivateKey,
});

var vc = await issuer.IssueAsync(new IssueOptions
{
    Type = CredentialType.MedicalFitnessCredential,
    SubjectDid = "did:web:conductor.attestto.id",
    Claims = new Dictionary<string, object>
    {
        ["status"] = "fit",
        ["categories"] = new[] { "B", "C" },
        ["expiresAt"] = DateTime.UtcNow.AddMonths(12).ToString("o"),
    },
});
```

### Verify a credential

```csharp
var verifier = new VCVerifier();
var result = await verifier.VerifyWithKeyAsync(vc, keys.PublicKey, SigningAlgorithm.Ed25519, new VerifyOptions
{
    ExpectedType = CredentialType.MedicalFitnessCredential,
    CheckExpiration = true,
});

if (result.Valid)
    Console.WriteLine("Credential is valid");
else
    Console.WriteLine($"Errors: {string.Join(", ", result.Errors)}");
```

### Verify with a DID resolver

```csharp
PublicKeyResolver resolver = async (did, keyId) =>
{
    // Resolve public key from your DID registry
    var key = await MyDidRegistry.ResolveKey(did, keyId);
    return key is not null ? new ResolvedKey(key.Bytes, SigningAlgorithm.Ed25519) : null;
};

var verifier = new VCVerifier(resolver);
var result = await verifier.VerifyAsync(vc, new VerifyOptions
{
    ExpectedType = CredentialType.DrivingLicense,
    ExpectedIssuer = "did:web:cosevi.attestto.id",
});
```

## Supported Credential Types

| Type | Subject Property | Use Case |
|------|-----------------|----------|
| `DrivingLicense` | `license` | COSEVI driving license |
| `TheoreticalTestResult` | `theoreticalTest` | Written exam result |
| `PracticalTestResult` | `practicalTest` | Driving test result |
| `MedicalFitnessCredential` | `fitness` | Medical fitness certificate |
| `VehicleRegistration` | `vehicle` | Vehicle registration |
| `VehicleTechnicalReview` | `technicalReview` | RTV inspection |
| `CirculationRights` | `circulationRights` | Derechos de circulacion |
| `SOATCredential` | `insurance` | Mandatory insurance (INS) |
| `DriverIdentity` | `driverIdentity` | TSE/IDC identity wrapper |
| `TrafficViolation` | `violation` | Traffic violation record |
| `AccidentReport` | `accident` | Accident report |

## Algorithms

- **Ed25519** (default) — EdDSA signing, 32-byte keys
- **ES256** (P-256) — ECDSA signing, NIST P-256 curve

## Schemas

JSON-LD schemas: [Attestto-com/cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas)

## Ecosystem

Full index: [Attestto-com/attestto-open](https://github.com/Attestto-com/attestto-open)

## License

Apache 2.0
