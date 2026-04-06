using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Attestto.Open.CRVC
{
    /// <summary>W3C Verifiable Credential envelope.</summary>
    public class VerifiableCredential
    {
        [JsonPropertyName("@context")]
        public List<string> Context { get; set; } = new List<string>();

        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public List<string> Type { get; set; } = new List<string>();

        [JsonPropertyName("issuer")]
        public string Issuer { get; set; } = string.Empty;

        [JsonPropertyName("issuanceDate")]
        public string IssuanceDate { get; set; } = string.Empty;

        [JsonPropertyName("expirationDate")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ExpirationDate { get; set; }

        [JsonPropertyName("credentialSubject")]
        public Dictionary<string, object> CredentialSubject { get; set; } = new Dictionary<string, object>();

        [JsonPropertyName("credentialStatus")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public CredentialStatus CredentialStatus { get; set; }

        [JsonPropertyName("proof")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Proof Proof { get; set; }
    }

    /// <summary>W3C StatusList2021 entry.</summary>
    public class CredentialStatus
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = "StatusList2021Entry";

        [JsonPropertyName("statusPurpose")]
        public string StatusPurpose { get; set; } = "revocation";

        [JsonPropertyName("statusListIndex")]
        public string StatusListIndex { get; set; } = string.Empty;

        [JsonPropertyName("statusListCredential")]
        public string StatusListCredential { get; set; } = string.Empty;
    }

    /// <summary>Linked Data Proof.</summary>
    public class Proof
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("created")]
        public string Created { get; set; } = string.Empty;

        [JsonPropertyName("verificationMethod")]
        public string VerificationMethod { get; set; } = string.Empty;

        [JsonPropertyName("proofPurpose")]
        public string ProofPurpose { get; set; } = "assertionMethod";

        [JsonPropertyName("proofValue")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ProofValue { get; set; }

        [JsonPropertyName("jws")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Jws { get; set; }
    }
}
