using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Attestto.Open.CRVC
{
    /// <summary>Shared constants and utilities for VC operations.</summary>
    internal static class VCConstants
    {
        internal const string W3CVcContext = "https://www.w3.org/2018/credentials/v1";
        internal const string CrDrivingContext = "https://schemas.attestto.org/cr/driving/v1";

        internal static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
        };

        /// <summary>
        /// Serialize a credential without its proof for signing/verification.
        /// Both issuer and verifier need this exact same operation.
        /// </summary>
        internal static byte[] SerializeForSigning(VerifiableCredential credential)
        {
            var unsigned = new VerifiableCredential
            {
                Context = credential.Context,
                Id = credential.Id,
                Type = credential.Type,
                Issuer = credential.Issuer,
                IssuanceDate = credential.IssuanceDate,
                ExpirationDate = credential.ExpirationDate,
                CredentialSubject = credential.CredentialSubject,
                CredentialStatus = credential.CredentialStatus,
                Proof = null,
            };

            var json = JsonSerializer.Serialize(unsigned, SerializerOptions);
            return Encoding.UTF8.GetBytes(json);
        }
    }
}
