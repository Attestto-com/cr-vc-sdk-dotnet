namespace Attestto.Open.CRVC
{
    /// <summary>Issuer configuration.</summary>
    public sealed class IssuerConfig
    {
        /// <summary>DID of the issuer (e.g. did:web:cosevi.attestto.id).</summary>
        public string Did { get; set; }

        /// <summary>Private key for signing (Ed25519 or P-256).</summary>
        public byte[] PrivateKey { get; set; }

        /// <summary>Key algorithm. Default: Ed25519.</summary>
        public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.Ed25519;

        /// <summary>Key ID fragment (e.g. #key-1).</summary>
        public string KeyId { get; set; } = "#key-1";
    }
}
