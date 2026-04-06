namespace Attestto.Open.CRVC
{
    /// <summary>
    /// Abstracts cryptographic signing operations.
    /// Enables DI and testability — consumers can mock this for unit tests
    /// or swap implementations (HSM, cloud KMS, etc.).
    /// </summary>
    public interface ISigner
    {
        byte[] Sign(byte[] message, byte[] privateKey, SigningAlgorithm algorithm);
        bool Verify(byte[] message, byte[] signature, byte[] publicKey, SigningAlgorithm algorithm);
    }

    /// <summary>Default implementation using BouncyCastle (Ed25519) and BCL (P-256).</summary>
    internal sealed class DefaultSigner : ISigner
    {
        public byte[] Sign(byte[] message, byte[] privateKey, SigningAlgorithm algorithm)
            => CryptoKeys.Sign(message, privateKey, algorithm);

        public bool Verify(byte[] message, byte[] signature, byte[] publicKey, SigningAlgorithm algorithm)
            => CryptoKeys.Verify(message, signature, publicKey, algorithm);
    }
}
