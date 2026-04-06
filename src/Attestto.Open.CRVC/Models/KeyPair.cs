namespace Attestto.Open.CRVC
{
    /// <summary>Key pair structure.</summary>
    public sealed class KeyPair
    {
        public SigningAlgorithm Algorithm { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] PrivateKey { get; set; }
    }
}
