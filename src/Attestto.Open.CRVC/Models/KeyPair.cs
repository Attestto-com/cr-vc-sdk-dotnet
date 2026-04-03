namespace Attestto.Open.CRVC;

/// <summary>Key pair structure.</summary>
public sealed class KeyPair
{
    public required SigningAlgorithm Algorithm { get; init; }
    public required byte[] PublicKey { get; init; }
    public required byte[] PrivateKey { get; init; }
}
