using System.Text;
using Attestto.Open.CRVC;

namespace Attestto.Open.CRVC.Tests;

public class KeysTests
{
    [Fact]
    public void Ed25519_GeneratesValidKeyPair()
    {
        var keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        Assert.Equal(SigningAlgorithm.Ed25519, keys.Algorithm);
        Assert.Equal(32, keys.PrivateKey.Length);
        Assert.Equal(32, keys.PublicKey.Length);
    }

    [Fact]
    public void Ed25519_SignsAndVerifies()
    {
        var keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = CryptoKeys.Sign(message, keys.PrivateKey, SigningAlgorithm.Ed25519);

        Assert.True(CryptoKeys.Verify(message, signature, keys.PublicKey, SigningAlgorithm.Ed25519));
    }

    [Fact]
    public void Ed25519_RejectsTamperedMessage()
    {
        var keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = CryptoKeys.Sign(message, keys.PrivateKey, SigningAlgorithm.Ed25519);

        var tampered = Encoding.UTF8.GetBytes("hello tampered");
        Assert.False(CryptoKeys.Verify(tampered, signature, keys.PublicKey, SigningAlgorithm.Ed25519));
    }

    [Fact]
    public void Ed25519_RejectsWrongKey()
    {
        var keys1 = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        var keys2 = CryptoKeys.GenerateKeyPair(SigningAlgorithm.Ed25519);
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = CryptoKeys.Sign(message, keys1.PrivateKey, SigningAlgorithm.Ed25519);

        Assert.False(CryptoKeys.Verify(message, signature, keys2.PublicKey, SigningAlgorithm.Ed25519));
    }

    [Fact]
    public void ES256_GeneratesValidKeyPair()
    {
        var keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.ES256);
        Assert.Equal(SigningAlgorithm.ES256, keys.Algorithm);
        Assert.True(keys.PrivateKey.Length > 0);
        Assert.True(keys.PublicKey.Length > 0);
    }

    [Fact]
    public void ES256_SignsAndVerifies()
    {
        var keys = CryptoKeys.GenerateKeyPair(SigningAlgorithm.ES256);
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = CryptoKeys.Sign(message, keys.PrivateKey, SigningAlgorithm.ES256);

        Assert.True(CryptoKeys.Verify(message, signature, keys.PublicKey, SigningAlgorithm.ES256));
    }

    [Fact]
    public void Base64Url_Roundtrips()
    {
        var original = new byte[] { 1, 2, 3, 4, 5, 255, 0, 128 };
        var encoded = CryptoKeys.ToBase64Url(original);
        var decoded = CryptoKeys.FromBase64Url(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Hex_ProducesValidOutput()
    {
        var bytes = new byte[] { 0, 15, 255 };
        Assert.Equal("000fff", CryptoKeys.ToHex(bytes));
    }
}
