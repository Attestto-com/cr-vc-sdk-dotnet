using System.Security.Cryptography;

namespace Attestto.Open.CRVC;

/// <summary>
/// Key management utilities.
/// Supports Ed25519 (default) and P-256 (ES256) key pairs.
/// </summary>
public static class CryptoKeys
{
    /// <summary>Generate a new key pair.</summary>
    public static KeyPair GenerateKeyPair(SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
    {
        if (algorithm == SigningAlgorithm.Ed25519)
        {
            var ed = new NSec.Cryptography.Ed25519();
            using var key = NSec.Cryptography.Key.Create(ed,
                new NSec.Cryptography.KeyCreationParameters { ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport });

            var privateKeyBytes = key.Export(NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            var publicKeyBytes = key.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);

            return new KeyPair
            {
                Algorithm = algorithm,
                PrivateKey = privateKeyBytes,
                PublicKey = publicKeyBytes,
            };
        }

        // P-256
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(true);

        // Private key: 32 bytes (D parameter)
        var privKey = parameters.D!;

        // Public key: uncompressed format (0x04 + X + Y) = 65 bytes
        var pubKey = new byte[65];
        pubKey[0] = 0x04;
        Buffer.BlockCopy(parameters.Q.X!, 0, pubKey, 1, 32);
        Buffer.BlockCopy(parameters.Q.Y!, 0, pubKey, 33, 32);

        return new KeyPair
        {
            Algorithm = algorithm,
            PrivateKey = privKey,
            PublicKey = pubKey,
        };
    }

    /// <summary>Sign a message with a private key.</summary>
    public static byte[] Sign(byte[] message, byte[] privateKey, SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
    {
        if (algorithm == SigningAlgorithm.Ed25519)
        {
            var ed = new NSec.Cryptography.Ed25519();
            using var key = NSec.Cryptography.Key.Import(ed, privateKey, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            return ed.Sign(key, message);
        }

        // P-256
        using var ecdsa = ImportP256PrivateKey(privateKey);
        return ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>Verify a signature.</summary>
    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey, SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
    {
        try
        {
            if (algorithm == SigningAlgorithm.Ed25519)
            {
                var ed = new NSec.Cryptography.Ed25519();
                var pubKey = NSec.Cryptography.PublicKey.Import(ed, publicKey, NSec.Cryptography.KeyBlobFormat.RawPublicKey);
                return ed.Verify(pubKey, message, signature);
            }

            // P-256
            using var ecdsa = ImportP256PublicKey(publicKey);
            return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Encode bytes to base64url (no padding).</summary>
    public static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>Decode base64url to bytes.</summary>
    public static byte[] FromBase64Url(string str)
    {
        var base64 = str.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        base64 += new string('=', padding);
        return Convert.FromBase64String(base64);
    }

    /// <summary>Encode bytes to hex.</summary>
    public static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static ECDsa ImportP256PrivateKey(byte[] d)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
        };
        // Derive Q from D by creating a temporary key
        using var temp = ECDsa.Create(parameters);
        var full = temp.ExportParameters(true);
        return ECDsa.Create(full);
    }

    private static ECDsa ImportP256PublicKey(byte[] publicKey)
    {
        // Uncompressed: 0x04 + X(32) + Y(32)
        byte[] x, y;
        if (publicKey.Length == 65 && publicKey[0] == 0x04)
        {
            x = publicKey[1..33];
            y = publicKey[33..65];
        }
        else if (publicKey.Length == 64)
        {
            x = publicKey[0..32];
            y = publicKey[32..64];
        }
        else
        {
            throw new ArgumentException("Invalid P-256 public key format");
        }

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        };
        return ECDsa.Create(parameters);
    }
}
