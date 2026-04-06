using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Attestto.Open.CRVC
{
    /// <summary>
    /// Key management utilities.
    /// Supports Ed25519 (default, via BouncyCastle) and P-256 (ES256, via BCL).
    /// </summary>
    public static class CryptoKeys
    {
        /// <summary>Generate a new key pair.</summary>
        public static KeyPair GenerateKeyPair(SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
        {
            if (algorithm == SigningAlgorithm.Ed25519)
            {
                var gen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
                gen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 256));
                var pair = gen.GenerateKeyPair();

                var privParams = (Ed25519PrivateKeyParameters)pair.Private;
                var pubParams = (Ed25519PublicKeyParameters)pair.Public;

                return new KeyPair
                {
                    Algorithm = algorithm,
                    PrivateKey = privParams.GetEncoded(),
                    PublicKey = pubParams.GetEncoded(),
                };
            }

            // P-256
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = ecdsa.ExportParameters(true);
                var privKey = parameters.D;
                var pubKey = new byte[65];
                pubKey[0] = 0x04;
                Buffer.BlockCopy(parameters.Q.X, 0, pubKey, 1, 32);
                Buffer.BlockCopy(parameters.Q.Y, 0, pubKey, 33, 32);

                return new KeyPair
                {
                    Algorithm = algorithm,
                    PrivateKey = privKey,
                    PublicKey = pubKey,
                };
            }
        }

        /// <summary>Sign a message with a private key.</summary>
        public static byte[] Sign(byte[] message, byte[] privateKey, SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
        {
            if (algorithm == SigningAlgorithm.Ed25519)
            {
                var privParams = new Ed25519PrivateKeyParameters(privateKey, 0);
                var signer = new Ed25519Signer();
                signer.Init(true, privParams);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.GenerateSignature();
            }

            // P-256
            using (var ecdsa = ImportP256PrivateKey(privateKey))
            {
#if NETSTANDARD2_0
                var derSig = ecdsa.SignData(message, HashAlgorithmName.SHA256);
                return DerToIeee(derSig);
#else
                return ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
            }
        }

        /// <summary>Verify a signature.</summary>
        public static bool Verify(byte[] message, byte[] signature, byte[] publicKey, SigningAlgorithm algorithm = SigningAlgorithm.Ed25519)
        {
            try
            {
                if (algorithm == SigningAlgorithm.Ed25519)
                {
                    var pubParams = new Ed25519PublicKeyParameters(publicKey, 0);
                    var verifier = new Ed25519Signer();
                    verifier.Init(false, pubParams);
                    verifier.BlockUpdate(message, 0, message.Length);
                    return verifier.VerifySignature(signature);
                }

                // P-256
                using (var ecdsa = ImportP256PublicKey(publicKey))
                {
#if NETSTANDARD2_0
                    var derSig = IeeeToDer(signature);
                    return ecdsa.VerifyData(message, derSig, HashAlgorithmName.SHA256);
#else
                    return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
                }
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
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();
        }

#if NETSTANDARD2_0
        private static byte[] DerToIeee(byte[] der)
        {
            // DER: 0x30 len 0x02 rLen r 0x02 sLen s → IEEE P1363: r(32) + s(32)
            int offset = 2;
            int rLen = der[offset + 1];
            var r = new byte[32];
            var s = new byte[32];
            int rStart = offset + 2 + (rLen > 32 ? rLen - 32 : 0);
            int rCopy = System.Math.Min(rLen, 32);
            Array.Copy(der, rStart, r, 32 - rCopy, rCopy);
            offset = offset + 2 + rLen;
            int sLen = der[offset + 1];
            int sStart = offset + 2 + (sLen > 32 ? sLen - 32 : 0);
            int sCopy = System.Math.Min(sLen, 32);
            Array.Copy(der, sStart, s, 32 - sCopy, sCopy);
            var result = new byte[64];
            Array.Copy(r, 0, result, 0, 32);
            Array.Copy(s, 0, result, 32, 32);
            return result;
        }

        private static byte[] IeeeToDer(byte[] ieee)
        {
            // IEEE P1363: r(32) + s(32) → DER: 0x30 len 0x02 rLen r 0x02 sLen s
            var r = TrimLeadingZeros(ieee, 0, 32);
            var s = TrimLeadingZeros(ieee, 32, 32);
            if (r[0] >= 0x80) { var tmp = new byte[r.Length + 1]; Array.Copy(r, 0, tmp, 1, r.Length); r = tmp; }
            if (s[0] >= 0x80) { var tmp = new byte[s.Length + 1]; Array.Copy(s, 0, tmp, 1, s.Length); s = tmp; }
            var der = new byte[6 + r.Length + s.Length];
            der[0] = 0x30;
            der[1] = (byte)(4 + r.Length + s.Length);
            der[2] = 0x02;
            der[3] = (byte)r.Length;
            Array.Copy(r, 0, der, 4, r.Length);
            der[4 + r.Length] = 0x02;
            der[5 + r.Length] = (byte)s.Length;
            Array.Copy(s, 0, der, 6 + r.Length, s.Length);
            return der;
        }

        private static byte[] TrimLeadingZeros(byte[] src, int offset, int length)
        {
            int start = offset;
            while (start < offset + length - 1 && src[start] == 0) start++;
            var result = new byte[offset + length - start];
            Array.Copy(src, start, result, 0, result.Length);
            return result;
        }
#endif

        private static ECDsa ImportP256PrivateKey(byte[] d)
        {
            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
            };
            using (var temp = ECDsa.Create(parameters))
            {
                var full = temp.ExportParameters(true);
                return ECDsa.Create(full);
            }
        }

        private static ECDsa ImportP256PublicKey(byte[] publicKey)
        {
            byte[] x, y;
            if (publicKey.Length == 65 && publicKey[0] == 0x04)
            {
                x = new byte[32];
                y = new byte[32];
                Array.Copy(publicKey, 1, x, 0, 32);
                Array.Copy(publicKey, 33, y, 0, 32);
            }
            else if (publicKey.Length == 64)
            {
                x = new byte[32];
                y = new byte[32];
                Array.Copy(publicKey, 0, x, 0, 32);
                Array.Copy(publicKey, 32, y, 0, 32);
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
}
