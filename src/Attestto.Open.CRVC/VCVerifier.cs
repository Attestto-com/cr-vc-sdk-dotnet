using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Attestto.Open.CRVC
{
    /// <summary>
    /// Resolves a public key from a DID and key ID.
    /// Returns null if the key cannot be resolved.
    /// </summary>
    public delegate Task<ResolvedKey> PublicKeyResolver(string did, string keyId);

    /// <summary>Resolved public key with its algorithm.</summary>
    public sealed class ResolvedKey
    {
        public byte[] PublicKey { get; }
        public SigningAlgorithm Algorithm { get; }

        public ResolvedKey(byte[] publicKey, SigningAlgorithm algorithm)
        {
            PublicKey = publicKey;
            Algorithm = algorithm;
        }
    }

    /// <summary>
    /// Verify Verifiable Credentials.
    /// </summary>
    public sealed class VCVerifier
    {
        private readonly PublicKeyResolver _resolvePublicKey;
        private readonly ISigner _signer;

        public VCVerifier(PublicKeyResolver resolvePublicKey = null)
            : this(resolvePublicKey, new DefaultSigner()) { }

        public VCVerifier(PublicKeyResolver resolvePublicKey, ISigner signer)
        {
            if (signer == null) throw new ArgumentNullException(nameof(signer));
            _resolvePublicKey = resolvePublicKey;
            _signer = signer;
        }

        /// <summary>Verify a Verifiable Credential.</summary>
        public async Task<VerificationResult> VerifyAsync(
            VerifiableCredential credential,
            VerifyOptions options = null)
        {
            if (credential == null) throw new ArgumentNullException(nameof(credential));
            if (options == null) options = new VerifyOptions();

            var checks = new List<VerificationCheck>();
            var errors = new List<string>();
            var warnings = new List<string>();

            CheckStructure(credential, checks, errors);
            CheckContext(credential, checks, errors);

            if (options.ExpectedType != null)
                CheckExpectedType(credential, options.ExpectedType, checks, errors);

            if (options.ExpectedIssuer != null)
                CheckExpectedIssuer(credential, options.ExpectedIssuer, checks, errors);

            if (options.CheckExpiration)
                CheckExpiration(credential, checks, errors, warnings);

            CheckIssuanceDate(credential, checks, errors);
            await CheckProofIfPresent(credential, checks, errors, warnings);

            if (options.CheckStatus && credential.CredentialStatus != null)
                warnings.Add("Status check requested but StatusList2021 verification not yet implemented");

            return new VerificationResult
            {
                Valid = errors.Count == 0,
                Checks = checks,
                Errors = errors,
                Warnings = warnings,
            };
        }

        /// <summary>Verify a credential with a known public key (no resolver needed).</summary>
        public Task<VerificationResult> VerifyWithKeyAsync(
            VerifiableCredential credential,
            byte[] publicKey,
            SigningAlgorithm algorithm = SigningAlgorithm.Ed25519,
            VerifyOptions options = null)
        {
            PublicKeyResolver resolver = (did, keyId) =>
                Task.FromResult(new ResolvedKey(publicKey, algorithm));

            var verifier = new VCVerifier(resolver, _signer);
            return verifier.VerifyAsync(credential, options);
        }

        private async Task CheckProofIfPresent(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors,
            List<string> warnings)
        {
            if (credential.Proof != null && _resolvePublicKey != null)
                await VerifyProofSignature(credential, checks, errors);
            else if (credential.Proof != null)
                warnings.Add("Proof present but no public key resolver configured — signature not verified");
            else
                warnings.Add("No proof present — credential is unsigned");
        }

        private async Task VerifyProofSignature(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors)
        {
            string did, keyId;
            ParseVerificationMethod(credential.Proof.VerificationMethod, out did, out keyId);

            var resolved = await _resolvePublicKey(did, keyId);
            if (resolved == null)
            {
                checks.Add(new VerificationCheck { Check = "proof.keyResolution", Passed = false, Message = string.Format("Could not resolve key for {0}", did) });
                errors.Add(string.Format("Could not resolve public key for {0}", credential.Proof.VerificationMethod));
                return;
            }

            checks.Add(new VerificationCheck { Check = "proof.keyResolution", Passed = true });

            var message = VCConstants.SerializeForSigning(credential);
            var signature = CryptoKeys.FromBase64Url(credential.Proof.ProofValue ?? "");
            var isValid = _signer.Verify(message, signature, resolved.PublicKey, resolved.Algorithm);

            checks.Add(new VerificationCheck { Check = "proof.signature", Passed = isValid });
            if (!isValid) errors.Add("Invalid signature");
        }

        private static void ParseVerificationMethod(string verificationMethod, out string did, out string keyId)
        {
            var hashIndex = verificationMethod.LastIndexOf('#');
            did = hashIndex > 0 ? verificationMethod.Substring(0, hashIndex) : verificationMethod;
            keyId = hashIndex > 0 ? verificationMethod.Substring(hashIndex) : "#key-1";
        }

        private static void CheckStructure(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors)
        {
            AddCheck(checks, errors, "structure.context",
                credential.Context.Count > 0, "Missing or invalid @context");

            AddCheck(checks, errors, "structure.type",
                credential.Type.Contains("VerifiableCredential"), "Missing VerifiableCredential in type array");

            AddCheck(checks, errors, "structure.issuer",
                !string.IsNullOrEmpty(credential.Issuer) && credential.Issuer.StartsWith("did:"),
                "Missing or invalid issuer DID");

            AddCheck(checks, errors, "structure.subject",
                credential.CredentialSubject.ContainsKey("id"), "Missing credentialSubject.id");

            AddCheck(checks, errors, "structure.issuanceDate",
                !string.IsNullOrEmpty(credential.IssuanceDate), "Missing issuanceDate");
        }

        private static void CheckContext(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors)
        {
            AddCheck(checks, errors, "context.w3c",
                credential.Context.Contains(VCConstants.W3CVcContext),
                string.Format("Missing W3C VC context: {0}", VCConstants.W3CVcContext));

            AddCheck(checks, errors, "context.cr-driving",
                credential.Context.Contains(VCConstants.CrDrivingContext),
                string.Format("Missing CR driving context: {0}", VCConstants.CrDrivingContext));
        }

        private static void CheckExpectedType(
            VerifiableCredential credential, string expectedType,
            List<VerificationCheck> checks, List<string> errors)
        {
            var passed = credential.Type.Contains(expectedType);
            checks.Add(new VerificationCheck { Check = "type.expected", Passed = passed, Message = expectedType });
            if (!passed) errors.Add(string.Format("Expected credential type \"{0}\" not found", expectedType));
        }

        private static void CheckExpectedIssuer(
            VerifiableCredential credential, string expectedIssuer,
            List<VerificationCheck> checks, List<string> errors)
        {
            var passed = credential.Issuer == expectedIssuer;
            checks.Add(new VerificationCheck { Check = "issuer.expected", Passed = passed, Message = expectedIssuer });
            if (!passed) errors.Add(string.Format("Expected issuer \"{0}\", got \"{1}\"", expectedIssuer, credential.Issuer));
        }

        private static void CheckExpiration(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors,
            List<string> warnings)
        {
            if (credential.ExpirationDate == null)
            {
                checks.Add(new VerificationCheck { Check = "expiration", Passed = true, Message = "No expiration date set" });
                return;
            }

            var expiry = DateTime.Parse(credential.ExpirationDate, null, System.Globalization.DateTimeStyles.RoundtripKind);
            var now = DateTime.UtcNow;
            var isValid = expiry > now;

            checks.Add(new VerificationCheck { Check = "expiration", Passed = isValid, Message = credential.ExpirationDate });
            if (!isValid) errors.Add(string.Format("Credential expired on {0}", credential.ExpirationDate));

            if (isValid && (expiry - now).TotalDays < 30)
                warnings.Add(string.Format("Credential expires soon: {0}", credential.ExpirationDate));
        }

        private static void CheckIssuanceDate(
            VerifiableCredential credential,
            List<VerificationCheck> checks,
            List<string> errors)
        {
            if (string.IsNullOrEmpty(credential.IssuanceDate)) return;

            var issued = DateTime.Parse(credential.IssuanceDate, null, System.Globalization.DateTimeStyles.RoundtripKind);
            var isValid = issued <= DateTime.UtcNow + TimeSpan.FromMinutes(5);

            checks.Add(new VerificationCheck { Check = "issuanceDate.notFuture", Passed = isValid });
            if (!isValid) errors.Add(string.Format("Credential issuance date is in the future: {0}", credential.IssuanceDate));
        }

        private static void AddCheck(
            List<VerificationCheck> checks, List<string> errors,
            string checkName, bool passed, string errorMessage)
        {
            checks.Add(new VerificationCheck { Check = checkName, Passed = passed });
            if (!passed) errors.Add(errorMessage);
        }
    }
}
