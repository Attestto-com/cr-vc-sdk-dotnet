using System.Collections.Generic;

namespace Attestto.Open.CRVC
{
    /// <summary>Options for issuing a credential.</summary>
    public sealed class IssueOptions
    {
        /// <summary>Credential type.</summary>
        public string Type { get; set; }

        /// <summary>DID of the subject (holder).</summary>
        public string SubjectDid { get; set; }

        /// <summary>Credential subject data (matches the schema for the type).</summary>
        public Dictionary<string, object> Claims { get; set; } = new Dictionary<string, object>();

        /// <summary>Optional expiration date (ISO 8601).</summary>
        public string ExpirationDate { get; set; }

        /// <summary>Optional credential status for revocation.</summary>
        public CredentialStatus CredentialStatus { get; set; }

        /// <summary>Optional credential ID (auto-generated if not provided).</summary>
        public string Id { get; set; }
    }
}
