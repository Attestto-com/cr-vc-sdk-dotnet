using System.Collections.Generic;

namespace Attestto.Open.CRVC
{
    /// <summary>Verification result.</summary>
    public sealed class VerificationResult
    {
        public bool Valid { get; set; }
        public IReadOnlyList<VerificationCheck> Checks { get; set; }
        public IReadOnlyList<string> Errors { get; set; }
        public IReadOnlyList<string> Warnings { get; set; }
    }

    /// <summary>Individual verification check.</summary>
    public sealed class VerificationCheck
    {
        public string Check { get; set; }
        public bool Passed { get; set; }
        public string Message { get; set; }
    }
}
