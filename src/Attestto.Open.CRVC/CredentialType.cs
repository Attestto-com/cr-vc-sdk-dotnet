namespace Attestto.Open.CRVC;

/// <summary>
/// Supported credential types from cr-vc-schemas.
/// </summary>
public static class CredentialType
{
    public const string DrivingLicense = "DrivingLicense";
    public const string TheoreticalTestResult = "TheoreticalTestResult";
    public const string PracticalTestResult = "PracticalTestResult";
    public const string MedicalFitnessCredential = "MedicalFitnessCredential";
    public const string VehicleRegistration = "VehicleRegistration";
    public const string VehicleTechnicalReview = "VehicleTechnicalReview";
    public const string CirculationRights = "CirculationRights";
    public const string SOATCredential = "SOATCredential";
    public const string DriverIdentity = "DriverIdentity";
    public const string TrafficViolation = "TrafficViolation";
    public const string AccidentReport = "AccidentReport";

    /// <summary>All known credential types.</summary>
    public static readonly string[] All =
    [
        DrivingLicense, TheoreticalTestResult, PracticalTestResult,
        MedicalFitnessCredential, VehicleRegistration, VehicleTechnicalReview,
        CirculationRights, SOATCredential, DriverIdentity,
        TrafficViolation, AccidentReport,
    ];

    /// <summary>Property name in credentialSubject for each credential type.</summary>
    internal static readonly Dictionary<string, string> PropertyMap = new()
    {
        [DrivingLicense] = "license",
        [TheoreticalTestResult] = "theoreticalTest",
        [PracticalTestResult] = "practicalTest",
        [MedicalFitnessCredential] = "fitness",
        [VehicleRegistration] = "vehicle",
        [VehicleTechnicalReview] = "technicalReview",
        [CirculationRights] = "circulationRights",
        [SOATCredential] = "insurance",
        [DriverIdentity] = "driverIdentity",
        [TrafficViolation] = "violation",
        [AccidentReport] = "accident",
    };
}
