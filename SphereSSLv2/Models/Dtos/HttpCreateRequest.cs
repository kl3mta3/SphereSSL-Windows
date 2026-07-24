using System.Text.Json.Serialization;

namespace SphereSSLv2.Models.Dtos;

public class HttpCreateRequest
{
    [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    [JsonPropertyName("domains")] public List<string> Domains { get; set; } = new();
    [JsonPropertyName("savePath")] public string SavePath { get; set; } = string.Empty;
    [JsonPropertyName("httpValidationMode")] public string HttpValidationMode { get; set; } = "http-sys";
    [JsonPropertyName("httpWebRoot")] public string HttpWebRoot { get; set; } = string.Empty;
    [JsonPropertyName("useSeparateFiles")] public bool UseSeparateFiles { get; set; }
    [JsonPropertyName("outputFormat")] public string OutputFormat { get; set; } = "pem";
    [JsonPropertyName("pfxPassword")] public string PfxPassword { get; set; } = string.Empty;
    [JsonPropertyName("autoImport")] public bool AutoImport { get; set; }
    [JsonPropertyName("saveForRenewal")] public bool SaveForRenewal { get; set; }
    [JsonPropertyName("autoRenew")] public bool AutoRenew { get; set; }
    [JsonPropertyName("useStaging")] public bool UseStaging { get; set; }
}
