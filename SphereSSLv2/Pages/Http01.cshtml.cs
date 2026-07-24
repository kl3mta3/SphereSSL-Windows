using ACMESharp.Crypto.JOSE.Impl;
using ACMESharp.Protocol;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using SphereSSLv2.Data.Repositories;
using SphereSSLv2.Models.CertModels;
using SphereSSLv2.Models.Dtos;
using SphereSSLv2.Models.UserModels;
using SphereSSLv2.Services.AcmeServices;
using SphereSSLv2.Services.Config;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SphereSSLv2.Pages;

public class Http01Model : PageModel
{
    private static readonly SemaphoreSlim GenerationLock = new(1, 1);
    private readonly Logger _logger;
    private readonly UserRepository _userRepository;
    public UserSession CurrentUser { get; private set; } = new();

    public Http01Model(Logger logger, UserRepository userRepository)
    {
        _logger = logger;
        _userRepository = userRepository;
    }

    public IActionResult OnGet()
    {
        return TryLoadUser() ? Page() : RedirectToPage("/Index");
    }

    public async Task<IActionResult> OnPostTestListenerAsync()
    {
        if (!TryLoadUser()) return Unauthorized();
        try
        {
            await HttpSysUrlReservation.EnsureListenerAvailableAsync();
            return new JsonResult(new
            {
                success = true,
                message = "HTTP.sys accepted the port 80 challenge listener. If Windows requested administrator approval, the one-time SphereSSL URL reservation was installed. Router, firewall, and public reachability still require external testing."
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { success = false, message = ex.Message });
        }
    }
    public async Task<IActionResult> OnPostCreateAsync([FromBody] HttpCreateRequest request)
    {
        if (!TryLoadUser()) return Unauthorized();
        if (!await GenerationLock.WaitAsync(0))
            return StatusCode(409, new { success = false, message = "A certificate request is already running." });

        try
        {
            var domains = request.Domains
                .Select(d => d.Trim().TrimEnd('.').ToLowerInvariant())
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (domains.Count == 0 || domains.Any(d => d.StartsWith("*.") || Uri.CheckHostName(d) != UriHostNameType.Dns))
                return BadRequest(new { success = false, message = "HTTP-01 requires one or more valid, non-wildcard domain names." });
            if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@'))
                return BadRequest(new { success = false, message = "Enter a valid email address." });
            if (string.IsNullOrWhiteSpace(request.SavePath) || !Path.IsPathFullyQualified(request.SavePath))
                return BadRequest(new { success = false, message = "Select an absolute certificate output folder." });

            var mode = string.Equals(request.HttpValidationMode, "webroot", StringComparison.OrdinalIgnoreCase) ? "webroot" : "http-sys";
            if (mode == "webroot" && (string.IsNullOrWhiteSpace(request.HttpWebRoot) || !Path.IsPathFullyQualified(request.HttpWebRoot)))
                return BadRequest(new { success = false, message = "Webroot mode requires an absolute public webroot folder." });
            if (mode == "http-sys")
                await HttpSysUrlReservation.EnsureListenerAvailableAsync();

            var isViewer = string.Equals(CurrentUser.Role, "Viewer", StringComparison.OrdinalIgnoreCase);
            if (isViewer && ConfigureService.RestrictViewers)
            {
                request.SaveForRenewal = false;
                request.AutoRenew = false;
                request.AutoImport = false;
            }
            if (request.AutoRenew) request.SaveForRenewal = true;
            if (request.AutoImport && !string.Equals(request.OutputFormat, "pfx", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { success = false, message = "Auto Import requires PFX / PKCS#12 format." });
            if (request.AutoImport)
                AcmeService.EnsureLocalMachineCertificateStoreWritable();

            var useStaging = request.UseStaging || ConfigureService.StagingOnly;
            var baseAddress = useStaging ? ConfigureService.CAStagingUrl : ConfigureService.CAPrimeUrl;
            var seed = new AcmeService(_logger);
            ESJwsTool signer = AcmeService.LoadOrCreateSigner(seed);
            var acme = new AcmeService(_logger)
            {
                _logger = _logger,
                _signer = signer,
                _client = new AcmeProtocolClient(new HttpClient { BaseAddress = new Uri(baseAddress) }, null, null, signer)
            };

            var orderId = AcmeService.GenerateCertRequestId();
            var challenges = await acme.CreateUserAccountForHttpCert(request.Email, domains);
            foreach (var challenge in challenges)
            {
                challenge.ChallengeId = Guid.NewGuid().ToString("N");
                challenge.OrderId = orderId;
                challenge.UserId = CurrentUser.UserId;
                challenge.Status = "Processing";
            }

            var (certPem, certKey) = await acme.ProcessHttpCertificateGeneration(
                request.UseSeparateFiles, request.SavePath, mode, request.HttpWebRoot, challenges, CurrentUser.Username,
                request.OutputFormat, request.PfxPassword);
            foreach (var challenge in challenges) challenge.Status = "Valid";

            var importedThumbprint = string.Empty;
            if (request.AutoImport)
            {
                importedThumbprint = AcmeService.ImportPfxToLocalMachine(certPem, certKey, request.PfxPassword);
                await _logger.Info($"[{CurrentUser.Username}]: Imported HTTP-01 certificate into Local Computer > Personal. Thumbprint: {importedThumbprint}.");
            }

            DateTime expiry;
            using (var certificate = X509Certificate2.CreateFromPem(certPem))
                expiry = certificate.NotAfter.ToUniversalTime();

            var record = new CertRecord
            {
                OrderId = orderId,
                UserId = CurrentUser.UserId,
                Email = request.Email.Trim(),
                Challenges = challenges,
                SavePath = Path.GetFullPath(request.SavePath),
                CreationDate = DateTime.UtcNow,
                ExpiryDate = expiry,
                UseSeparateFiles = request.UseSeparateFiles,
                OutputFormat = request.OutputFormat,
                PfxPassword = request.PfxPassword,
                AutoImport = request.AutoImport,
                ImportedThumbprint = importedThumbprint,
                SaveForRenewal = request.SaveForRenewal,
                autoRenew = request.AutoRenew,
                OrderUrl = acme._order.OrderUrl,
                ChallengeType = "http-01",
                HttpValidationMode = mode,
                HttpWebRoot = string.IsNullOrWhiteSpace(request.HttpWebRoot) ? string.Empty : Path.GetFullPath(request.HttpWebRoot),
                CertPem = certPem,
                CertKey = certKey
            };

            if (record.SaveForRenewal)
            {
                await CertRepository.InsertCertRecord(record);
                var stats = await _userRepository.GetUserStatByIdAsync(CurrentUser.UserId) ?? new UserStat { UserId = CurrentUser.UserId };
                stats.TotalCerts++;
                stats.LastCertCreated = DateTime.UtcNow;
                await _userRepository.UpdateUserStatAsync(stats);
            }

            await _logger.Update($"[{CurrentUser.Username}]: HTTP-01 certificate issued for {string.Join(", ", domains)}.");
            return new JsonResult(new
            {
                success = true,
                orderId,
                domains,
                expiryDate = expiry.ToString("O"),
                staging = useStaging,
                useSeparateFiles = request.UseSeparateFiles,
                outputFormat = request.OutputFormat,
                autoImport = request.AutoImport,
                importedThumbprint,
                message = useStaging ? "Staging certificate created successfully." : "Certificate created successfully."
            });
        }
        catch (Exception ex)
        {
            await _logger.Error($"[{CurrentUser.Username}]: HTTP-01 request failed: {ex.Message}");
            return StatusCode(500, new { success = false, message = ex.Message });
        }
        finally
        {
            GenerationLock.Release();
        }
    }

    public IActionResult OnGetDownloadCertPfx() => DownloadTemp("tempCert.pfx", "application/x-pkcs12", "certificate.pfx");
    public IActionResult OnGetDownloadCertPem() => DownloadTemp("tempCert.pem", "application/x-pem-file", "certificate.pem");
    public IActionResult OnGetDownloadCertCrt() => DownloadTemp("tempCert.crt", "application/x-x509-ca-cert", "certificate.crt");
    public IActionResult OnGetDownloadCertKey() => DownloadTemp("tempKey.key", "application/x-pem-key", "private.key");

    private IActionResult DownloadTemp(string sourceName, string contentType, string downloadName)
    {
        var file = Path.Combine(AppContext.BaseDirectory, "Temp", sourceName);
        if (!System.IO.File.Exists(file)) return NotFound();
        return File(System.IO.File.ReadAllBytes(file), contentType, downloadName);
    }

    private bool TryLoadUser()
    {
        var sessionData = HttpContext.Session.GetString("UserSession");
        var user = string.IsNullOrEmpty(sessionData) ? null : JsonConvert.DeserializeObject<UserSession>(sessionData);
        if (user == null) return false;
        CurrentUser = user;
        return true;
    }
}
