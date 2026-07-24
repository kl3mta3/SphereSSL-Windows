using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SphereSSLv2.Services.AcmeServices;

internal sealed class HttpChallengeServer : IAsyncDisposable
{
    internal const string UrlPrefix = "http://+:80/.well-known/acme-challenge/";
    private readonly IReadOnlyDictionary<string, string> _responses;
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;

    internal HttpChallengeServer(IReadOnlyDictionary<string, string> responses)
    {
        _responses = responses;
        _listener.Prefixes.Add(UrlPrefix);
    }

    internal void Start()
    {
        try
        {
            _listener.Start();
            _loop = RunAsync(_stop.Token);
        }
        catch (HttpListenerException ex)
        {
            throw new InvalidOperationException(
                "SphereSSL could not register its temporary HTTP-01 listener on port 80. " +
                "Run SphereSSL with the required HTTP.sys URL reservation or use Webroot mode.", ex);
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync().WaitAsync(cancellationToken);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) when (!_listener.IsListening) { break; }

            _ = Task.Run(() => RespondAsync(context), CancellationToken.None);
        }
    }

    private async Task RespondAsync(HttpListenerContext context)
    {
        try
        {
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            var token = Uri.UnescapeDataString(context.Request.Url?.Segments.LastOrDefault() ?? string.Empty).Trim('/');

            if ((context.Request.HttpMethod == "GET" || context.Request.HttpMethod == "HEAD") &&
                _responses.TryGetValue(token, out var keyAuthorization))
            {
                var bytes = Encoding.ASCII.GetBytes(keyAuthorization);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "text/plain";
                context.Response.ContentLength64 = bytes.Length;
                if (context.Request.HttpMethod != "HEAD")
                    await context.Response.OutputStream.WriteAsync(bytes);
            }
            else
            {
                context.Response.StatusCode = 404;
            }
        }
        finally
        {
            context.Response.Close();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        if (_listener.IsListening) _listener.Stop();
        _listener.Close();
        if (_loop != null)
        {
            try { await _loop; } catch (OperationCanceledException) { }
        }
        _stop.Dispose();
    }
}

internal static class HttpSysUrlReservation
{
    internal static async Task EnsureListenerAvailableAsync()
    {
        try
        {
            await TestListenerAsync();
            return;
        }
        catch (InvalidOperationException ex) when (
            ex.InnerException is HttpListenerException listenerException &&
            listenerException.ErrorCode == 5)
        {
            // HTTP.sys needs a one-time URL ACL. Elevate netsh only, not SphereSSL.
        }
        var account = WindowsIdentity.GetCurrent().Name;
        if (string.IsNullOrWhiteSpace(account) || account.Contains('"'))
            throw new InvalidOperationException(
                "SphereSSL could not determine the current Windows account for the HTTP.sys URL reservation.");
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = $"http add urlacl url={HttpChallengeServer.UrlPrefix} user=\"{account}\"",
            UseShellExecute = true,
            Verb = "runas"
        });
        if (process == null)
            throw new InvalidOperationException("Windows did not start the HTTP.sys reservation helper.");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                "The HTTP.sys URL reservation was not created. Approve the Windows administrator prompt, or select Webroot mode.");
        await TestListenerAsync();
    }
    private static async Task TestListenerAsync()
    {
        await using var server = new HttpChallengeServer(new Dictionary<string, string>
        {
            ["spheressl-configcheck"] = "SphereSSL HTTP-01 challenge server is available."
        });
        server.Start();
        await Task.Delay(100);
    }
}internal sealed class HttpWebRootLease : IAsyncDisposable
{
    private static readonly Regex SafeToken = new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);
    private readonly List<string> _files = new();

    internal HttpWebRootLease(string webRoot, IReadOnlyDictionary<string, string> responses)
    {
        if (string.IsNullOrWhiteSpace(webRoot) || !Path.IsPathFullyQualified(webRoot))
            throw new InvalidOperationException("Webroot mode requires an absolute public webroot path.");

        var root = Path.GetFullPath(webRoot);
        var challengeDirectory = Path.Combine(root, ".well-known", "acme-challenge");
        Directory.CreateDirectory(challengeDirectory);

        foreach (var response in responses)
        {
            if (!SafeToken.IsMatch(response.Key))
                throw new InvalidOperationException("The ACME server returned an invalid HTTP challenge token.");
            var file = Path.Combine(challengeDirectory, response.Key);
            File.WriteAllText(file, response.Value, new UTF8Encoding(false));
            _files.Add(file);
        }
    }

    public ValueTask DisposeAsync()
    {
        foreach (var file in _files)
        {
            try { if (File.Exists(file)) File.Delete(file); } catch { }
        }
        return ValueTask.CompletedTask;
    }
}
