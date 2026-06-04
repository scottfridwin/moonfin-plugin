using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Moonfin.Server.Services;

/// <summary>
/// Manages per-user Seerr session cookies for SSO.
/// Sessions are stored server-side so any Moonfin client
/// can access Seerr through the Jellyfin plugin without re-authenticating.
/// </summary>
public class JellyseerrSessionService
{
    private readonly string _sessionsPath;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly ILogger<JellyseerrSessionService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private static readonly SemaphoreSlim _lock = new(1, 1);
    private static readonly string[] CsrfCookieNames = { "XSRF-TOKEN", "_csrf", "csrf", "csrfToken" };
    private static readonly string[] CsrfProbePaths = { "/", "/api/v1/settings/public" };

    public JellyseerrSessionService(
        ILogger<JellyseerrSessionService> logger,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;

        var dataPath = MoonfinPlugin.Instance?.DataFolderPath
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Jellyfin", "plugins", "Moonfin");

        _sessionsPath = Path.Combine(dataPath, "jellyseerr-sessions");

        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };

        EnsureDirectory();
    }

    private void EnsureDirectory()
    {
        if (!Directory.Exists(_sessionsPath))
        {
            Directory.CreateDirectory(_sessionsPath);
        }
    }

    private string GetSessionPath(Guid userId) =>
        Path.Combine(_sessionsPath, $"{userId}.json");

    private async Task<string?> FetchCsrfTokenAsync(HttpClient client, string jellyseerrUrl, CookieContainer cookieContainer)
    {
        var baseUrl = jellyseerrUrl.TrimEnd('/');
        var baseUri = new Uri(baseUrl);

        foreach (var path in CsrfProbePaths)
        {
            try
            {
                using var response = await client.GetAsync(
                    baseUrl + path,
                    HttpCompletionOption.ResponseHeadersRead);

                var cookies = cookieContainer.GetCookies(baseUri);
                foreach (var name in CsrfCookieNames)
                {
                    var cookie = cookies[name];
                    if (cookie != null && !string.IsNullOrEmpty(cookie.Value))
                        return Uri.UnescapeDataString(cookie.Value);
                }

                if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
                    continue;

                foreach (var header in setCookieHeaders)
                {
                    foreach (var name in CsrfCookieNames)
                    {
                        var prefix = name + "=";
                        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            continue;

                        var value = header[prefix.Length..];
                        var semi = value.IndexOf(';');
                        if (semi > 0) value = value[..semi];
                        return Uri.UnescapeDataString(value);
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "CSRF prefetch failed for {Url} (non-fatal)", baseUrl + path);
            }
        }

        return null;
    }

    /// <summary>
    /// Authenticates a Jellyfin user with Seerr and stores the session.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <param name="username">The username.</param>
    /// <param name="password">The password.</param>
    /// <param name="authType">Auth type: "jellyfin" (default) or "local" for a native Seerr account.</param>
    /// <returns>The authenticated Seerr user info, or null on failure.</returns>
    public async Task<JellyseerrAuthResult?> AuthenticateAsync(Guid userId, string username, string? password, string? authType = null)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();

        if (string.IsNullOrEmpty(jellyseerrUrl))
        {
            _logger.LogError("Seerr URL not configured");
            return null;
        }

        try
        {
            var cookieContainer = new CookieContainer();
            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true
            };
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(15);

            var isLocal = string.Equals(authType, "local", StringComparison.OrdinalIgnoreCase);
            var authEndpoint = isLocal
                ? $"{jellyseerrUrl}/api/v1/auth/local"
                : $"{jellyseerrUrl}/api/v1/auth/jellyfin";

            var authPayload = isLocal
                ? (object)new { email = username, password = password }
                : new { username = username, password = password ?? string.Empty };

            var content = new StringContent(
                JsonSerializer.Serialize(authPayload),
                Encoding.UTF8,
                "application/json");

            var csrfToken = await FetchCsrfTokenAsync(client, jellyseerrUrl, cookieContainer);

            var request = new HttpRequestMessage(HttpMethod.Post, authEndpoint) { Content = content };
            if (!string.IsNullOrEmpty(csrfToken))
            {
                request.Headers.Add("X-CSRF-Token", csrfToken);
            }

            var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Seerr auth failed for user {Username}: {Status} - {Error}",
                    username, response.StatusCode, errorBody);
                return new JellyseerrAuthResult
                {
                    Success = false,
                    Error = response.StatusCode == HttpStatusCode.Forbidden
                        ? "Access denied. Make sure you have a Seerr account."
                        : $"Authentication failed: {response.StatusCode}"
                };
            }

            // Extract session cookie
            // CookieContainer.GetCookies() can fail with IP-based URLs, so
            // fall back to parsing the Set-Cookie header directly.
            var cookies = cookieContainer.GetCookies(new Uri(jellyseerrUrl));
            var sessionCookie = cookies["connect.sid"]?.Value;

            if (string.IsNullOrEmpty(sessionCookie) &&
                response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            {
                foreach (var header in setCookieHeaders)
                {
                    if (header.StartsWith("connect.sid=", StringComparison.OrdinalIgnoreCase))
                    {
                        var value = header.Substring("connect.sid=".Length);
                        var semicolonIdx = value.IndexOf(';');
                        if (semicolonIdx > 0)
                        {
                            value = value.Substring(0, semicolonIdx);
                        }
                        sessionCookie = Uri.UnescapeDataString(value);
                        _logger.LogInformation("Extracted connect.sid from Set-Cookie header (CookieContainer fallback)");
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(sessionCookie))
            {
                _logger.LogWarning("No session cookie received from Seerr for user {Username}", username);
                return new JellyseerrAuthResult
                {
                    Success = false,
                    Error = "No session cookie received from Seerr"
                };
            }

            // Parse the user response
            var responseBody = await response.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<JsonElement>(responseBody);

            // Store the session
            var session = new JellyseerrSession
            {
                JellyfinUserId = userId,
                SessionCookie = sessionCookie,
                JellyseerrUserId = userInfo.TryGetProperty("id", out var idProp) ? idProp.GetInt32() : 0,
                Username = username,
                DisplayName = userInfo.TryGetProperty("displayName", out var dnProp) ? dnProp.GetString() : username,
                Avatar = userInfo.TryGetProperty("avatar", out var avProp) ? avProp.GetString() : null,
                Permissions = userInfo.TryGetProperty("permissions", out var permProp) ? permProp.GetInt32() : 0,
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                LastValidated = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            await SaveSessionAsync(session);

            _logger.LogInformation("Seerr SSO session created for user {Username} (Jellyfin: {UserId})",
                username, userId);

            return new JellyseerrAuthResult
            {
                Success = true,
                JellyseerrUserId = session.JellyseerrUserId,
                DisplayName = session.DisplayName,
                Avatar = session.Avatar,
                Permissions = session.Permissions
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to connect to Seerr at {Url}", jellyseerrUrl);
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = $"Cannot reach Seerr: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during Seerr auth for user {Username}", username);
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = "An unexpected error occurred"
            };
        }
    }

    /// <summary>
    /// Starts an OIDC login by calling Seerr's OIDC login endpoint and storing correlation cookies.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID starting the OIDC login.</param>
    /// <param name="slug">The OIDC provider slug.</param>
    /// <param name="returnUrl">Optional return URL to pass to Seerr.</param>
    /// <returns>
    /// The result of the OIDC login initiation, including the redirect URL or error details.
    /// </returns>
    public async Task<JellyseerrOidcLoginResult> StartOidcLoginAsync(Guid userId, string slug, string? returnUrl)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();

        if (string.IsNullOrEmpty(jellyseerrUrl))
        {
            return new JellyseerrOidcLoginResult
            {
                Success = false,
                Error = "Seerr URL not configured"
            };
        }

        try
        {
            var cookieContainer = new CookieContainer();
            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                AllowAutoRedirect = false
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(15)
            };

            var loginUrl = $"{jellyseerrUrl}/api/v1/auth/oidc/login/{Uri.EscapeDataString(slug)}";
            if (!string.IsNullOrEmpty(returnUrl))
            {
                loginUrl += $"?returnUrl={Uri.EscapeDataString(returnUrl)}";
            }

            using var response = await client.GetAsync(loginUrl, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode &&
                (response.StatusCode < HttpStatusCode.MultipleChoices || response.StatusCode >= HttpStatusCode.BadRequest))
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Seerr OIDC login initiation failed for user {UserId}: {Status} - {Error}",
                    userId, response.StatusCode, errorBody);

                return new JellyseerrOidcLoginResult
                {
                    Success = false,
                    Error = $"OIDC login initiation failed: {response.StatusCode}"
                };
            }

            string? redirectUrl = null;
            if (response.Headers.Location != null)
            {
                redirectUrl = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location.ToString()
                    : new Uri(new Uri(jellyseerrUrl), response.Headers.Location).ToString();
            }
            else
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                try
                {
                    var payload = JsonSerializer.Deserialize<JsonElement>(responseBody);
                    if (payload.TryGetProperty("redirectUrl", out var redirectElement) &&
                        redirectElement.ValueKind == JsonValueKind.String)
                    {
                        redirectUrl = redirectElement.GetString();
                    }
                }
                catch (JsonException)
                {
                    _logger.LogDebug("Seerr OIDC login response is not JSON; body length={Length}", responseBody.Length);
                }
            }

            if (string.IsNullOrEmpty(redirectUrl))
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Seerr OIDC login did not return a redirect URL for user {UserId}. Response code: {Status}.", userId, response.StatusCode);

                return new JellyseerrOidcLoginResult
                {
                    Success = false,
                    Error = "Seerr OIDC login initiation did not return a redirect URL"
                };
            }
            var state = new JellyseerrOidcState
            {
                JellyfinUserId = userId,
                Slug = slug,
                ReturnUrl = returnUrl,
                Cookies = GetCookiesFromResponse(response, cookieContainer, new Uri(jellyseerrUrl)),
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            await SaveOidcStateAsync(state);

            return new JellyseerrOidcLoginResult
            {
                Success = true,
                RedirectUrl = redirectUrl
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to connect to Seerr at {Url}", jellyseerrUrl);
            return new JellyseerrOidcLoginResult
            {
                Success = false,
                Error = $"Cannot reach Seerr: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during Seerr OIDC login for user {UserId}", userId);
            return new JellyseerrOidcLoginResult
            {
                Success = false,
                Error = "An unexpected error occurred"
            };
        }
    }

    /// <summary>
    /// Completes an OIDC callback by posting the provider callback URL to Seerr and storing the resulting session.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID completing the OIDC login.</param>
    /// <param name="slug">The OIDC provider slug.</param>
    /// <param name="callbackUrl">The full callback URL returned by the OIDC provider.</param>
    /// <returns>
    /// The authenticated Seerr user info if the OIDC callback completed successfully, otherwise error details.
    /// </returns>
    public async Task<JellyseerrAuthResult> CompleteOidcCallbackAsync(Guid userId, string slug, string callbackUrl)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();

        if (string.IsNullOrEmpty(jellyseerrUrl))
        {
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = "Seerr URL not configured"
            };
        }

        var state = await LoadOidcStateAsync(userId);
        if (state == null || !string.Equals(state.Slug, slug, StringComparison.OrdinalIgnoreCase))
        {
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = "No pending OIDC login found for this user"
            };
        }

        try
        {
            var cookieContainer = new CookieContainer();
            var baseUri = new Uri(jellyseerrUrl);
            AddCookiesToContainer(cookieContainer, baseUri, state.Cookies);

            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(15)
            };

            var requestUrl = $"{jellyseerrUrl}/api/v1/auth/oidc/callback/{Uri.EscapeDataString(slug)}";
            var requestContent = new StringContent(
                JsonSerializer.Serialize(new { callbackUrl }),
                Encoding.UTF8,
                "application/json");

            using var response = await client.PostAsync(requestUrl, requestContent);
            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Seerr OIDC callback failed for user {UserId}: {Status} - {Error}",
                    userId, response.StatusCode, errorBody);

                return new JellyseerrAuthResult
                {
                    Success = false,
                    Error = $"OIDC callback failed: {response.StatusCode}"
                };
            }

            var sessionCookie = cookieContainer.GetCookies(baseUri)["connect.sid"]?.Value;
            if (string.IsNullOrEmpty(sessionCookie) &&
                response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            {
                foreach (var header in setCookieHeaders)
                {
                    if (header.StartsWith("connect.sid=", StringComparison.OrdinalIgnoreCase))
                    {
                        var value = header.Substring("connect.sid=".Length);
                        var semicolonIdx = value.IndexOf(';');
                        if (semicolonIdx > 0)
                        {
                            value = value.Substring(0, semicolonIdx);
                        }
                        sessionCookie = Uri.UnescapeDataString(value);
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(sessionCookie))
            {
                _logger.LogWarning("Seerr OIDC callback did not return a session cookie for user {UserId}", userId);
                return new JellyseerrAuthResult
                {
                    Success = false,
                    Error = "Seerr did not return a session cookie"
                };
            }

            var userInfo = await GetSeerrUserInfoAsync(client, jellyseerrUrl);
            if (userInfo == null)
            {
                return new JellyseerrAuthResult
                {
                    Success = false,
                    Error = "Failed to verify Seerr user after OIDC callback"
                };
            }

            var userInfoElement = userInfo.Value;
            var session = new JellyseerrSession
            {
                JellyfinUserId = userId,
                SessionCookie = sessionCookie,
                JellyseerrUserId = userInfoElement.TryGetProperty("id", out var idProp) ? idProp.GetInt32() : 0,
                Username = userInfoElement.TryGetProperty("username", out var usernameProp) ? usernameProp.GetString() ?? string.Empty : string.Empty,
                DisplayName = userInfoElement.TryGetProperty("displayName", out var dnProp) ? dnProp.GetString() : null,
                Avatar = userInfoElement.TryGetProperty("avatar", out var avProp) ? avProp.GetString() : null,
                Permissions = userInfoElement.TryGetProperty("permissions", out var permProp) ? permProp.GetInt32() : 0,
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                LastValidated = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            await SaveSessionAsync(session);
            await ClearOidcStateAsync(userId);

            _logger.LogInformation("Seerr OIDC session created for user {UserId}", userId);

            return new JellyseerrAuthResult
            {
                Success = true,
                JellyseerrUserId = session.JellyseerrUserId,
                DisplayName = session.DisplayName,
                Avatar = session.Avatar,
                Permissions = session.Permissions
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to connect to Seerr at {Url}", jellyseerrUrl);
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = $"Cannot reach Seerr: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during Seerr OIDC callback for user {UserId}", userId);
            return new JellyseerrAuthResult
            {
                Success = false,
                Error = "An unexpected error occurred"
            };
        }
    }

    private async Task<JsonElement?> GetSeerrUserInfoAsync(HttpClient client, string jellyseerrUrl)
    {
        using var response = await client.GetAsync($"{jellyseerrUrl}/api/v1/auth/me");
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var body = await response.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<JsonElement?>(body, _jsonOptions);
        if (userInfo == null || userInfo.Value.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

        return userInfo;
    }

    private static Dictionary<string, string> GetCookiesFromResponse(
        HttpResponseMessage response,
        CookieContainer cookieContainer,
        Uri baseUri)
    {
        var cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Cookie cookie in cookieContainer.GetCookies(baseUri))
        {
            if (!string.IsNullOrEmpty(cookie.Value))
            {
                cookies[cookie.Name] = cookie.Value;
            }
        }

        if (response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            foreach (var header in setCookieHeaders)
            {
                var cookiePair = header.Split(';', 2)[0];
                var equalIndex = cookiePair.IndexOf('=');
                if (equalIndex <= 0) continue;

                var name = cookiePair[..equalIndex].Trim();
                var value = Uri.UnescapeDataString(cookiePair[(equalIndex + 1)..].Trim());
                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(value))
                {
                    cookies[name] = value;
                }
            }
        }

        return cookies;
    }

    private static void AddCookiesToContainer(
        CookieContainer cookieContainer,
        Uri baseUri,
        IDictionary<string, string> cookies)
    {
        foreach (var kvp in cookies)
        {
            if (!string.IsNullOrEmpty(kvp.Key) && kvp.Value != null)
            {
                cookieContainer.Add(baseUri, new Cookie(kvp.Key, kvp.Value));
            }
        }
    }

    private string GetOidcStatePath(Guid userId) =>
        Path.Combine(_sessionsPath, $"{userId}.oidc.json");

    private async Task SaveOidcStateAsync(JellyseerrOidcState state)
    {
        await _lock.WaitAsync();
        try
        {
            EnsureDirectory();
            var json = JsonSerializer.Serialize(state, _jsonOptions);
            await File.WriteAllTextAsync(GetOidcStatePath(state.JellyfinUserId), json);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<JellyseerrOidcState?> LoadOidcStateAsync(Guid userId)
    {
        var path = GetOidcStatePath(userId);
        if (!File.Exists(path)) return null;

        await _lock.WaitAsync();
        try
        {
            var json = await File.ReadAllTextAsync(path);
            return JsonSerializer.Deserialize<JellyseerrOidcState>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load Seerr OIDC state for user {UserId}", userId);
            return null;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task ClearOidcStateAsync(Guid userId)
    {
        await _lock.WaitAsync();
        try
        {
            var path = GetOidcStatePath(userId);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Gets the stored session for a user, optionally validating it.
    /// </summary>
    public async Task<JellyseerrSession?> GetSessionAsync(Guid userId, bool validate = false)
    {
        var session = await LoadSessionAsync(userId);
        if (session == null || string.IsNullOrEmpty(session.SessionCookie))
        {
            if (session != null)
            {
                _logger.LogWarning("Seerr session for user {UserId} has empty cookie, treating as invalid", userId);
            }
            return null;
        }

        if (validate)
        {
            var isValid = await ValidateSessionAsync(session);
            if (!isValid)
            {
                _logger.LogInformation("Seerr session expired for user {UserId}, removing", userId);
                await ClearSessionAsync(userId);
                return null;
            }
        }

        return session;
    }

    /// <summary>
    /// Validates a stored session by calling Seerr's /auth/me endpoint.
    /// </summary>
    private async Task<bool> ValidateSessionAsync(JellyseerrSession session)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();

        if (string.IsNullOrEmpty(jellyseerrUrl)) return false;

        try
        {
            var cookieContainer = new CookieContainer();
            cookieContainer.Add(new Uri(jellyseerrUrl), new Cookie("connect.sid", session.SessionCookie));

            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true
            };
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(10);

            var response = await client.GetAsync($"{jellyseerrUrl}/api/v1/auth/me");

            if (response.IsSuccessStatusCode)
            {
                await CheckForRotatedCookieAsync(session, response, cookieContainer, jellyseerrUrl);

                // Update last validated timestamp
                session.LastValidated = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                await SaveSessionAsync(session);
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to validate Seerr session for user {UserId}", session.JellyfinUserId);
            return false;
        }
    }

    /// <summary>
    /// Checks if Seerr rotated the connect.sid cookie and updates the session if so.
    /// Express.js with rolling sessions may issue a new cookie on every response.
    /// </summary>
    private async Task CheckForRotatedCookieAsync(
        JellyseerrSession session,
        HttpResponseMessage response,
        CookieContainer cookieContainer,
        string jellyseerrUrl)
    {
        var updatedCookie = cookieContainer.GetCookies(new Uri(jellyseerrUrl))["connect.sid"]?.Value;
        if (string.IsNullOrEmpty(updatedCookie) &&
            response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            foreach (var header in setCookieHeaders)
            {
                if (header.StartsWith("connect.sid=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = header.Substring("connect.sid=".Length);
                    var semicolonIdx = value.IndexOf(';');
                    if (semicolonIdx > 0) value = value.Substring(0, semicolonIdx);
                    updatedCookie = Uri.UnescapeDataString(value);
                    break;
                }
            }
        }

        if (!string.IsNullOrEmpty(updatedCookie) && updatedCookie != session.SessionCookie)
        {
            _logger.LogInformation("Seerr rotated session cookie for user {UserId}, updating", session.JellyfinUserId);
            session.SessionCookie = updatedCookie;
            await SaveSessionAsync(session);
        }
    }

    public async Task ClearSessionAsync(Guid userId)
    {
        await _lock.WaitAsync();
        try
        {
            var path = GetSessionPath(userId);
            if (File.Exists(path))
            {
                File.Delete(path);
                _logger.LogInformation("Seerr session cleared for user {UserId}", userId);
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Proxies an HTTP request to Seerr with the user's stored session cookie.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">API path (e.g., "auth/me", "request", "search").</param>
    /// <param name="queryString">Optional query string.</param>
    /// <param name="body">Optional request body.</param>
    /// <param name="contentType">Content type of the body.</param>
    /// <returns>The proxied response.</returns>
    public async Task<JellyseerrProxyResponse> ProxyRequestAsync(
        Guid userId,
        HttpMethod method,
        string path,
        string? queryString = null,
        byte[]? body = null,
        string? contentType = null)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();

        if (string.IsNullOrEmpty(jellyseerrUrl))
        {
            return new JellyseerrProxyResponse
            {
                StatusCode = 503,
                Body = JsonSerializer.SerializeToUtf8Bytes(new { error = "Seerr URL not configured" }),
                ContentType = "application/json"
            };
        }

        var session = await LoadSessionAsync(userId);
        if (session == null)
        {
            return new JellyseerrProxyResponse
            {
                StatusCode = 401,
                Body = JsonSerializer.SerializeToUtf8Bytes(new { error = "Not authenticated with Seerr", code = "NO_SESSION" }),
                ContentType = "application/json"
            };
        }

        try
        {
            var cookieContainer = new CookieContainer();
            cookieContainer.Add(new Uri(jellyseerrUrl), new Cookie("connect.sid", session.SessionCookie));

            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true
            };
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(30);

            // Build the target URL
            var targetUrl = $"{jellyseerrUrl}/api/v1/{path.TrimStart('/')}";
            if (!string.IsNullOrEmpty(queryString))
            {
                targetUrl += $"?{queryString.TrimStart('?')}";
            }

            var request = new HttpRequestMessage(method, targetUrl);

            if (method != HttpMethod.Get && method != HttpMethod.Head)
            {
                var csrfToken = await FetchCsrfTokenAsync(client, jellyseerrUrl, cookieContainer);
                if (!string.IsNullOrEmpty(csrfToken))
                {
                    request.Headers.Add("X-CSRF-Token", csrfToken);
                }
            }

            if (body != null && body.Length > 0)
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                    contentType ?? "application/json");
            }

            var response = await client.SendAsync(request);

            var responseBody = await response.Content.ReadAsByteArrayAsync();
            var responseContentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";

            // If auth expired, clear session
            if (response.StatusCode == HttpStatusCode.Unauthorized ||
                response.StatusCode == HttpStatusCode.Forbidden)
            {
                _logger.LogInformation("Seerr session expired for user {UserId}", userId);
                await ClearSessionAsync(userId);

                return new JellyseerrProxyResponse
                {
                    StatusCode = 401,
                    Body = JsonSerializer.SerializeToUtf8Bytes(new { error = "Seerr session expired", code = "SESSION_EXPIRED" }),
                    ContentType = "application/json"
                };
            }

            if (response.IsSuccessStatusCode)
            {
                await CheckForRotatedCookieAsync(session, response, cookieContainer, jellyseerrUrl);
            }

            return new JellyseerrProxyResponse
            {
                StatusCode = (int)response.StatusCode,
                Body = responseBody,
                ContentType = responseContentType
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to proxy request to Seerr: {Path}", path);
            return new JellyseerrProxyResponse
            {
                StatusCode = 502,
                Body = JsonSerializer.SerializeToUtf8Bytes(new { error = $"Cannot reach Seerr: {ex.Message}" }),
                ContentType = "application/json"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error proxying to Seerr: {Path}", path);
            return new JellyseerrProxyResponse
            {
                StatusCode = 500,
                Body = JsonSerializer.SerializeToUtf8Bytes(new { error = "Internal proxy error" }),
                ContentType = "application/json"
            };
        }
    }

    private async Task SaveSessionAsync(JellyseerrSession session)
    {
        await _lock.WaitAsync();
        try
        {
            EnsureDirectory();
            var json = JsonSerializer.Serialize(session, _jsonOptions);
            await File.WriteAllTextAsync(GetSessionPath(session.JellyfinUserId), json);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<JellyseerrSession?> LoadSessionAsync(Guid userId)
    {
        var path = GetSessionPath(userId);
        if (!File.Exists(path)) return null;

        await _lock.WaitAsync();
        try
        {
            var json = await File.ReadAllTextAsync(path);
            return JsonSerializer.Deserialize<JellyseerrSession>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load Seerr session for user {UserId}", userId);
            return null;
        }
        finally
        {
            _lock.Release();
        }
    }
}

/// <summary>
/// Temporarily stores the state for an ongoing Seerr OIDC login flow.
/// </summary>
public class JellyseerrOidcState
{
    [JsonPropertyName("jellyfinUserId")]
    public Guid JellyfinUserId { get; set; }

    [JsonPropertyName("slug")]
    public string Slug { get; set; } = string.Empty;

    [JsonPropertyName("returnUrl")]
    public string? ReturnUrl { get; set; }

    [JsonPropertyName("cookies")]
    public Dictionary<string, string> Cookies { get; set; } = new();

    [JsonPropertyName("createdAt")]
    public long CreatedAt { get; set; }
}

/// <summary>
/// Result returned when an OIDC login is started.
/// </summary>
public class JellyseerrOidcLoginResult
{
    /// <summary>Whether the OIDC login initiation succeeded.</summary>
    public bool Success { get; set; }

    /// <summary>Redirect URL returned by Seerr for the OIDC provider.</summary>
    public string? RedirectUrl { get; set; }

    /// <summary>Error message if the login initiation failed.</summary>
    public string? Error { get; set; }
}

/// <summary>
/// Stored Seerr session data for a Jellyfin user.
/// </summary>
public class JellyseerrSession
{
    /// <summary>The Jellyfin user ID this session belongs to.</summary>
    [JsonPropertyName("jellyfinUserId")]
    public Guid JellyfinUserId { get; set; }

    /// <summary>The Seerr connect.sid session cookie value.</summary>
    [JsonPropertyName("sessionCookie")]
    public string SessionCookie { get; set; } = string.Empty;

    /// <summary>The Seerr internal user ID.</summary>
    [JsonPropertyName("jellyseerrUserId")]
    public int JellyseerrUserId { get; set; }

    /// <summary>The username used to authenticate.</summary>
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>Display name from Seerr.</summary>
    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    /// <summary>Avatar URL from Seerr.</summary>
    [JsonPropertyName("avatar")]
    public string? Avatar { get; set; }

    /// <summary>Seerr permission bitmask.</summary>
    [JsonPropertyName("permissions")]
    public int Permissions { get; set; }

    /// <summary>When the session was created (unix ms).</summary>
    [JsonPropertyName("createdAt")]
    public long CreatedAt { get; set; }

    /// <summary>When the session was last validated (unix ms).</summary>
    [JsonPropertyName("lastValidated")]
    public long LastValidated { get; set; }
}

/// <summary>
/// Result of a Seerr authentication attempt.
/// </summary>
public class JellyseerrAuthResult
{
    /// <summary>Whether authentication succeeded.</summary>
    public bool Success { get; set; }

    /// <summary>Error message if auth failed.</summary>
    public string? Error { get; set; }

    /// <summary>Seerr user ID if successful.</summary>
    public int JellyseerrUserId { get; set; }

    /// <summary>Display name from Seerr.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Avatar URL.</summary>
    public string? Avatar { get; set; }

    /// <summary>Seerr permission bitmask.</summary>
    public int Permissions { get; set; }
}

/// <summary>
/// Response from a proxied Seerr request.
/// </summary>
public class JellyseerrProxyResponse
{
    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; set; }

    /// <summary>Response body bytes.</summary>
    public byte[]? Body { get; set; }

    /// <summary>Response content type.</summary>
    public string ContentType { get; set; } = "application/json";
}
