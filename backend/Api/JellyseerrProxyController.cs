using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moonfin.Server.Services;

namespace Moonfin.Server.Api;

/// <summary>
/// API controller for Jellyseerr SSO proxy.
/// Handles authentication, session management, and API proxying so that
/// any Moonfin client can access Jellyseerr through the Jellyfin server.
/// </summary>
[ApiController]
[Route("Moonfin/Jellyseerr")]
[Produces(MediaTypeNames.Application.Json)]
public class JellyseerrProxyController : ControllerBase
{
    private readonly JellyseerrSessionService _sessionService;

    public JellyseerrProxyController(JellyseerrSessionService sessionService)
    {
        _sessionService = sessionService;
    }

    /// <summary>
    /// Authenticate with Seerr using Jellyfin credentials.
    /// The session cookie is stored server-side and associated with the Jellyfin user.
    /// Any Moonfin client can then proxy requests through this plugin.
    /// </summary>
    /// <param name="request">Jellyfin credentials for Seerr auth.</param>
    /// <returns>Authentication result with Seerr user info.</returns>
    [HttpPost("Login")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Login([FromBody] JellyseerrLoginRequest request)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();
        if (config?.JellyseerrEnabled != true || string.IsNullOrEmpty(jellyseerrUrl))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new { error = "Seerr integration is not enabled" });
        }

        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        if (string.IsNullOrEmpty(request.Username))
        {
            return BadRequest(new { error = "Username is required" });
        }

        var result = await _sessionService.AuthenticateAsync(
            userId.Value, request.Username, request.Password,
            request.AuthType);

        if (result == null || !result.Success)
        {
            return Unauthorized(new
            {
                error = result?.Error ?? "Authentication failed",
                success = false
            });
        }

        return Ok(new
        {
            success = true,
            jellyseerrUserId = result.JellyseerrUserId,
            displayName = result.DisplayName,
            avatar = result.Avatar,
            permissions = result.Permissions
        });
    }

    /// <summary>
    /// Initiate an OpenID Connect login flow through Seerr.
    /// </summary>
    [HttpGet("Oidc/Login/{slug}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> BeginOidcLogin(string slug, [FromQuery] string? returnUrl)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();
        if (config?.JellyseerrEnabled != true || string.IsNullOrEmpty(jellyseerrUrl))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new { error = "Seerr integration is not enabled" });
        }

        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        var result = await _sessionService.StartOidcLoginAsync(userId.Value, slug, returnUrl);
        if (!result.Success)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { error = result.Error ?? "OIDC login initiation failed" });
        }

        return Ok(new { redirectUrl = result.RedirectUrl });
    }

    /// <summary>
    /// Complete an OpenID Connect callback flow through Seerr.
    /// </summary>
    [HttpPost("Oidc/Callback/{slug}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> CompleteOidcCallback(string slug, [FromBody] JellyseerrOidcCallbackRequest request)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();
        if (config?.JellyseerrEnabled != true || string.IsNullOrEmpty(jellyseerrUrl))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new { error = "Seerr integration is not enabled" });
        }

        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        if (request == null || string.IsNullOrEmpty(request.CallbackUrl))
        {
            return BadRequest(new { error = "callbackUrl is required" });
        }

        var result = await _sessionService.CompleteOidcCallbackAsync(userId.Value, slug, request.CallbackUrl);
        if (result == null || !result.Success)
        {
            return BadRequest(new
            {
                error = result?.Error ?? "OIDC callback failed",
                success = false
            });
        }

        return Ok(new
        {
            success = true,
            jellyseerrUserId = result.JellyseerrUserId,
            displayName = result.DisplayName,
            avatar = result.Avatar,
            permissions = result.Permissions
        });
    }

    /// <summary>
    /// Check the current user's Seerr SSO session status.
    /// </summary>
    /// <returns>Session status including whether authenticated and user info.</returns>
    [HttpGet("Status")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> GetStatus()
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();
        if (config?.JellyseerrEnabled != true || string.IsNullOrEmpty(jellyseerrUrl))
        {
            return Ok(new
            {
                enabled = false,
                authenticated = false,
                url = (string?)null
            });
        }

        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Ok(new
            {
                enabled = true,
                authenticated = false,
                url = jellyseerrUrl
            });
        }

        var session = await _sessionService.GetSessionAsync(userId.Value, validate: false);

        return Ok(new
        {
            enabled = true,
            authenticated = session != null,
            url = jellyseerrUrl,
            jellyseerrUserId = session?.JellyseerrUserId,
            displayName = session?.DisplayName,
            avatar = session?.Avatar,
            permissions = session?.Permissions ?? 0,
            sessionCreated = session?.CreatedAt,
            lastValidated = session?.LastValidated
        });
    }

    /// <summary>
    /// Validate the current session is still active with Seerr.
    /// </summary>
    /// <returns>Whether the session is valid.</returns>
    [HttpGet("Validate")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Validate()
    {
        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Ok(new { valid = false, error = "Not authenticated with Jellyfin" });
        }

        var session = await _sessionService.GetSessionAsync(userId.Value, validate: true);

        return Ok(new
        {
            valid = session != null,
            lastValidated = session?.LastValidated
        });
    }

    /// <summary>
    /// Clear the current user's Seerr SSO session.
    /// </summary>
    [HttpDelete("Logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Logout()
    {
        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        await _sessionService.ProxyRequestAsync(
            userId.Value,
            HttpMethod.Post,
            "auth/logout");

        await _sessionService.ClearSessionAsync(userId.Value);

        return Ok(new { success = true, message = "Logged out from Seerr" });
    }

    /// <summary>
    /// Proxy GET requests to Seerr API.
    /// Path is relative to /api/v1/ (e.g., "auth/me", "request", "search?query=foo").
    /// </summary>
    [HttpGet("Api/{**path}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ProxyGet(string path)
    {
        return await ProxyApiRequest(HttpMethod.Get, path);
    }

    /// <summary>
    /// Proxy POST requests to Seerr API.
    /// </summary>
    [HttpPost("Api/{**path}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ProxyPost(string path)
    {
        return await ProxyApiRequest(HttpMethod.Post, path);
    }

    /// <summary>
    /// Proxy PUT requests to Seerr API.
    /// </summary>
    [HttpPut("Api/{**path}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ProxyPut(string path)
    {
        return await ProxyApiRequest(HttpMethod.Put, path);
    }

    /// <summary>
    /// Proxy DELETE requests to Seerr API.
    /// </summary>
    [HttpDelete("Api/{**path}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ProxyDelete(string path)
    {
        return await ProxyApiRequest(HttpMethod.Delete, path);
    }

    private async Task<IActionResult> ProxyApiRequest(HttpMethod method, string path)
    {
        var config = MoonfinPlugin.Instance?.Configuration;
        var jellyseerrUrl = config?.GetEffectiveJellyseerrUrl();
        if (config?.JellyseerrEnabled != true || string.IsNullOrEmpty(jellyseerrUrl))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new { error = "Seerr integration is not enabled" });
        }

        var userId = this.GetUserIdFromClaims();
        if (userId == null)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        byte[]? body = null;
        string? contentType = null;

        if (method == HttpMethod.Post || method == HttpMethod.Put)
        {
            using var ms = new MemoryStream();
            await Request.Body.CopyToAsync(ms);
            body = ms.ToArray();
            contentType = Request.ContentType;
        }

        var result = await _sessionService.ProxyRequestAsync(
            userId.Value,
            method,
            path,
            Request.QueryString.Value,
            body,
            contentType);

        if (result.Body == null)
        {
            return StatusCode(result.StatusCode);
        }

        var responseContentType = string.IsNullOrWhiteSpace(result.ContentType)
            ? MediaTypeNames.Application.Octet
            : result.ContentType;

        Response.StatusCode = result.StatusCode;
        return File(result.Body, responseContentType);
    }
}

/// <summary>
/// Request body for Seerr login.
/// </summary>
public class JellyseerrLoginRequest
{
    /// <summary>Username (Jellyfin or local Seerr account).</summary>
    public string? Username { get; set; }

    /// <summary>Password.</summary>
    public string? Password { get; set; }

    /// <summary>
    /// Authentication type: "jellyfin" (default) or "local".
    /// Determines which Seerr auth endpoint is used.
    /// </summary>
    public string? AuthType { get; set; }
}

/// <summary>
/// Request body for Seerr OIDC callback.
/// </summary>
public class JellyseerrOidcCallbackRequest
{
    /// <summary>
    /// The full URL returned by the OpenID Connect provider, including code and state.
    /// </summary>
    public string? CallbackUrl { get; set; }
}
