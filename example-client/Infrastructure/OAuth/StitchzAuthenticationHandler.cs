using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using example_client.Infrastructure.OAuth.Provider;

namespace example_client.Infrastructure.OAuth
{
    public class StitchzAuthenticationHandler : AuthenticationHandler<StitchzAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public StitchzAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));
                body.Add(new KeyValuePair<string, string>("Version", "v2"));
                body.Add(new KeyValuePair<string, string>("Format", "xml"));

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                HttpResponseMessage tokenResponse = await httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = (string)response.access_token;

                var token = new AuthorizationToken
                {
                    AccessToken = (string)response.access_token,
                    RefreshToken = (string)response.refresh_token,
                    ExpiresIn = (int)response.expires_in,
                    TokenType = (string)response.token_type,
                    Scope = (string)response.scope,
                };

                // Get the Stitchz user
                HttpRequestMessage userRequest = new HttpRequestMessage(HttpMethod.Get, Options.Endpoints.UserInfoEndpoint);
                userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage userResponse = await httpClient.SendAsync(userRequest, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new StitchzAuthenticatedContext(Context, user, accessToken);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:name", context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.ApiKey))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.ApiKey, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Description))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:description", context.Description, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DnsAlias))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:dnsalias", context.DnsAlias, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Domain))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:domain", context.Domain, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Favicon))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:favicon", context.Favicon, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.PrivacyUrl))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:privacyurl", context.PrivacyUrl, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.ReturnUrl))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:returnurl", context.ReturnUrl, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.WhiteListUrls))
                {
                    context.Identity.AddClaim(new Claim("urn:stitchz:whitelisturl", context.WhiteListUrls, XmlSchemaString, Options.AuthenticationType));
                }
                //if (!string.IsNullOrEmpty(context.RequestUserEmailFromProviders))
                //{
                //    context.Identity.AddClaim(new Claim("urn:stitchz:url", context.RequestUserEmailFromProviders, XmlSchemaString, Options.AuthenticationType));
                //}
                //if (!string.IsNullOrEmpty(context.UseGetFormMethodRequest))
                //{
                //    context.Identity.AddClaim(new Claim("urn:stitchz:url", context.UseGetFormMethodRequest, XmlSchemaString, Options.AuthenticationType));
                //}

                // Add token to claims for use later
                context.Identity.AddClaim(new Claim("urn:stitchz:token", token.AccessToken, XmlSchemaString, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim("urn:stitchz:refreshtoken", token.RefreshToken, XmlSchemaString, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim("urn:stitchz:tokenexpiresin", Convert.ToString(token.ExpiresIn), XmlSchemaString, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim("urn:stitchz:tokenscope", token.Scope, XmlSchemaString, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim("urn:stitchz:tokentype", token.TokenType, XmlSchemaString, Options.AuthenticationType));

                context.Properties = properties;

                await Options.Provider.Authenticated(context);
                
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    Options.Endpoints.AuthorizationEndpoint +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new StitchzReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}