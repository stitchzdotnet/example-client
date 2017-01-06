// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;

namespace example_client.Infrastructure.OAuth.Provider
{
    public class StitchzAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="StitchzAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Stitchz Access token</param>
        public StitchzAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            ApiKey = TryGetValue<string>(user, "ApiKey");
            Name = TryGetValue<string>(user, "Name");
            UserName = TryGetValue<string>(user, "Name");
            Description = TryGetValue<string>(user, "Description");
            DnsAlias = TryGetValue<string>(user, "DnsAlias");
            Domain = TryGetValue<string>(user, "Domain");
            Favicon = TryGetValue<string>(user, "Favicon");
            PrivacyUrl = TryGetValue<string>(user, "PrivacyUrl");
            WhiteListUrls = TryGetValue<string>(user, "WhiteListUrls");
            UseGetFormMethodRequest = TryGetValue<bool>(user, "UseGetFormMethodRequest");
            RequestUserEmailFromProviders = TryGetValue<bool>(user, "RequestUserEmailFromProviders");
        }

        public StitchzAuthenticatedContext(IOwinContext context) : base(context)
        {
            
        }

        /// <summary>
        /// Gets the JSON-serialized application settings
        /// </summary>
        /// <remarks>
        /// Contains the Stitchz application info obtained from the Settings endpoint. By default this is https://api.stitchz.net/api/v2/Settings but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Stitchz access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Stitchz API Key
        /// </summary>
        public string ApiKey { get; private set; }

        /// <summary>
        /// Gets the Applications's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the Applications's username
        /// </summary>
        public string UserName { get; private set; }

        public string Description { get; set; }

        public string DnsAlias { get; private set; }

        public string Domain { get; set; }

        public string Favicon { get; set; }

        public string PrivacyUrl { get; set; }

        public string ReturnUrl { get; set; }

        public string WhiteListUrls { get; set; }

        public bool UseGetFormMethodRequest { get; set; }

        public bool RequestUserEmailFromProviders { get; set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static T TryGetValue<T>(JObject user, string propertyName)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }

            return default(T);
        }
    }
}