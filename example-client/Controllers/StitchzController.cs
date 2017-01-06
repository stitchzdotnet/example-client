using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace example_client.Controllers
{
    [Authorize]
    public class StitchzController : Controller
    {
        private const string identity = "https://www.facebook.com/app_scoped_user_id/1592234387/";
        private const string host = "https://api.stitchz.net/api/v2";
        private const string acceptType = "application/json";

        // GET: Stitchz
        public ActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> GetSettings()
        {
            string body = "Failed... No Access Token Found!";
            string url = string.Format("{0}/settings", host);
            string accessToken = ExtractTokenFromClaim((User as ClaimsPrincipal));

            using (var hc = new HttpClient(new AuthenticationHeaderDelegatingHandler(accessToken) {
                    InnerHandler = new AcceptHeaderDelegatingHandler(acceptType) {
                        InnerHandler = new HttpClientHandler()}}))
            {
                // send the OAuth request
                HttpResponseMessage apiResponse = await hc.GetAsync(url, CallCancelled);
                apiResponse.EnsureSuccessStatusCode();
                body = await apiResponse.Content.ReadAsStringAsync();
            }

            return View((object)body);
        }

        public async Task<ActionResult> GetLoginTotals()
        {
            string body = "Failed... No Access Token Found!";
            string url = string.Format("{0}/logintotal", host);
            string accessToken = ExtractTokenFromClaim((User as ClaimsPrincipal));

            using (var hc = new HttpClient(new AuthenticationHeaderDelegatingHandler(accessToken) {
                InnerHandler = new AcceptHeaderDelegatingHandler(acceptType) {
                    InnerHandler = new HttpClientHandler()}}))
            {
                // send the OAuth request
                HttpResponseMessage apiResponse = await hc.GetAsync(url, CallCancelled);
                apiResponse.EnsureSuccessStatusCode();
                body = await apiResponse.Content.ReadAsStringAsync();
            }

            return View((object)body);
        }

        public async Task<ActionResult> GetFollowers()
        {
            string body = "Failed... No Access Token Found!";
            string url = string.Format("{0}/followers?identity={1}", host, identity);
            string accessToken = ExtractTokenFromClaim((User as ClaimsPrincipal));

            using (var hc = new HttpClient(new AuthenticationHeaderDelegatingHandler(accessToken)
            {
                InnerHandler = new AcceptHeaderDelegatingHandler(acceptType)
                {
                    InnerHandler = new HttpClientHandler()
                }
            }))
            {
                // send the OAuth request
                HttpResponseMessage apiResponse = await hc.GetAsync(url, CallCancelled);
                apiResponse.EnsureSuccessStatusCode();
                body = await apiResponse.Content.ReadAsStringAsync();
            }

            return View((object)body);
        }

        public async Task<ActionResult> GetActivities()
        {
            string body = "Failed... No Access Token Found!";
            string url = string.Format("{0}/activities?identity={1}", host, identity);
            string accessToken = ExtractTokenFromClaim((User as ClaimsPrincipal));

            using (var hc = new HttpClient(new AuthenticationHeaderDelegatingHandler(accessToken)
            {
                InnerHandler = new AcceptHeaderDelegatingHandler(acceptType)
                {
                    InnerHandler = new HttpClientHandler()
                }
            }))
            {
                // send the OAuth request
                HttpResponseMessage apiResponse = await hc.GetAsync(url, CallCancelled);
                apiResponse.EnsureSuccessStatusCode();
                body = await apiResponse.Content.ReadAsStringAsync();
            }

            return View((object)body);
        }

        public async Task<ActionResult> GetActivity(string id)
        {
            string body = "Failed... No Access Token Found!";
            string url = string.Format("{0}/activity/{1}?identity={2}", host, id, identity);
            string accessToken = ExtractTokenFromClaim((User as ClaimsPrincipal));

            using (var hc = new HttpClient(new AuthenticationHeaderDelegatingHandler(accessToken)
            {
                InnerHandler = new AcceptHeaderDelegatingHandler(acceptType)
                {
                    InnerHandler = new HttpClientHandler()
                }
            }))
            {
                // send the OAuth request
                HttpResponseMessage apiResponse = await hc.GetAsync(url, CallCancelled);
                apiResponse.EnsureSuccessStatusCode();
                body = await apiResponse.Content.ReadAsStringAsync();
            }

            return View((object)body);
        }

        private CancellationToken _callCancelled = new CancellationToken();
        private CancellationToken CallCancelled
        {
            get { return _callCancelled; }
            set { _callCancelled = value; }
        }

        private string ExtractTokenFromClaim(ClaimsPrincipal principal)
        {
            string accessToken = string.Empty;
            var tokenClaim = principal.Claims.FirstOrDefault(claim => claim.Type == "urn:stitchz:token");

            if (tokenClaim != null)
            {
                accessToken = tokenClaim.Value;
            }

            return accessToken;
        }
    }

    /// <summary>
    /// Adds the "Bearer" header to the outgoing OAuth2 request
    /// </summary>
    internal class AuthenticationHeaderDelegatingHandler : DelegatingHandler
    {
        public string AccessToken { get; set; }

        public AuthenticationHeaderDelegatingHandler(string accessToken)
        {
            this.AccessToken = accessToken;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", this.AccessToken);

            return base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>
    /// Adds the acceptable Content Type header to the outgoing request
    /// </summary>
    internal class AcceptHeaderDelegatingHandler : DelegatingHandler
    {
        public string MediaType { get; set; }

        public AcceptHeaderDelegatingHandler(string mediaType)
        {
            this.MediaType = mediaType;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaType));

            return base.SendAsync(request, cancellationToken);
        }
    }
}