using System.Net.Http;
using System.Threading.Tasks;

namespace TinyOAuth1
{
	public class TinyOAuthMessageHandler : DelegatingHandler
	{
		private string _accessToken;
		private string _accessTokenSecret;
		private TinyOAuth _tinyOAuth;

		public TinyOAuthMessageHandler(TinyOAuthConfig config, string accessToken, string accessTokenSecret) : base(new HttpClientHandler())
		{
			_tinyOAuth = new TinyOAuth(config);
			_accessTokenSecret = accessTokenSecret;
			_accessToken = accessToken;
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
		{
			request.Headers.Authorization = _tinyOAuth.GetAuthorizationHeader(_accessToken, _accessTokenSecret,
				request.RequestUri.AbsoluteUri, request.Method);

			return base.SendAsync(request, cancellationToken);
		}
	}
}
