using System.Net.Http;
using System.Threading.Tasks;

namespace TinyOAuth1
{
	public class TinyOAuthMessageHandler : DelegatingHandler
	{
		private string _accessToken;
		private string _accessTokenSecret;
		private TinyOAuth _tinyOAuth;

		public TinyOAuthMessageHandler(TinyOAuthConfig config, string accessToken, string accessTokenSecret)
			: this(config, accessToken, accessTokenSecret, new HttpClientHandler())
		{
		}

		public TinyOAuthMessageHandler(TinyOAuthConfig config, string accessToken, string accessTokenSecret, HttpMessageHandler handler)
			: base(handler)
		{
			this._tinyOAuth = new TinyOAuth(config);
			this._accessTokenSecret = accessTokenSecret;
			this._accessToken = accessToken;
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
