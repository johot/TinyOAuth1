namespace TinyOAuth1
{
	public class TinyOAuthConfig
	{
		/* 4.2.  Service Providers

		The Service Provider's responsibility is to enable Consumer Developers to establish a Consumer Key and Consumer Secret. The process and requirements for provisioning these are entirely up to the Service Providers.
		*/

		public string ConsumerKey { get; set; }
		public string ConsumerSecret { get; set; }

		/* 4.1.  Request URLs

		OAuth defines three request URLs:

		Request Token URL:
		The URL used to obtain an unauthorized Request Token, described in Section 6.1.
		User Authorization URL:
		The URL used to obtain User authorization for Consumer access, described in Section 6.2.
		Access Token URL:
		The URL used to exchange the User-authorized Request Token for an Access Token, described in Section 6.3.
		The three URLs MUST include scheme, authority, and path, and MAY include query and fragment as defined by [RFC3986] section 3. The request URL query MUST NOT contain any OAuth Protocol Parameters. For example:
*/
		public string AccessTokenUrl { get; set; }
		public string AuthorizeTokenUrl { get; set; }
		public string RequestTokenUrl { get; set; }
		public string SignatureMethod { get; set; } = "HMAC-SHA1";
		public string SigningKey { get; set; }
	}
}