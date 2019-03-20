using System.Collections.Generic;

namespace TinyOAuth1
{
	public class AccessTokenInfo
	{
		public string AccessToken { get; set; }
		public string AccessTokenSecret { get; set; }
		public IDictionary<string, string> AdditionalParams { get; set; }
	}
}