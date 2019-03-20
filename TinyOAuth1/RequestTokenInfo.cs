using System.Collections.Generic;

namespace TinyOAuth1
{
	public class RequestTokenInfo
	{
		public string RequestToken { get; set; }
		public string RequestTokenSecret { get; set; }
		public IDictionary<string, string> AdditionalParams { get; set; }
	}
}