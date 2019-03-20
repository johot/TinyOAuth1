using System.Collections.Generic;
using System.Collections.Specialized;

namespace TinyOAuth1.Utility
{
	internal static class NameValueCollectionExtensions
	{
		internal static IDictionary<string, string> ToDictionary(this NameValueCollection col)
		{
			var dict = new Dictionary<string, string>();
			foreach (var k in col.AllKeys)
			{
				dict.Add(k, col[k]);
			}
			return dict;
		}
	}
}