using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TinyOAuth1
{
	//https://oauth.net/core/1.0a/
	//https://oauth1.wp-api.org/docs/basics/Auth-Flow.html
	public class TinyOAuth : ITinyOAuth
	{
		private readonly TinyOAuthConfig _config;

		public TinyOAuth(TinyOAuthConfig config)
		{
			_config = config;
		}

		//6.2.1. Consumer Directs the User to the Service Provider
		public string GetAuthorizationUrl(string requestToken)
		{
			// TODO: Add 
			//oauth_callback:
			//OPTIONAL.The Consumer MAY specify a URL the Service Provider will use to redirect the User back to the Consumer when Obtaining User Authorization is complete.

			string url = $"{_config.AuthorizeTokenUrl}?{Uri.UnescapeDataString($"oauth_token={requestToken}")}";

			if (!String.IsNullOrWhiteSpace(_config.OauthCallback))
			{
				url += $"&{Uri.UnescapeDataString($"oauth_callback={_config.OauthCallback}")}";
			}

			return url;
		}

		private string GetNonce()
		{
			var rand = new Random();
			var nonce = rand.Next(1000000000);
			return nonce.ToString();
		}

		private string GetTimeStamp()
		{
			var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			return Convert.ToInt64(ts.TotalSeconds).ToString();
		}

		private Dictionary<string, string> ExtractQueryParameters(string queryString)
		{
			if (queryString.StartsWith("?"))
				queryString = queryString.Remove(0, 1);

			var result = new Dictionary<string, string>();

			if (string.IsNullOrEmpty(queryString))
				return result;

			foreach (var s in queryString.Split('&'))
				if (!string.IsNullOrEmpty(s) && !s.StartsWith("oauth_"))
					if (s.IndexOf('=') > -1)
					{
						var temp = s.Split('=');
						result.Add(temp[0], temp[1]);
					}
					else
					{
						result.Add(s, string.Empty);
					}

			return result;
		}

		private string GetNormalizedUrl(Uri uri)
		{
			var normUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);
			if (!(uri.Scheme == "http" && uri.Port == 80 ||
				  uri.Scheme == "https" && uri.Port == 443))
				normUrl += ":" + uri.Port;

			normUrl += uri.AbsolutePath;

			return normUrl;
		}

		public AuthenticationHeaderValue GetAuthorizationHeader(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod)
		{
			return new AuthenticationHeaderValue("OAuth", GetAuthorizationHeaderValue(accessToken, accessTokenSecret, url, httpMethod));
		}

		public string GetAuthorizationHeaderValue(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod)
		{
			/*5.2.  Consumer Request Parameters

			OAuth Protocol Parameters are sent from the Consumer to the Service Provider in one of three methods, in order of decreasing preference:

			In the HTTP Authorization header as defined in OAuth HTTP Authorization Scheme.
			As the HTTP POST request body with a content-type of application/x-www-form-urlencoded.
			Added to the URLs in the query part (as defined by [RFC3986] section 3).
			In addition to these defined methods, future extensions may describe alternate methods for sending the OAuth Protocol Parameters. The methods for sending other request parameters are left undefined, but SHOULD NOT use the OAuth HTTP Authorization Scheme header.

      		*/

			/* 5.4.1.  Authorization Header

			The OAuth Protocol Parameters are sent in the Authorization header the following way:

			Parameter names and values are encoded per Parameter Encoding.
			For each parameter, the name is immediately followed by an ‘=’ character (ASCII code 61), a ‘”’ character (ASCII code 34), the parameter value (MAY be empty), and another ‘”’ character (ASCII code 34).
			Parameters are separated by a comma character (ASCII code 44) and OPTIONAL linear whitespace per [RFC2617].
			The OPTIONAL realm parameter is added and interpreted per [RFC2617], section 1.2.
			For example:

			Authorization: OAuth realm="http://sp.example.com/",
			oauth_consumer_key="0685bd9184jfhq22",
			oauth_token="ad180jjd733klru7",
			oauth_signature_method="HMAC-SHA1",
			oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
			oauth_timestamp="137131200",
			oauth_nonce="4572616e48616d6d65724c61686176",
			oauth_version="1.0"
			
			*/

			var nonce = GetNonce();
			var timeStamp = GetTimeStamp();

			var requestParameters = new List<string>
			{
				"oauth_consumer_key=" + _config.ConsumerKey,
				"oauth_token=" + accessToken,
				"oauth_signature_method=" + _config.SignatureMethod,
				"oauth_timestamp=" + timeStamp,
				"oauth_nonce=" + nonce,
				"oauth_version=1.0"
			};

			var requestUri = new Uri(url, UriKind.Absolute);

			if (!string.IsNullOrWhiteSpace(requestUri.Query))
			{
				var parameters = ExtractQueryParameters(requestUri.Query);

				foreach (var kvp in parameters)
					requestParameters.Add(kvp.Key + "=" + kvp.Value);

				// TODO: url = GetNormalizedUrl(requestUri);
			}

			// Appendix A.5.1. Generating Signature Base String
			var signatureBaseString = GetSignatureBaseString(httpMethod.ToString().ToUpper(), url, requestParameters);

			// Appendix A.5.2. Calculating Signature Value
			string signature = String.Empty;
			if (_config.SignatureMethod.ToLower().Contains("rsa"))
			{
				signature = GetRSASignature(signatureBaseString, _config.SigningKey);
			}
			else
			{
				signature = GetSignature(signatureBaseString, _config.ConsumerSecret, accessTokenSecret);
			}

			// Same as request parameters but uses a quote (") character around its values and is comma separated
			var requestParametersForHeader = new List<string>
			{
				"oauth_consumer_key=\"" + _config.ConsumerKey + "\"",
				"oauth_token=\"" + accessToken + "\"",
				"oauth_signature_method=\"" + _config.SignatureMethod + "\"",
				"oauth_timestamp=\"" + timeStamp + "\"",
				"oauth_nonce=\"" + nonce + "\"",
				"oauth_version=\"1.0\"",
				"oauth_signature=\"" + Uri.EscapeDataString(signature) + "\""
			};

			return ConcatList(requestParametersForHeader, ",");
		}

		private async Task<string> PostData(string url, string postData)
		{
			try
			{
				var httpClient = new HttpClient();
				httpClient.MaxResponseContentBufferSize = int.MaxValue;
				httpClient.DefaultRequestHeaders.ExpectContinue = false;
				var requestMsg = new HttpRequestMessage();
				requestMsg.Content = new StringContent(postData);
				requestMsg.Method = new HttpMethod("POST");
				requestMsg.RequestUri = new Uri(url, UriKind.Absolute);
				requestMsg.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
				var response = await httpClient.SendAsync(requestMsg);
				return await response.Content.ReadAsStringAsync();
			}
			catch (Exception ex)
			{
				throw;
			}
		}

		private string GetSignature(string signatureBaseString, string consumerSecret, string tokenSecret = null)
		{
			/*9.2.  HMAC-SHA1

			The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104] where the Signature Base String is the text and the key is the concatenated values (each first encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&' character (ASCII code 38) even if empty.
			*/

			var hmacsha1 = new HMACSHA1();

			var key = Uri.EscapeDataString(consumerSecret) + "&" + (string.IsNullOrEmpty(tokenSecret)
						  ? ""
						  : Uri.EscapeDataString(tokenSecret));
			hmacsha1.Key = Encoding.ASCII.GetBytes(key);

			var dataBuffer = Encoding.ASCII.GetBytes(signatureBaseString);
			var hashBytes = hmacsha1.ComputeHash(dataBuffer);

			return Convert.ToBase64String(hashBytes);

			// .NET Core implementation
			// var signingKey = string.Format("{0}&{1}", consumerSecret, !string.IsNullOrEmpty(requestTokenSecret) ? requestTokenSecret : "");
			// IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(signingKey, BinaryStringEncoding.Utf8);
			// MacAlgorithmProvider hmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
			// CryptographicKey macKey = hmacSha1Provider.CreateKey(keyMaterial);
			// IBuffer dataToBeSigned = CryptographicBuffer.ConvertStringToBinary(signatureBaseString, BinaryStringEncoding.Utf8);
			// IBuffer signatureBuffer = CryptographicEngine.Sign(macKey, dataToBeSigned);
			// String signature = CryptographicBuffer.EncodeToBase64String(signatureBuffer);
			// return signature;
		}

		private string GetRSASignature(string stringToSign, string privateKey)
		{
			using (var reader = new StringReader(privateKey))
			{
				AsymmetricCipherKeyPair kp = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

				ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");

				signer.Init(true, kp.Private);

				var bytes = Encoding.UTF8.GetBytes(stringToSign);

				signer.BlockUpdate(bytes, 0, bytes.Length);
				byte[] signature = signer.GenerateSignature();

				return Convert.ToBase64String(signature);
			}
		}

		// 6.3.1. Consumer Requests an Access Token +
		// 6.3.2. Service Provider Grants an Access Token
		public async Task<AccessTokenInfo> GetAccessTokenAsync(string requestToken, string requestTokenSecret, string verifier)
		{
			/* 6.3.1.  Consumer Requests an Access Token
			
			The Request Token and Token Secret MUST be exchanged for an Access Token and Token Secret.
			To request an Access Token, the Consumer makes an HTTP request to the Service Provider's Access Token URL. The Service Provider documentation specifies the HTTP method for this request, and HTTP POST is RECOMMENDED. The request MUST be signed per Signing Requests, and contains the following parameters:

			oauth_consumer_key:			The Consumer Key.
			oauth_token:			The Request Token obtained previously.
			oauth_signature_method:			The signature method the Consumer used to sign the request.
			oauth_signature:			The signature as defined in Signing Requests.
			oauth_timestamp:			As defined in Nonce and Timestamp.
			oauth_nonce:			As defined in Nonce and Timestamp.
			oauth_version:			OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present. Service Providers' response to non-1.0 value is left undefined.
			oauth_verifier:			The verification code received from the Service Provider in the Service Provider Directs the User Back to the Consumer step.
			No additional Service Provider specific parameters are allowed when requesting an Access Token to ensure all Token related information is present prior to seeking User approval.
			*/

			var nonce = GetNonce();
			var timeStamp = GetTimeStamp();

			var requestParameters = new List<string>
			{
				"oauth_consumer_key=" + _config.ConsumerKey,
				"oauth_token=" + requestToken,
				"oauth_signature_method=" + _config.SignatureMethod,
				"oauth_timestamp=" + timeStamp,
				"oauth_nonce=" + nonce,
				"oauth_version=1.0",
				"oauth_verifier=" + verifier
			};

			// Appendix A.5.1. Generating Signature Base String
			var signatureBaseString = GetSignatureBaseString("POST", _config.AccessTokenUrl, requestParameters);

			// Appendix A.5.2. Calculating Signature Value
			string signature = String.Empty;
			if (_config.SignatureMethod.ToLower().Contains("rsa"))
			{
				signature = GetRSASignature(signatureBaseString, _config.SigningKey);
			}
			else
			{
				signature = GetSignature(signatureBaseString, _config.ConsumerSecret, requestTokenSecret);
			}

			var responseText =
				await
					PostData(_config.AccessTokenUrl,
						ConcatList(requestParameters, "&") + "&oauth_signature=" + Uri.EscapeDataString(signature));

			if (!responseText.ToLowerInvariant().Contains("oauth_token"))
				throw new Exception(@"An error occured when trying to retrieve access token, the response was: """ + responseText +
									@"""" + Environment.NewLine + Environment.NewLine +
									"Did you remember to navigate to and complete the authorization page?");

			if (!string.IsNullOrEmpty(responseText))
			{
				string oauthToken = null;
				string oauthTokenSecret = null;
				var keyValPairs = responseText.Split('&');

				for (var i = 0; i < keyValPairs.Length; i++)
				{
					var splits = keyValPairs[i].Split('=');
					switch (splits[0])
					{
						case "oauth_token":
							oauthToken = splits[1];
							break;
						case "oauth_token_secret":
							oauthTokenSecret = splits[1];
							break;
					}
				}

				return new AccessTokenInfo
				{
					AccessToken = oauthToken,
					AccessTokenSecret = oauthTokenSecret
				};
			}
			throw new Exception("Empty response text when getting the access token");
		}

		//6.1.1. Consumer Obtains a Request Token (https://oauth.net/core/1.0a/)
		public async Task<RequestTokenInfo> GetRequestTokenAsync()
		{
			/*6.1.1.  Consumer Obtains a Request Token

			To obtain a Request Token, the Consumer sends an HTTP request to the Service Provider's Request Token URL. The Service Provider documentation specifies the HTTP method for this request, and HTTP POST is RECOMMENDED. The request MUST be signed and contains the following parameters:

			oauth_consumer_key:			The Consumer Key.
			oauth_signature_method:			The signature method the Consumer used to sign the request.
			oauth_signature:			The signature as defined in Signing Requests.
			oauth_timestamp:			As defined in Nonce and Timestamp.
			oauth_nonce:			As defined in Nonce and Timestamp.
			oauth_version:			OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present. Service Providers' response to non-1.0 value is left undefined.
			oauth_callback:			An absolute URL to which the Service Provider will redirect the User back when the Obtaining User Authorization step is completed. If the Consumer is unable to receive callbacks or a callback URL has been established via other means, the parameter value MUST be set to oob (case sensitive), to indicate an out-of-band configuration.
			Additional parameters:
			Any additional parameters, as defined by the Service Provider. */

			var nonce = GetNonce();
			var timeStamp = GetTimeStamp();

			// See 6.1.1
			var requestParameters = new List<string>
			{
				"oauth_consumer_key=" + _config.ConsumerKey,
				"oauth_signature_method=" + _config.SignatureMethod,
				"oauth_timestamp=" + timeStamp,
				"oauth_nonce=" + nonce,
				"oauth_version=1.0",
				"oauth_callback=oob" //TODO: Add parameter so it can be used :)
			};

			// Appendix A.5.1. Generating Signature Base String
			var signatureBaseString = GetSignatureBaseString("POST", _config.RequestTokenUrl, requestParameters);

			// Appendix A.5.2. Calculating Signature Value
			string signature = String.Empty;
			if (_config.SignatureMethod.ToLower().Contains("rsa"))
			{
				signature = GetRSASignature(signatureBaseString, _config.SigningKey);
			}
			else
			{
				signature = GetSignature(signatureBaseString, _config.ConsumerSecret);
			}
			
			// 6.1.2.Service Provider Issues an Unauthorized Request Token
			var responseText = await PostData(_config.RequestTokenUrl,
				ConcatList(requestParameters, "&") + "&oauth_signature=" + Uri.EscapeDataString(signature));

			if (!string.IsNullOrEmpty(responseText))
			{
				//oauth_token:
				//The Request Token.
				//	oauth_token_secret:
				//The Token Secret.

				string oauthToken = null;
				string oauthTokenSecret = null;
				//string oauthAuthorizeUrl = null;

				var keyValPairs = responseText.Split('&');

				for (var i = 0; i < keyValPairs.Length; i++)
				{
					var splits = keyValPairs[i].Split('=');
					switch (splits[0])
					{
						case "oauth_token":
							oauthToken = splits[1];
							break;
						case "oauth_token_secret":
							oauthTokenSecret = splits[1];
							break;
							// TODO: Handle this one?
							//case "xoauth_request_auth_url":
							//	oauthAuthorizeUrl = splits[1];
							//	break;
					}
				}

				return new RequestTokenInfo
				{
					RequestToken = oauthToken,
					RequestTokenSecret = oauthTokenSecret
				};
			}
			throw new Exception("Empty response text when getting the request token");
		}

		private static string ConcatList(IEnumerable<string> source, string separator)
		{
			var sb = new StringBuilder();
			foreach (var s in source)
				if (sb.Length == 0)
				{
					sb.Append(s);
				}
				else
				{
					sb.Append(separator);
					sb.Append(s);
				}
			return sb.ToString();
		}

		private string GetSignatureBaseString(string method, string url, List<string> requestParameters)
		{
			// It's very important that we "normalize" the parameters, that is sort them:
			//9.1.1.Normalize Request Parameters

			//The request parameters are collected, sorted and concatenated into a normalized string:

			// * Parameters in the OAuth HTTP Authorization header excluding the realm parameter.
			// * Parameters in the HTTP POST request body(with a content - type of application / x - www - form - urlencoded).
			// * HTTP GET parameters added to the URLs in the query part(as defined by[RFC3986] section 3).
			var sortedList = new List<string>(requestParameters);
			sortedList.Sort();

			var requestParametersSortedString = ConcatList(sortedList, "&");

			// Url must be slightly reformatted because of:

			/*9.1.2. Construct Request URL

			The Signature Base String includes the request absolute URL, tying the signature to a specific endpoint. The URL used in the Signature Base String MUST include the scheme, authority, and path, and MUST exclude the query and fragment as defined by [RFC3986] section 3.

			If the absolute request URL is not available to the Service Provider (it is always available to the Consumer), it can be constructed by combining the scheme being used, the HTTP Host header, and the relative HTTP request URL. If the Host header is not available, the Service Provider SHOULD use the host name communicated to the Consumer in the documentation or other means.

			The Service Provider SHOULD document the form of URL used in the Signature Base String to avoid ambiguity due to URL normalization. Unless specified, URL scheme and authority MUST be lowercase and include the port number; http default port 80 and https default port 443 MUST be excluded.

			For example, the request:

							HTTP://Example.com:80/resource?id=123
			Is included in the Signature Base String as:

							http://example.com/resource
 */


			url = ConstructRequestUrl(url);

			return method.ToUpper() + "&" + Uri.EscapeDataString(url) + "&" +
				   Uri.EscapeDataString(requestParametersSortedString);
		}

		private string ConstructRequestUrl(string url)
		{
			var uri = new Uri(url, UriKind.Absolute);
			var normUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);
			if (!(uri.Scheme == "http" && uri.Port == 80 ||
				  uri.Scheme == "https" && uri.Port == 443))
				normUrl += ":" + uri.Port;

			normUrl += uri.AbsolutePath;

			return normUrl;
		}
	}
}