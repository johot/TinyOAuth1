# TinyOAuth 1

## What is TinyOAuth1?
A tiny, super easy to use OAuth 1.0a library with support for the full OAuth flow. Supports both **.NET Framework** and **.NET Core** (by using .NET Standard)!

## Why?
I had to make an API integration against a service provider that still used OAuth 1.0(a) for authorization. I didn't find very many good, easy to use, well documented and small OAuth 1.0a libraries for .NET so I created TinyOAuth1.

## How does OAuth 1.0a work?
Here's a short explanation of how OAuth 1.0a works and a couple of links with great information.

### A short explanation
OAuth is used to access protected resources, in most cases an API endpoint. The goal of the OAuth 1.0a authorization flow is to get hold of an _access token_ and an _access token secret_. When we have these pieces of information we can generate an `Authorization: OAuth ...` header that gets included in every API call. When this header contains the correct information the service provider of the API will let our requests come through.

#### First time authorization (getting the access tokens)
Before starting the authorization flow you will have been given a `consumer key` and `consumer secret` from the service provider. You have also been given three different urls, the `requst token url`, the `authorize token url` and the `access token url`.
* You start by request a request token.
* A request token and request token secret are returned.
* Using the request token you generate an authorization url.
* You navigate to this url and enter any details, in many cases it's a simple confirm page. It may (or should in the case of 1.0a) also contain a verification code which you take note of.
  > When completing this page your request token is basically authorized and can be used in the next step.
* By using your request token, request token secret and verification code you request an access token.
* An access token and access token secret are returned (!), you can now start making API calls, keep on reading.

#### Save tokens
Once we have gotten hold of the access token and access token secret we can start making API calls, but before doing this we want to do one more thing:
* Save the access token and access token secret somewhere (safe)
> It's up to you to solve this part. The library has no opinion (or functionality) about how to do this.

We don't want the users to go through the authorization flow each time so by saving this information a returning user can get back to work right away since we can skip the whole "First time authorization" step.

#### Making API calls
To make API calls we must construct an `Authorization: OAuth ...` header and include it with every API call. This header has a timestamp and oauth_nonce part which means it changes slightly on every API call (for security reasons).

Here's an example header:

```
Authorization: OAuth realm="http://sp.example.com/",
               oauth_consumer_key="0685bd9184jfhq22",
               oauth_token="ad180jjd733klru7",
               oauth_signature_method="HMAC-SHA1",
               oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
               oauth_timestamp="137131200",
               oauth_nonce="4572616e48616d6d65724c61686176",
               oauth_version="1.0"
```

Once the correct header is included you API calls should hopefully come through! Keep reading for code samples.

### The reference that was used when building this library:
* https://oauth.net/core/1.0a/
> In the code comments have been added pointing to different chapters of this documentation.

### More reading:
* https://oauth1.wp-api.org/docs/basics/Auth-Flow.html
* https://www.cubrid.org/blog/dancing-with-oauth-understanding-how-authorization-works
* http://oauthbible.com/


## How do I use this library?
Here's a full sample that goes through the steps listed in the **How does OAuth 1.0a work?** chapter.

### First time authorization (getting the access tokens)
> Note that once you have saved your access token and access token secret you can skip this step and move directly to **Making API calls**.
```cs
// *** Check if we have saved tokens already, if not do the following: ***

// Set up the basic config parameters
var config = new TinyOAuthConfig
{
    AccessTokenUrl = "https://api.provider.com/oauth/accessToken",
    AuthorizeTokenUrl = "https://api.provider.com/oauth/authorize",
    RequestTokenUrl = "https://api.provider.com/oauth/requestToken",
    ConsumerKey = "CONSUMER_KEY",
    ConsumerSecret = "CONSUMER_SECRET"
};

// Use the library
var tinyOAuth = new TinyOAuth(config);

// Get the request token and request token secret
var requestTokenInfo = await tinyOAuth.GetRequestToken();

// Construct the authorization url
var authorizationUrl = tinyOAuth.GetAuthorizationUrl(requestTokenInfo.RequestToken);

// *** You will need to implement these methods yourself ***
await LaunchWebBrowser(url); // Use Process.Start(url), LaunchUriAsync(new Uri(url)) etc...
var verificationCode = await InputVerificationCode(url);

// *** Important: Do not run this code before visiting and completing the authorization url ***
var accessTokenInfo = await tinyOAuth.GetAccessToken(requestTokenInfo.RequestToken, requestTokenInfo.RequestTokenSecret,
	verificationCode);

HttpClient httpClient =
	new HttpClient(new TinyOAuthMessageHandler(config, accessTokenInfo.AccessToken, accessTokenInfo.AccessTokenSecret));

var resp = await httpClient.GetAsync("http://api.telldus.com/json/device/turnOn?id=1283446");
string respJson = await resp.Content.ReadAsStringAsync();
```

### Save tokens
```cs
// Implement this any way you see fit but remember to keep these safe or anyone can make API calls on behalf of the user
```

### Making API calls
To make API calls we need to create an `Authorization: OAuth ...` header and use it in every API call. There are two good ways of doing this that this library supports
* Use the included HttpClient message handler that automatically generates and inserts the header on each API call (recommended)
* Manually generate and insert the header for each request

#### Using the `TinyOAuthMessageHandler` (recommended)
Will automatically generate and insert the header on each API call.
```cs
HttpClient httpClient =
	new HttpClient(new TinyOAuthMessageHandler(config, accessTokenInfo.AccessToken, accessTokenInfo.AccessTokenSecret));

// Now we just use the HttpClient like normally
var resp = await httpClient.GetAsync("http://api.provider.com/something/resource?id=12345");
string respJson = await resp.Content.ReadAsStringAsync();
```

#### Manually generating and inserting header
```cs
HttpRequestMessage requestMsg = new HttpRequestMessage();
requestMsg.Method = new HttpMethod("GET");
requestMsg.RequestUri = new Uri("http://api.provider.com/something/resource?id=12345");
requestMsg.Headers.Authorization = tinyOAuth.GetAuthorizationHeader(...);
var resp = await httpClient.SendAsync(requestMsg);
string respJson = await resp.Content.ReadAsStringAsync();
```