yatael
======

Yet Another [Twitter REST API][1] (v1.1) Erlang Library

Exported REST API Calls
===
* `verify_credentials/1`
* `get_timeline/0`
* `get_timeline/1`
* `get_mentions_timeline/1`
* `lookup_status/1`
* `search/1`

Besides REST API and Search API there is of coure support for OAuth and few related helper functions for easy signup integration.

## Dependencies
* Erlang (>= R17)
* [jiffy][2]

Fetch and compile all dependencies:
```bash
$ rebar get-deps compile
```

OAuth
===
https://dev.twitter.com/oauth

API Rate Limits
===
https://dev.twitter.com/rest/public/rate-limits
https://dev.twitter.com/rest/public/rate-limiting

Register your application
===

1. Sign in at https://apps.twitter.com
2. Click on Create New App
3. Enter your Application Name, Description and Website
4. For Callback URL: `http://127.0.0.1:3000`
5. Go to Settings tab
6. Under Application Type select Read and Write access
7. Check the box Allow this application to be used to Sign in with Twitter
8. Click Update this Twitter's applications settings
9. Obtain Consumer Key (API Key or ClientId) and Consumer Secret (API Secret)


Raw library usage
===
```erlang
1> ConsumerKey = <<"foo"">>,
2> ConsumerSecret = <<"bar"">>,
3> CallbackUri = <<"http://127.0.0.1/">>.
4> {ok, _Apps} = application:ensure_all_started(yatael).
5> {ok, _Pid} = yatael:start_link(ConsumerKey, ConsumerSecret).
6> ok = yatael:request_token(CallbackUri).
7> {ok, Url} = yatael:get_authorize_url().
```
Open `Url` value in brower and accept Twitter oAuth and extract following arguments
after sucessfull redirect to your `CallbackUri`:
```erlang
8> AccessToken = <<"foo2">>.
9> Verifier = <<"bar2">>.
10> ok = yatael:get_access_token(AccessToken, Verifier),
```
Now athentification is done and you can use supproted API calls:
```erlang
11> yatael:verify_credentials([{skip_status, true}]).
{ok,#{<<"contributors_enabled">> => false,
      <<"created_at">> => <<"Fri Jun 26 09:22:24 +0000 2009">>,
      <<"default_profile">> => false,
      <<"default_profile_image">> => false,
      ....
12> yatael:get_timeline().
      ....
13> yatael_auth:unauthorize().
ok
```

Auth helper usage
===
```erlang
1> ConsumerKey = <<"foo"">>,
2> ConsumerSecret = <<"bar"">>,
3> CallbackUri = <<"http://127.0.0.1/">>.
4> {ok, _Apps} = application:ensure_all_started(yatael).
5> {ok, _Pid} = yatael:start_link(ConsumerKey, ConsumerSecret).
6> ok = yatael:request_token(CallbackUri).
7> {ok, Url} = yatael:get_authorize_url().
8> Map = #{<<"oauth_token">> => <<"foo3">>, <<"oauth_verifier">> => <<"bar3">>, <<"callback_uri">> => CallbackUri}.
9> yatael_auth:authorize(Map).
{ok,#{<<"contributors_enabled">> => false,
      <<"created_at">> => <<"Fri Jun 26 09:22:24 +0000 2009">>,
      <<"default_profile">> => false,
      <<"default_profile_image">> => false,
      ....
10> yatael:get_timeline().
      ....
11> yatael_auth:unauthorize().
ok

```


[1]: https://dev.twitter.com/rest/public
[2]: https://github.com/davisp/jiffy
