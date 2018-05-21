%%%----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmail.com>
%%% @doc
%%% Authentification helper for Twitter REST API v1.1
%%% @end
%%%----------------------------------------------------------------------------
-module(yatael_auth).

%% API
-export([ authorize/2
        , unauthorize/1
        ]).

%%%============================================================================
%%% API
%%%============================================================================
-spec authorize(pid(), map()) -> {ok, map()} | {error, term()}.
authorize(Pid, Map) ->
  AccessToken = get_oauth_token(Map),
  Verifier    = get_oauth_verifier(Map),
  CallbackURI = get_callback_uri(Map),
  case has_access_token(AccessToken, Verifier) of
    false ->
      maybe_request_tokens(Pid, CallbackURI);
    true ->
      case yatael:get_access_token(Pid, AccessToken, Verifier) of
        ok ->
          yatael:verify_credentials(Pid, [{skip_status, true}]);
        Error ->
          Error
      end
  end.

-spec unauthorize(pid()) -> ok | no_return().
unauthorize(Pid) ->
  yatael:unauthorize(Pid).

%%%============================================================================
%%% Internal functions
%%%============================================================================
has_access_token(undefined, undefined) ->
  false;
has_access_token(_AccessToken, _Verifier) ->
  true.

maybe_request_tokens(_Pid, undefined) ->
  {error, missing_callback_uri};
maybe_request_tokens(Pid, CallbackURI) ->
  ok = yatael:request_token(Pid, CallbackURI),
  case yatael:get_oauth_credentials(Pid) of
    {ok, Creds} when map_size(Creds) >= 1 ->
      {ok, #{<<"oauth_token">> => maps:get(<<"access_token">>, Creds)}};
    _Other ->
      {error, missing_credentials}
  end.

get_oauth_token(Map) ->
  get_value(<<"oauth_token">>, Map).

get_oauth_verifier(Map) ->
  get_value(<<"oauth_verifier">>, Map).

get_callback_uri(Map) ->
  get_value(<<"callback_uri">>, Map).

get_value(Key, Map) ->
  maps:get(Key, Map, undefined).
