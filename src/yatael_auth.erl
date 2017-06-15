%%%----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmail.com>
%%% @doc
%%% Authentification helper for Twitter REST API v1.1
%%% @end
%%%----------------------------------------------------------------------------
-module(yatael_auth).

%% API
-export([ authorize/1
        , unauthorize/0
        ]).

%%%============================================================================
%%% API
%%%============================================================================
-spec authorize(map()) -> {ok, map()} | {error, term()}.
authorize(Map) ->
    AccessToken = get_oauth_token(Map),
    Verifier    = get_oauth_verifier(Map),
    CallbackURI = get_callback_uri(Map),
    case has_access_token(AccessToken, Verifier) of
        false ->
            maybe_request_tokens(CallbackURI);
        true ->
            case yatael:get_access_token(AccessToken, Verifier) of
                ok ->
                    yatael:verify_credentials([{skip_status, true}]);
                Error ->
                    Error
            end
    end.

-spec unauthorize() -> ok | no_return().
unauthorize() ->
    yatael:unauthorize().

%%%============================================================================
%%% Internal functions
%%%============================================================================
has_access_token(undefined, undefined) ->
    false;
has_access_token(_AccessToken, _Verifier) ->
    true.

maybe_request_tokens(undefined) ->
    {error, missing_callback_uri};
maybe_request_tokens(CallbackURI) ->
    ok = yatael:request_token(CallbackURI),
    {ok, Creds} = yatael:get_oauth_credentials(),
    {ok, #{<<"oauth_token">> => maps:get(<<"access_token">>, Creds)}}.

get_oauth_token(Map) ->
    get_value(<<"oauth_token">>, Map).

get_oauth_verifier(Map) ->
    get_value(<<"oauth_verifier">>, Map).

get_callback_uri(Map) ->
    get_value(<<"callback_uri">>, Map).

get_value(Key, Map) ->
    maps:get(Key, Map, undefined).
