%%%----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmail.com>
%%% @doc
%%% Authentification helper for Twitter REST API v1.1 authorization
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
    AccessToken = maps:get(<<"oauth_token">>, Map, undefined),
    Verifier    = maps:get(<<"oauth_verifier">>, Map, undefined),
    CallbackURI = maps:get(<<"callback_uri">>, Map, undefined),
    case {AccessToken, Verifier} of
        {undefined, undefined} ->
            case CallbackURI =:= undefined of
                true ->
                    {error, missing_callback_uri};
                false ->
                    ok = yatael:request_token(CallbackURI),
                    {ok, Creds} = yatael:get_oauth_credentials(),
                    {ok, #{<<"oauth_token">> =>
                               maps:get(<<"access_token">>, Creds)}}
            end;
        {_, _} ->
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
