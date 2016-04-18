%%%-----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmail.com>
%%% @doc
%%% Erlang library for Twitter REST API v1.1
%%% @end
%%%-----------------------------------------------------------------------------
-module(yatael).

-behaviour(gen_server).

%% API
-export([  request_token/1
         , get_authorize_url/0
         , get_access_token/2
         , unauthorize/0
         , set_oauth_credentials/1
         , set_oauth_credentials/2
         , get_oauth_credentials/0

         , verify_credentials/1
         , get_timeline/0
         , get_timeline/1
         , lookup_status/1

         , start_link/0
         , start_link/2
         , stop/0
        ]).

%% Exported for testing
-export([get_url/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Types
-type headers()    :: list({string(), any()}).
-type payload()    :: map() | list(map()).
-type response()   :: {ok, headers(), payload()} | {ok, payload()}
                    | {error, headers(), term()}.
-type query_args() :: list({atom(), any()}).

-define(SERV,     ?MODULE).
-define(TIMEOUT,  1200000).

-define(API_URL,  "https://api.twitter.com/1.1/").
-define(AUTH_URL, "https://api.twitter.com/oauth/").

-record(state, {oauth_creds = #{} :: map()}).

%%%=============================================================================
%%% API
%%%=============================================================================
-spec request_token(string() | binary()) -> ok | no_return().
request_token(CallbackURI) ->
    gen_server:call(?SERV, {request_token, CallbackURI}, ?TIMEOUT).

-spec get_authorize_url() -> {ok, binary()} | no_return().
get_authorize_url() ->
    gen_server:call(?SERV, get_authorize_url, ?TIMEOUT).

-spec get_access_token(binary(), binary()) -> ok | {error, term()}.
get_access_token(OAuthToken, OAuthVerifier) ->
    gen_server:call(?SERV, {get_access_token, OAuthToken, OAuthVerifier},
                    ?TIMEOUT).

-spec unauthorize() -> ok | no_return().
unauthorize() ->
    gen_server:cast(?SERV, unauthorize).

-spec set_oauth_credentials(map()) -> ok | no_return().
set_oauth_credentials(Creds) ->
    gen_server:call(?SERV, {set_oauth_credentials, Creds}).

-spec set_oauth_credentials(binary(), binary()) -> ok | no_return().
set_oauth_credentials(ConsumerKey, ConsumerSecret) ->
    gen_server:call(?SERV, {set_oauth_credentials, ConsumerKey, ConsumerSecret},
                    ?TIMEOUT).

-spec get_oauth_credentials() -> {ok, map()} | no_return().
get_oauth_credentials() ->
    gen_server:call(?SERV, get_oauth_credentials).

-spec verify_credentials(query_args()) -> response().
verify_credentials(Args) ->
    gen_server:call(?SERV, {verify_credentials, Args}, ?TIMEOUT).

-spec get_timeline() -> response().
get_timeline() ->
    gen_server:call(?SERV, home_timeline, ?TIMEOUT).

-spec get_timeline(binary()) -> response().
get_timeline(Name) ->
    gen_server:call(?SERV, {user_timeline, Name}, ?TIMEOUT).

-spec lookup_status(query_args()) -> response().
lookup_status(Args) ->
    gen_server:call(?SERV, {lookup_status, Args}, ?TIMEOUT).

%% @doc Start an acquirer API service.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERV}, ?MODULE, [], []).

%% @doc Start an acquirer API service with credentials.
-spec start_link(string(), string()) -> {ok, pid()} | {error, term()}.
start_link(ConsumerKey, ConsumerSecret) ->
    gen_server:start_link({local, ?SERV}, ?MODULE,
                          [ConsumerKey, ConsumerSecret], []).

%% @doc Stop an acquirer API service.
-spec stop() -> ok.
stop() ->
    gen_server:cast(?SERV, stop).

%%==============================================================================
%% gen_server callbacks
%%==============================================================================
init([ConsumerKey, ConsumerSecret]) ->
  {ok, #state{oauth_creds = #{<<"consumer_key">>    => to_binary(ConsumerKey),
                              <<"consumer_secret">> => to_binary(ConsumerSecret)
                             }}};
init([]) ->
    {ok, #state{}}.

handle_call({request_token, CallbackUri}, _From,
            #state{oauth_creds = Creds} = State) ->
    Response = call_api(request_token, CallbackUri, Creds),
    error_logger:info_msg("yatael.request_token=~p", [Response]),
    Updates = #{<<"callback_uri">>        =>
                    to_binary(CallbackUri),
                <<"access_token">>        =>
                    to_binary(oauth:token(Response)),
                <<"access_token_secret">> =>
                    to_binary(oauth:token_secret(Response))},
    {reply, ok, State#state{oauth_creds = maps:merge(Creds, Updates)}};
handle_call(get_authorize_url, _From, #state{oauth_creds = Creds} = State) ->
    AuthenticateUrl = build_url(
                        authorize,
                        [{oauth_token, maps:get(<<"access_token">>, Creds)}]),
    {reply, {ok, to_binary(AuthenticateUrl)}, State};
handle_call({get_access_token, OAuthToken, OAuthVerifier}, _From,
            #state{oauth_creds = Creds} = State) ->
    Updates = call_api(access_token, {OAuthToken, OAuthVerifier}, Creds),
    case is_map(Updates) of
        true ->
            error_logger:info_msg("yatael.access_token=~p", [Updates]),
            {reply, ok, State#state{oauth_creds = maps:merge(Creds, Updates)}};
        false ->
            {reply, Updates, State}
    end;
handle_call({set_oauth_credentials, Map}, _From,
            #state{oauth_creds = Creds} = State) when is_map(Map) ->
    {reply, ok, State#state{oauth_creds = maps:merge(Creds, Map)}};
handle_call({set_oauth_credentials, ConsumerKey, ConsumerSecret}, _From, State) ->
    Creds = #{<<"consumer_key">>    => ConsumerKey,
              <<"consumer_secret">> => ConsumerSecret},
    {reply, ok, State#state{oauth_creds = Creds}};
handle_call(get_oauth_credentials, _From, State) ->
    {reply, {ok, State#state.oauth_creds}, State};
handle_call({verify_credentials, Args}, _From,
            #state{oauth_creds = Creds} = State) ->
    case call_api(verify_credentials, Args, Creds) of
        {ok, _Headers, Body}  ->
            {reply, {ok, Body}, State};
        Error ->
            {reply, Error, State}
    end;
handle_call(home_timeline, _From,
            #state{oauth_creds = Creds} = State) ->
    {reply, call_api(home_timeline, [], Creds), State};
handle_call({user_timeline, Name}, _From,
            #state{oauth_creds = Creds} = State) ->
    {reply, call_api(user_timeline, [{screen_name, Name}], Creds), State};
handle_call({lookup_status, Args}, _From,
            #state{oauth_creds = Creds} = State) ->
    {reply, call_api(lookup_status, Args, Creds), State};
handle_call(Request, _From, State) ->
    {reply, {unknown_request, Request}, State}.

handle_cast(unauthorize, State) ->
    {noreply, State#state{oauth_creds = maps:new()}};
handle_cast(stop, State) ->
    {stop, normal, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(normal, _State) ->
    ok.

%%%=============================================================================
%%% Internal functionality
%%%=============================================================================
call_api(request_token = UrlType, Args, Map) ->
    {ok, Response} = oauth:post(
                       get_url(UrlType),
                       [{oauth_callback, Args}], get_consumer(Map)),
    oauth:params_decode(Response);
call_api(access_token = UrlType, {OAuthToken, OAuthVerifier}, Map) ->
    EndpointURI = get_url(UrlType),
    Args = [{oauth_verifier, to_list(OAuthVerifier)}],
    OAuthSecretToken = maps:get(<<"access_token">>, Map, undefined),
    case OAuthSecretToken =:= undefined of
        true ->
            {error, missing_access_token};
        false ->
            {ok, Response} = oauth:post(EndpointURI, Args, get_consumer(Map),
                                        to_list(OAuthToken),
                                        to_list(OAuthSecretToken)),
            AccessParams = oauth:params_decode(Response),
            NewMap = #{<<"access_token">> =>
                           to_binary(oauth:token(AccessParams)),
               <<"access_token_secret">>  =>
                           to_binary(oauth:token_secret(AccessParams))},
            maps:merge(Map, NewMap)
    end;
call_api(UrlType, Args, Map) ->
    EndpointURI       = get_url(UrlType),
    AccessToken       = maps:get(<<"access_token">>, Map, undefined),
    AccessTokenSecret = maps:get(<<"access_token_secret">>, Map, undefined),
    case {AccessToken, AccessTokenSecret} of
        {undefined, undefined} ->
            {error, missing_credentials};
        {_, undefined} ->
            {error, missing_credentials};
        {undefined, _} ->
            {error, missing_credentials};
        _ ->
            case oauth:get(EndpointURI, Args, get_consumer(Map), AccessToken,
                           AccessTokenSecret) of
                {ok, {{_HTTPVersion, 200, _Status}, Headers, Body}} ->
                    {ok, Headers, parse_json(Body)};
                {ok, {{_HTTPVersion, Code, _Status}, Headers, Body}} ->
                    case Code < 400 of
                        true ->
                            {ok, Headers, parse_json(Body)};
                        false ->
                            {error, Headers, parse_json(Body)}
                    end;
                {error, Reason} ->
                    {error, [], Reason}
            end
    end.

get_consumer(Map) ->
    {maps:get(<<"consumer_key">>, Map),
     maps:get(<<"consumer_secret">>, Map), hmac_sha1}.

parse_json(Response) ->
    jiffy:decode(unicode:characters_to_binary(Response), [return_maps]).

build_url(UrlType, Args) ->
    get_url(UrlType) ++ "?" ++ flatten_args(Args).

flatten_args(Args) ->
    string:join(
      [http_uri:encode(to_list(K)) ++ "=" ++ http_uri:encode(to_list(V))
       || {K,V} <- Args], "&").

get_url(request_token) ->
    ?AUTH_URL ++ "request_token";
get_url(authorize) ->
    ?AUTH_URL ++ "authorize";
get_url(access_token) ->
    ?AUTH_URL ++ "access_token";
get_url(verify_credentials) ->
    ?API_URL ++ "account/verify_credentials.json";
get_url(home_timeline) ->
    ?API_URL ++ "statuses/home_timeline.json";
get_url(user_timeline) ->
    ?API_URL ++ "statuses/user_timeline.json";
get_url(lookup_status) ->
    ?API_URL ++ "statuses/lookup.json".


-spec to_binary(list() | binary()) -> binary().
to_binary(L) when is_list(L) ->
    list_to_binary(L);
to_binary(B) when is_binary(B) ->
   B.

-spec to_list(list() | binary() | atom() | integer()) -> list().
to_list(Val) when is_integer(Val) ->
    integer_to_list(Val);
to_list(Value) when is_atom(Value) ->
    atom_to_list(Value);
to_list(Value) when is_binary(Value) ->
    binary_to_list(Value);
to_list(Val) ->
    Val.
