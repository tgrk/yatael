%%%-----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmail.com>
%%% @doc
%%% Erlang library for Twitter REST API v1.1
%%% @end
%%%-----------------------------------------------------------------------------
-module(yatael).

-behaviour(gen_server).

%% API
-export([  request_token/2
         , get_authorize_url/1
         , get_access_token/3
         , unauthorize/1
         , set_oauth_credentials/2
         , set_oauth_credentials/3
         , get_oauth_credentials/1
         , verify_credentials/2

         , get_timeline/1
         , get_timeline/2
         , get_mentions_timeline/2
         , lookup_status/2
         , search/2

         , start_link/0
         , start_link/2
         , stop/1
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
-type query_args() :: list({atom(), any()}) | map().

-define(TIMEOUT,     1200000).
-define(API_URL,     "https://api.twitter.com/1.1/").
-define(AUTH_URL,    "https://api.twitter.com/oauth/").
-define(SEARCH_ARGS, [<<"q">>, <<"result_type">>, <<"geocode">>, <<"lang">>,
                      <<"count">>, <<"until">>, <<"since_id">>, <<"max_id">>
                     ]).

-record(state, {oauth_creds = #{} :: map()}).

%%%=============================================================================
%%% API
%%%=============================================================================
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
  gen_server:start_link({local, get_server_name()}, ?MODULE, [], []).

-spec start_link(string(), string()) -> {ok, pid()} | {error, term()}.
start_link(CKey, CSecret) ->
  gen_server:start_link({local, get_server_name()}, ?MODULE, [CKey, CSecret], []).

-spec stop(pid()) -> ok.
stop(Pid) ->
  gen_server:cast(Pid, stop).

%%%=============================================================================
%%% oAuth API
%%%=============================================================================
-spec request_token(pid(), string() | binary()) -> ok | {error, term()}.
request_token(Pid, CallbackURI) ->
  gen_server:call(Pid, {request_token, CallbackURI}, ?TIMEOUT).

-spec get_authorize_url(pid()) -> {ok, binary()} | no_return().
get_authorize_url(Pid) ->
  gen_server:call(Pid, get_authorize_url, ?TIMEOUT).

-spec get_access_token(pid(), binary(), binary()) -> ok | {error, term()}.
get_access_token(Pid, OAuthToken, OAuthVerifier) ->
  gen_server:call(Pid, {get_access_token, OAuthToken, OAuthVerifier}, ?TIMEOUT).

-spec unauthorize(pid()) -> ok | no_return().
unauthorize(Pid) ->
  gen_server:cast(Pid, unauthorize).

-spec set_oauth_credentials(pid(), map()) -> ok | no_return().
set_oauth_credentials(Pid, Creds) ->
  gen_server:call(Pid, {set_oauth_credentials, Creds}).

-spec set_oauth_credentials(pid(), binary(), binary()) -> ok | no_return().
set_oauth_credentials(Pid, CKey, CSecret) ->
  gen_server:call(Pid, {set_oauth_credentials, CKey, CSecret}, ?TIMEOUT).

-spec get_oauth_credentials(pid()) -> {ok, map()} | no_return().
get_oauth_credentials(Pid) ->
  gen_server:call(Pid, get_oauth_credentials).

-spec verify_credentials(pid(), query_args()) -> response().
verify_credentials(Pid, Args) ->
  gen_server:call(Pid, {verify_credentials, Args}, ?TIMEOUT).

%%%=============================================================================
%%% Data API
%%%=============================================================================
-spec get_timeline(pid()) -> response().
get_timeline(Pid) ->
  gen_server:call(Pid, home_timeline, ?TIMEOUT).

-spec get_timeline(pid(), binary()) -> response().
get_timeline(Pid, Name) ->
  gen_server:call(Pid, {user_timeline, Name}, ?TIMEOUT).

-spec get_mentions_timeline(pid(), query_args()) -> response().
get_mentions_timeline(Pid, Args) ->
  gen_server:call(Pid, {mentions_timeline, Args}, ?TIMEOUT).

-spec lookup_status(pid(), query_args()) -> response().
lookup_status(Pid, Args) ->
  gen_server:call(Pid, {lookup_status, Args}, ?TIMEOUT).

-spec search(pid(), query_args()) -> response().
search(Pid, Args) ->
  gen_server:call(Pid, {search, Args}, ?TIMEOUT).

%%==============================================================================
%% gen_server callbacks
%%==============================================================================
init([]) ->
  {ok, #state{}};
init([CKey, CSecret]) ->
  {ok, #state{oauth_creds = build_creds(CKey, CSecret)}}.

handle_call({request_token, CallbackUri}, _From, #state{oauth_creds = Creds} = State) ->
  case call_api(request_token, CallbackUri, Creds) of
    {ok, Response} ->
      Updates  = build_access_token(Response),
      Updates1 = maps:put(<<"callback_uri">>, to_bin(CallbackUri), Updates),
      {reply, ok, State#state{oauth_creds = maps:merge(Creds, Updates1)}};
    {error, _Reason} = Error ->
      {reply, Error, State}
  end;
handle_call(get_authorize_url, _From, #state{oauth_creds = Creds} = State) ->
  URI = build_url(authorize, #{oauth_token => maps:get(<<"access_token">>, Creds)}),
  {reply, {ok, to_bin(URI)}, State};
handle_call({get_access_token, OAuthToken, OAuthVerifier}, _From,
            #state{oauth_creds = Creds} = State) ->
  Updates = call_api(access_token, {OAuthToken, OAuthVerifier}, Creds),
  case is_map(Updates) of
    true ->
      {reply, ok, State#state{oauth_creds = maps:merge(Creds, Updates)}};
    false ->
      {reply, Updates, State}
  end;
handle_call({set_oauth_credentials, Map}, _From,
            #state{oauth_creds = Creds} = State) when is_map(Map) ->
  {reply, ok, State#state{oauth_creds = maps:merge(Creds, Map)}};
handle_call({set_oauth_credentials, CKey, CSecret}, _From, State) ->
  {reply, ok, State#state{oauth_creds = build_creds(CKey, CSecret)}};
handle_call(get_oauth_credentials, _From, State) ->
  {reply, {ok, State#state.oauth_creds}, State};
handle_call({verify_credentials, Args}, _From, #state{oauth_creds = Creds} = State) ->
  case call_api(verify_credentials, Args, Creds) of
    {ok, _Headers, Body}  ->
      {reply, {ok, Body}, State};
    Error ->
      {reply, Error, State}
  end;
handle_call(home_timeline, _From, #state{oauth_creds = Creds} = State) ->
  {reply, call_api(home_timeline, [], Creds), State};
handle_call({user_timeline, Name}, _From, #state{oauth_creds = Creds} = State) ->
  {reply, call_api(user_timeline, [{screen_name, Name}], Creds), State};
handle_call({mentions_timeline, Args}, _From, #state{oauth_creds = Creds} = State) ->
  {reply, call_api(mentions_timeline, Args, Creds), State};
handle_call({lookup_status, Args}, _From, #state{oauth_creds = Creds} = State) ->
  {reply, call_api(lookup_status, Args, Creds), State};
handle_call({search, Args}, _From, #state{oauth_creds = Creds} = State) ->
  QueryArgs = to_args(filter_search_args(Args)),
  {reply, call_api(search, QueryArgs, Creds), State};

handle_call(Request, _From, State) ->
  error_logger:error_msg("[Twitter API] unknown call - ~p", [Request]),
  {reply, {unknown_request, Request}, State}.

handle_cast(unauthorize, #state{oauth_creds = Creds} = State) ->
  Creds1 = maps:with([<<"consumer_key">>, <<"consumer_secret">>], Creds),
  {noreply, State#state{oauth_creds = Creds1}};
handle_cast(unauthorize, State) ->
  {noreply, State#state{oauth_creds = maps:new()}};
handle_cast(stop, State) ->
  {stop, normal, State}.

handle_info(_Msg, State) ->
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(normal, _State) ->
  ok;
terminate(Reason, _State) ->
  error_logger:error_msg("[Twitter API] unexpected exit due to ~p", [Reason]),
  ok.

%%%=============================================================================
%%% Internal functionality
%%%=============================================================================
call_api(request_token = UrlType, CallbackUri, Map) ->
  Args = #{oauth_callback => CallbackUri},
  parse_httpc_response(UrlType, params, oauth_post(UrlType, Args, Map));
call_api(access_token = UrlType, {OAuthToken, OAuthVerifier}, Map) ->
  case validate_oauth_params(OAuthToken, OAuthVerifier) of
    ok ->
      OAuthSecretToken = get_access_token(Map),
      VerifierArg = #{oauth_verifier => to_list(OAuthVerifier)},
      Response = oauth_post(UrlType, VerifierArg, Map, OAuthToken, OAuthSecretToken),
      {ok, Params} = parse_httpc_response(UrlType, params, Response),
      maps:merge(Map, build_access_token(Params));
    Error ->
      error_logger:error_msg("[Twitter API] Error ~s - ~p", [UrlType, Error]),
      Error
  end;
call_api(UrlType, Args, Map) ->
  case validate_credentials(Map) of
    {ok, {AccessToken, AccessTokenSecret}} ->
      Response = oauth_get(UrlType, Args, Map, AccessToken, AccessTokenSecret),
      parse_httpc_response(UrlType, json, Response);
    Error ->
      error_logger:error_msg("[Twitter API] Error ~s - ~p", [UrlType, Error]),
      Error
  end.

oauth_get(UrlType, Args, Creds, AccessToken, AccessTokenSecret) ->
  error_logger:info_msg("[Twitter API] GET call - ~p", [UrlType]),
  oauth:get(get_url(UrlType), to_args(Args), oauth_creds(Creds),
            to_list(AccessToken), to_list(AccessTokenSecret)).

oauth_post(UrlType, Args, Creds, AccessToken, AccessTokenSecret) ->
  error_logger:info_msg("[Twitter API] POST call - ~p", [UrlType]),
  oauth:post(get_url(UrlType), to_args(Args), oauth_creds(Creds),
            to_list(AccessToken), to_list(AccessTokenSecret)).

oauth_post(UrlType, Args, Creds) ->
  error_logger:info_msg("[Twitter API] POST call - ~p", [UrlType]),
  oauth:post(get_url(UrlType), to_args(Args), oauth_creds(Creds)).

validate_oauth_params(undefined, undefined) ->
  {error, missing_oauth_credentials};
validate_oauth_params(undefined, _OAuthVerifier) ->
  {error, missing_oauth_token};
validate_oauth_params(_OAuthToken, undefined) ->
  {error, missing_oauth_verifier};
validate_oauth_params(_OAuthToken, _OAuthVerifier) ->
  ok.

validate_credentials(Map) ->
  validate_credentials(get_access_token(Map), get_access_token_secret(Map)).

validate_credentials(undefined, undefined) ->
  {error, missing_credentials};
validate_credentials(_, undefined) ->
  {error, missing_credentials};
validate_credentials(undefined, _) ->
  {error, missing_credentials};
validate_credentials(AccessToken, AccessTokenSecret) ->
  {ok, {AccessToken, AccessTokenSecret}}.

oauth_creds(Map) ->
  {to_list(maps:get(<<"consumer_key">>, Map)),
    to_list(maps:get(<<"consumer_secret">>, Map)), hmac_sha1}.

build_creds(CKey, CSecret) ->
  #{<<"consumer_key">>    => to_bin(CKey),
    <<"consumer_secret">> => to_bin(CSecret)}.

build_access_token(AccessParams) ->
  #{<<"access_token">>        => to_bin(oauth:token(AccessParams)),
    <<"access_token_secret">> => to_bin(oauth:token_secret(AccessParams))}.

filter_search_args(Args) when is_map(Args) ->
  maps:with(?SEARCH_ARGS, Args);
filter_search_args(Args) ->
  Args.

parse_json(Response) ->
  jiffy:decode(unicode:characters_to_binary(Response), [return_maps]).

build_url(UrlType, Args) ->
  get_url(UrlType) ++ "?" ++ flatten_qs(Args).

flatten_qs(Args) when is_map(Args) ->
  flatten_qs(to_args(Args));
flatten_qs(Args) ->
  string:join(
    [encode_qs(K) ++ "=" ++ encode_qs(V) || {K,V} <- Args], "&").

encode_qs(Value) when is_list(Value) ->
  encode_qs(Value);
encode_qs(Value) ->
  http_uri:encode(to_list(Value)).

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
get_url(mentions_timeline) ->
  ?API_URL ++ "statuses/mentions_timeline.json";
get_url(lookup_status) ->
  ?API_URL ++ "statuses/lookup.json";
get_url(search) ->
  ?API_URL ++ "search/tweets.json".

to_args(Map) when is_map(Map) ->
  maps:to_list(Map);
to_args(PL) ->
  PL.

to_bin(L) when is_list(L) ->
  list_to_binary(L);
to_bin(A) when is_atom(A) ->
  atom_to_binary(A, latin1);
to_bin(B) when is_binary(B) ->
  B.

to_list(Val) when is_integer(Val) ->
  integer_to_list(Val);
to_list(Value) when is_atom(Value) ->
  atom_to_list(Value);
to_list(Value) when is_binary(Value) ->
  binary_to_list(Value);
to_list(Val) ->
  Val.

parse_httpc_response(UrlType, Type, Reply) ->
  {ok, {{_Version, Code, Status}, Headers, Body}} = Reply,
  error_logger:info_msg("[Twitter API] response ~s - ~p", [UrlType, Status]),
  case Code of
    200 ->
      type_specific_reply(Type, Reply);
    304 ->
      {ok, not_modified};
    _ErrorCode ->
      {error, {Code, Headers, parse_json(Body)}}
  end.

type_specific_reply(params, {ok, Response}) ->
  {ok, parse_payload(params, Response)};
type_specific_reply(json, {ok, {_, Headers, Body}}) ->
  {ok, Headers, parse_payload(json, Body)}.

parse_payload(json, Response) ->
  parse_json(Response);
parse_payload(params, Response) ->
  oauth:params_decode(Response).

get_access_token(Map) ->
  get_value(<<"access_token">>, Map).

get_access_token_secret(Map) ->
  get_value(<<"access_token_secret">>, Map).

get_value(Key, Map) ->
  maps:get(Key, Map, undefined).

get_server_name() ->
  N = erlang:phash2(erlang:monotonic_time()),
  list_to_atom("yatael_" ++ integer_to_list(N)).
