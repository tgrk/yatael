%%%----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmai.com>
%%% @doc
%%% Erlang library for Twitter API v1.1
%%% TODO: * 3 legged oAuth
%%%       * basic calls
%%%       * stream api
%%%
%%% @end
%%% Created : 3 Aug 2013 by Martin Wiso <tajgur@gmail.com>
%%%----------------------------------------------------------------------------
-module(yatael).

-behaviour(gen_server).

%% API
-export([request_token/0,
         get_authorize_url/1,
         verify_access_pin/1,
         unauthorize/0,
         is_authorized/0,
         get_authorization/0,
         set_authorization/1,

         get_timeline/0,
         get_timeline/1,
         search/1,

         start_link/2,
         stop/0
        ]).
-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERV,     ?MODULE).
-define(DEPS,     [crypto, asn1, public_key, ssl, inets, oauth]).
-define(TIMEOUT,  1200000).
-define(API_URL,  "https://api.twitter.com/1.1/").
-define(AUTH_URL, "https://api.twitter.com/oauth/").


-record(state, {consumer, r_params, a_params}).

%%%============================================================================
%%% API
%%%============================================================================
request_token() ->
    gen_server:call(?SERV, request_token, ?TIMEOUT).

get_authorize_url(Token) ->
    oauth:uri(get_url(authorize), [{"oauth_token", Token}]).

verify_access_pin(PIN) ->
    gen_server:call(?SERV,{verify_access_token,
                           [{"oauth_verifier", to_list(PIN)}]}).

unauthorize() ->
    gen_server:cast(?SERV, unauthorize).

set_authorization(AuthData) ->
    gen_server:call(?SERV, {set_authorization, AuthData}).

get_authorization() ->
    gen_server:call(?SERV, get_authorization).

is_authorized() ->
    gen_server:call(?SERV, is_authorized).

get_timeline() ->
    gen_server:call(?SERV, home_timeline).

get_timeline(Name) ->
    gen_server:call(?SERV, {user_timeline, Name}).

search(Query) ->
    gen_server:call(?SERV, {search, Query}).

%% @doc Start an acquirer API service.
-spec start_link(string(), string()) -> {ok, pid()} | {error, term()}.
start_link(ConsumerKey, ConsumerSecret) ->
    start_dependencies(),
    gen_server:start_link({local, ?SERV}, ?MODULE,
                          [ConsumerKey, ConsumerSecret], []).

%% @doc Stop an acquirer API service.
-spec stop() -> ok.
stop() ->
    stop_dependencies(),
    gen_server:cast(?SERV, stop).

%%============================================================================
%% gen_server callbacks
%%============================================================================
init([ConsumerKey, ConsumerSecret]) ->
  {ok, #state{consumer = {ConsumerKey, ConsumerSecret, hmac_sha1}}}.

handle_call(request_token, _From, #state{consumer = Consumer} = State) ->
    case oauth_get(header, get_url(request_token), [], Consumer, "", "") of
        {ok, Response = {{_, 200, _}, _, _}} ->
            RParams = oauth:params_decode(Response),
            NewState = State#state{r_params = RParams},
            {reply, {ok, oauth:token(RParams)}, NewState};
        {ok, Response} ->
            {reply, Response, State};
        Error ->
            {reply, Error, State}
    end;
handle_call({verify_access_token, Params}, _From,
            #state{consumer = Consumer, r_params = RParams} = State) ->
    case oauth_get(header, get_url(access_token), Params, Consumer,
                   oauth:token(RParams), oauth:token_secret(RParams)) of
        {ok, Response = {{_, 200, _}, _, _}} ->
            {reply, ok, State#state{a_params = oauth:params_decode(Response)}};
        {ok, Response} ->
            {reply, Response, State};
        Error ->
            {reply, Error, State}
    end;
handle_call({set_authorization, {C, A, R}}, _From, State) ->
    {reply, ok, State#state{consumer = C, a_params = A, r_params = R}};
handle_call(get_authorization, _From,
            #state{consumer = C, a_params = A, r_params = R} = State) ->
    {reply, {C, A, R}, State};
handle_call(is_authorized, _From,
            #state{a_params = undefined, r_params = undefined} = State) ->
    {reply, false, State};
handle_call(is_authorized, _From, State) ->
    {reply, true, State};
handle_call(home_timeline, _From, State) ->
    call(home_timeline, [], State);
handle_call({user_timeline, Name}, _From, State) ->
    call(user_timeline, [{user, Name}], State);
handle_call({search, Query}, _From, State) ->
    call(search, [{q, Query}], State);
handle_call(Request, _From, State) ->
    {reply, {unknown_request, Request}, State}.


handle_cast(unauthorize, #state{consumer = Consumer}) ->
    {noreply, #state{consumer = Consumer}};
handle_cast(stop, State) ->
    {stop, normal, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(normal, _State) ->
    ok.

%%%============================================================================
%%% Internal functionality
%%%============================================================================
oauth_get(header, URL, Params, Consumer, Token, TokenSecret) ->
    Signed = oauth:sign("GET", URL, Params, Consumer, Token, TokenSecret),
    {AuthParams, QueryParams} = lists:partition(
                                  fun({K, _}) -> lists:prefix("oauth_", K) end,
                                  Signed
                                 ),
    httpc:request(
      get,
      {oauth:uri(URL, QueryParams), [oauth:header(AuthParams)]},
      [{autoredirect, false}],
      []
     );
oauth_get(querystring, URL, Params, Consumer, Token, TokenSecret) ->
  oauth:get(URL, Params, Consumer, Token, TokenSecret).

call(Name, Params, #state{consumer = Consumer, a_params = AParams} = State) ->
    case oauth_get(header, get_url(Name), Params, Consumer,
                   oauth:token(AParams), oauth:token_secret(AParams)) of
        {ok, {{_, 200, _}, Headers, Body}} ->
            case proplists:get_value("content-type", Headers) of
                undefined ->
                    {reply, {ok, Headers, response(Body)}, State};
                ContentType ->
                    io:format("DEBUG: ContentType: ~p~n", [ContentType]),
                    {reply, {ok, Headers, response(Body)}, State}
            end;
        {ok, Response} ->
            {reply, Response, State};
        Error ->
            {reply, Error, State}
    end.

get_url(request_token) ->
    ?AUTH_URL ++ "request_token";
get_url(access_token) ->
    ?AUTH_URL ++ "access_token";
get_url(authorize) ->
    ?AUTH_URL ++ "authorize";
get_url(home_timeline) ->
    ?API_URL ++ "statuses/home_timeline.json";
get_url(user_timeline) ->
    ?API_URL ++ "statuses/user_timeline.json";
get_url(search) ->
    ?API_URL ++ "search/tweets.json".

get_name(Name, Suffix) ->
    list_to_atom(atom_to_list(Name) ++ Suffix).

response(Body) ->
    unicode:characters_to_binary(Body).

to_bin(Value) when is_list(Value) ->
    list_to_binary(Value);
to_bin(Value) ->
    Value.

start_dependencies() ->
    [application:start(A) || A <- ?DEPS],
    ok.

stop_dependencies() ->
    [application:stop(A) || A <- ?DEPS],
    ok.

to_list(Val) when is_integer(Val) ->
    integer_to_list(Val);
to_list(Val) ->
    Val.
