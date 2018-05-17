%%%----------------------------------------------------------------------------
%%% @author Martin Wiso <tajgur@gmai.com>
%%% @doc
%%% Unit tests
%%% @end
%%% Created : 7 Apr 2013 by Martin Wiso <tajgur@gmail.com>
%%%----------------------------------------------------------------------------
-module(yatael_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

%% =============================================================================
yatael_test_() ->
    {setup,
     fun setup/0,
     fun terminate/1,
     [ {"Authorization",                   fun test_auth/0}
     , {"Authorization helper",            fun test_auth_helper/0}
     , {"Mocked API call - authorization", fun test_mock_auth/0}
     , {"Mocked API call - timeline",      fun test_mock_timeline/0}
     , {"Mocked API call - lookup status", fun test_mock_lookup/0}
     , {"Mocked API call - search",        fun test_mock_search/0}
     ]
    }.

%% =============================================================================
test_auth() ->
  {ok, Pid} = start_client(),

  ?assertEqual(ok, yatael:request_token(Pid, <<"http://127.0.0.1/">>)),

  {ok, Creds} = yatael:get_oauth_credentials(Pid),

  ?assert(maps:is_key(<<"access_token">>, Creds)),
  ?assert(maps:is_key(<<"consumer_key">>, Creds)),
  ?assert(maps:is_key(<<"consumer_secret">>, Creds)),
  ?assert(maps:is_key(<<"access_token_secret">>, Creds)),
  ?assert(maps:is_key(<<"callback_uri">>, Creds)),

  AuthToken = maps:get(<<"access_token">>, Creds),
  {ok, AuthUrl} = yatael:get_authorize_url(Pid),
  ?assertEqual(
    <<"https://api.twitter.com/oauth/authorize" "?oauth_token=", AuthToken/binary>>,
    AuthUrl
  ),

  ?assertEqual(ok, yatael:unauthorize(Pid)),

  ?assertEqual(ok, stop_client(Pid)),
  ok.

test_mock_auth() ->
  {ok, Pid} = start_client(mock),

  ?assertEqual(ok, yatael:unauthorize(Pid)),

  ?assertMatch({ok, _MockCreds}, yatael:get_oauth_credentials(Pid)),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request, match_expect(request_token)),
    ?assertEqual(ok, yatael:request_token(Pid, <<"http://127.0.0.1/">>)),

    MockCreds1 = #{<<"access_token">>        => <<"token">>,
                   <<"access_token_secret">> => <<"secret">>},
    ?assertEqual(ok, yatael:set_oauth_credentials(Pid, MockCreds1)),

    ok = meck:expect(httpc, request, match_expect(access_token)),
    ok = yatael:get_access_token(Pid, <<"foo">>, <<"bar">>),

    ok = meck:expect(httpc, request, match_expect(verify_credentials)),
    ?assertMatch(
      {ok, _},
      yatael:verify_credentials(Pid, [{skip_status, true}])
    )
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

test_auth_helper() ->
  {ok, Pid} = start_client(mock),

  ?assertEqual(
    {error, missing_callback_uri},
    yatael_auth:authorize(Pid, #{})
  ),

  ReqMap = #{<<"oauth_token">>     => <<"foobar">>,
              <<"oauth_verifier">> => <<"bar_verifier">>,
              <<"callback_uri">>   => <<"http">>},
  ?assertEqual(
    {error, missing_access_token},
    yatael_auth:authorize(Pid, ReqMap)
  ),

  ?assertEqual(ok, stop_client(Pid)),
  ok.

test_mock_timeline() ->
  {ok, Pid} = start_client(mock),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request, match_expect(home_timeline)),
    ?assertMatch({ok, _, _}, yatael:get_timeline(Pid)),

    ok = meck:expect(httpc, request, match_expect(user_timeline)),
    ?assertMatch({ok, _, _}, yatael:get_timeline(Pid, <<"tajgur">>))
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

test_mock_lookup() ->
  {ok, Pid} = start_client(mock),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request, match_expect(lookup_status)),
    ?assertMatch({ok, _, _}, yatael:lookup_status(Pid, #{foo=>bar}))
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

test_mock_search() ->
  {ok, Pid} = start_client(mock),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request, match_expect(search)),
    ?assertMatch(
      {ok, _, _},
      yatael:search(Pid, #{<<"q">> => <<"noisesearch">>})
    )
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

%%%============================================================================
%%% Internal functionality
%%%============================================================================
read_api_keys() ->
  case filelib:is_regular("api.txt") of
    true ->
      {ok, [PL]} = file:consult("api.txt"),
      {proplists:get_value(consumer_key, PL),
      proplists:get_value(consumer_secret, PL)};
    false ->
      {get_oauth_env("consumer_key"), get_oauth_env("consumer_secret")}
  end.

get_oauth_env(Key) ->
  os:getenv(string:to_upper("twitter_" ++ Key)).

match_expect(Type) ->
  ExpectedURI = yatael:get_url(Type),
  fun (_Method, {URI, _Headers, _ContentType, _Body}, _HTTPOptions, _Profile) ->
        ?assertEqual(ExpectedURI, URI),
        {ok, {{<<>>, 200, <<>>}, [], get_expected_response(Type)}};
      (get, {URI, []}, _HTTPOptions, _Profile) ->
        ?assertEqual(1, string:str(URI, ExpectedURI)),
        {ok, {{<<>>, 200, <<>>}, [], get_expected_response(Type)}}
  end.

get_expected_response(access_token) ->
  "oauth_token=foo&oauth_token_secret=bar&user_id=50989917&"
    "screen_name=tajgur&x_auth_expires=0";
get_expected_response(request_token) ->
  "oauth_token=foo&oauth_token_secret=bar&oauth_callback_confirmed=true";
get_expected_response(_Other) ->
  "{\"foo\": \"bar\"}".

start_client() ->
  start_client(nomock).

start_client(MockCreds) ->
  {ConsumerKey, ConsumerSecret} = read_api_keys(),
  case yatael:start_link(ConsumerKey, ConsumerSecret) of
    {ok, Pid} = Result ->
      case MockCreds == mock of
        true ->
          Creds = #{  <<"consumer_key">>        => to_bin(ConsumerKey),
                      <<"consumer_secret">>     => to_bin(ConsumerSecret),
                      <<"access_token">>        => <<"foo">>,
                      <<"access_token_secret">> => <<"bar">>
                  },
          ?assertEqual(ok, yatael:set_oauth_credentials(Pid, Creds)),
          Result;
        false ->
          Result
      end;
    {error, {already_started, Pid}} ->
      {ok, Pid}
  end.

to_bin(L) when is_list(L) ->
  list_to_binary(L);
to_bin(B) when is_binary(B) ->
  B.

stop_client(Pid) ->
  ?assertEqual(ok, yatael:stop(Pid)),
  ok.

setup() ->
  {ok, _} = application:ensure_all_started(yatael),
  ok.

terminate(_) ->
  application:stop(yatael).
