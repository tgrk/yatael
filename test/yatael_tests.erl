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
     [
          {"Authorization and validation", fun test_auth/0}
        , {"Mocked authorization helper",  fun test_mock_auth_helper/0}
        , {"Mocked authorization",         fun test_mock_auth/0}
        , {"Mocked timeline",              fun test_mock_timeline/0}
        , {"Mocked mentions timeline",     fun test_mock_mentions_timeline/0}
        , {"Mocked lookup status",         fun test_mock_lookup/0}
        , {"Mocked search",                fun test_mock_search/0}
        , {"Mocked multiple clients",      fun test_mock_multiple_clients/0}
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
    <<"https://api.twitter.com/oauth/authorize?oauth_token=", AuthToken/binary>>,
    AuthUrl
  ),

  CKey = <<"foo">>,
  CSecret = <<"bar">>,
  ?assertEqual(ok, yatael:set_oauth_credentials(Pid, CKey, CSecret)),
  {ok, NewCreds} = yatael:get_oauth_credentials(Pid),
  ?assertEqual(CKey,    maps:get(<<"consumer_key">>, NewCreds)),
  ?assertEqual(CSecret, maps:get(<<"consumer_secret">>, NewCreds)),

  ?assertEqual(ok, yatael:unauthorize(Pid)),

  ?assertEqual(
    {error, missing_oauth_credentials},
    yatael:get_access_token(Pid, undefined, undefined)
  ),
  ?assertEqual(
    {error, missing_oauth_verifier},
    yatael:get_access_token(Pid, <<"foo">>, undefined)
  ),
  ?assertEqual(
    {error, missing_oauth_token},
    yatael:get_access_token(Pid, undefined, <<"bar">>)
  ),
  ?assertEqual(
    {error, missing_credentials},
    yatael:get_timeline(Pid)
  ),

  ?assertEqual(ok, stop_client(Pid)),
  ok.

test_mock_auth_helper() ->
  {ok, Pid} = start_client(),

  OAuthCreds = #{
    <<"oauth_token">>    => <<"access_token">>,
    <<"callback_uri">>   => <<"http://127.0.0.1/">>,
    <<"oauth_verifier">> => <<"bar_verifier">>
  },

  ?assertEqual(
    {error, missing_callback_uri},
    yatael_auth:authorize(Pid, #{})
  ),

  ?assertEqual(
    {error, missing_oauth_verifier},
    yatael_auth:authorize(Pid, #{<<"oauth_token">> => <<"foo">>})
  ),

  ?assertEqual(
    {error, missing_oauth_token},
    yatael_auth:authorize(Pid, maps:remove(<<"oauth_token">>, OAuthCreds))
  ),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request,
      fun (_Method, {URI, _Headers, _ContentType, _Body}, _HTTPOptions, _Profile) ->
            ExpectedURIs = [
              access_token,
              request_token,
              verify_credentials
            ],
            MatchPred = fun (ExpectedType) ->
              string:str(URI, yatael:get_url(ExpectedType)) > 0
            end,
            case lists:filter(MatchPred, ExpectedURIs) of
              [Type] ->
                {ok, {{<<>>, 200, <<>>}, [], get_expected_response(Type)}};
              _Other ->
                ?assert(false)
            end;
          (_Method, {URI, []}, _HTTPOptions, _Profile) ->
            ExpectedURI = yatael:get_url(verify_credentials),
            ?assertEqual(1, string:str(URI, ExpectedURI)),
            {ok, {{<<>>, 200, <<>>}, [], get_expected_response(verify_credentials)}}
      end
    ),
    ?assertMatch({ok, _Map}, yatael_auth:authorize(Pid, OAuthCreds))
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

test_mock_auth() ->
  {ok, Pid} = start_client(),

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

test_mock_timeline() ->
  {ok, Pid} = start_client(),

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

test_mock_mentions_timeline() ->
  {ok, Pid} = start_client(),

  meck:new(httpc, [passthrough]),
  try
    ?assertEqual(true, meck:validate(httpc)),

    ok = meck:expect(httpc, request, match_expect(mentions_timeline)),
    ?assertMatch({ok, _, _}, yatael:get_mentions_timeline(Pid, #{}))
  after
    meck:unload(httpc),
    ?assertEqual(ok, stop_client(Pid))
  end.

test_mock_lookup() ->
  {ok, Pid} = start_client(),

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
  {ok, Pid} = start_client(),

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

test_mock_multiple_clients() ->
  {ok, Pid1} = start_client(),
  {ok, Pid2} = start_client(),

  ATKey  = <<"access_token">>,
  ATSKey = <<"access_token_secret">>,

  MakeCredsFun = fun (ATValue, ATSValue) ->
    maps:put(ATSKey, ATSValue, maps:put(ATKey, ATValue, #{}))
  end,

  MockCreds11 = MakeCredsFun(<<"token1">>, <<"secret1">>),
  ?assertEqual(ok, yatael:set_oauth_credentials(Pid1, MockCreds11)),

  MockCreds21 = MakeCredsFun(<<"token2">>, <<"secret2">>),
  ?assertEqual(ok, yatael:set_oauth_credentials(Pid2, MockCreds21)),

  {ok, MockCreds12} = yatael:get_oauth_credentials(Pid1),
  {ok, MockCreds22} = yatael:get_oauth_credentials(Pid2),

  ?assertEqual(maps:with([ATKey, ATSKey], MockCreds12), MockCreds11),
  ?assertEqual(maps:with([ATKey, ATSKey], MockCreds22), MockCreds21),

  ?assertEqual(ok, stop_client(Pid1)),
  ?assertEqual(ok, stop_client(Pid2)),
  ok.

%%%============================================================================
%%% Internal functionality
%%%============================================================================
read_api_keys() ->
  PL = case filelib:is_regular("api.txt") of
    true ->
      {ok, [CredsPL]} = file:consult("api.txt"),
      CredsPL;
    false ->
      []
  end,
  #{  <<"consumer_key">>        => maybe_get_from_env("consumer_key", PL),
      <<"consumer_secret">>     => maybe_get_from_env("consumer_secret", PL),
      <<"access_token">>        => maybe_get_from_env("access_token", PL),
      <<"access_token_secret">> => maybe_get_from_env("access_token_secret", PL)
  }.

maybe_get_from_env(Key, PL) ->
  case get_oauth_env(Key) of
    false -> to_bin(proplists:get_value(list_to_atom(Key), PL));
    Value -> to_bin(Value)
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
  Creds = read_api_keys(),
  CKey    = maps:get(<<"consumer_key">>, Creds),
  CSecret = maps:get(<<"consumer_secret">>, Creds),

  case yatael:start_link(CKey, CSecret) of
    {ok, Pid} = Result ->
      ?assertEqual(ok, yatael:set_oauth_credentials(Pid, Creds)),
      Result;
    {error, {already_started, Pid}} ->
      {ok, Pid}
  end.

to_bin(L) when is_list(L) ->
  list_to_binary(L);
to_bin(A) when is_atom(A) ->
  atom_to_binary(A, latin1);
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
