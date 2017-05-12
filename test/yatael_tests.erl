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
       {"Authorization",                   fun test_auth/0}
     , {"Authorization helper",            fun test_auth_helper/0}
     , {"Unauthorized retrieve call",      fun test_unauth/0}
     , {"Mocked API call - authorization", fun test_mock_auth/0}
     , {"Mocked API call - timeline",      fun test_mock_timeline/0}
     , {"Mocked API call - lookup status", fun test_mock_lookup/0}
     , {"Mocked API call - search",        fun test_mock_search/0}
     ]
    }.

%% =============================================================================
test_auth() ->
    %% test unauthorized request
    ?assertEqual({error,missing_credentials},
                 yatael:verify_credentials([{skip_status, true}])),

    %% test oauth
    ?assertEqual(ok, yatael:stop()),
    {ConsumerKey, ConsumerSecret} = read_api_keys(),
    ?assertMatch({ok, _Pid}, yatael:start_link(ConsumerKey, ConsumerSecret)),
    ?assertEqual(ok, yatael:request_token(<<"http://127.0.0.1/">>)),

    {ok, Creds} = yatael:get_oauth_credentials(),
    ?debugFmt("result=~p", [Creds]),

    ?assert(maps:is_key(<<"access_token">>, Creds)),
    ?assert(maps:is_key(<<"consumer_key">>, Creds)),
    ?assert(maps:is_key(<<"consumer_secret">>, Creds)),
    ?assert(maps:is_key(<<"access_token_secret">>, Creds)),
    ?assert(maps:is_key(<<"callback_uri">>, Creds)),

    AuthToken = maps:get(<<"access_token">>, Creds),
    {ok, AuthUrl} = yatael:get_authorize_url(),
    ?assertEqual(<<"https://api.twitter.com/oauth/authorize"
                 "?oauth_token=", AuthToken/binary>>, AuthUrl),

    ?assertEqual(ok, yatael:unauthorize()),
    ok.

test_mock_auth() ->
    ?assertEqual(ok, yatael:unauthorize()),
    MockCreds = #{<<"consumer_key">>    => <<"foo">>,
                  <<"consumer_secret">> => <<"bar">>},
    ?assertEqual(ok, yatael:set_oauth_credentials(MockCreds)),
    ?assertMatch({ok, MockCreds}, yatael:get_oauth_credentials()),

    meck:new(httpc, [passthrough]),
    try
        ?assertEqual(true, meck:validate(httpc)),

        ok = meck:expect(httpc, request, match_expect(request_token)),
        ?assertEqual(ok, yatael:request_token(<<"http://127.0.0.1/">>)),

        MockCreds1 = #{<<"access_token">> => <<"token">>,
                      <<"access_token_secret">> => <<"secret">>},
        ?assertEqual(ok, yatael:set_oauth_credentials(MockCreds1)),

        ok = meck:expect(httpc, request, match_expect(access_token)),
        ok = yatael:get_access_token(<<"foo">>, <<"bar">>),

        ok = meck:expect(httpc, request, match_expect(verify_credentials)),
        ?assertMatch({ok, _}, yatael:verify_credentials([{skip_status, true}]))
    after
        meck:unload(httpc)
    end.

test_auth_helper() ->
    ?assertEqual({error, missing_callback_uri}, yatael_auth:authorize(#{})),
    ReqMap = #{<<"oauth_token">>    => <<"fUE2_gAAAAAASpgSAAABVCkvSyA">>,
               <<"oauth_verifier">> => <<"BIfqu0wreL52b9Us3EDlvBQhBQVPBzdE">>,
               <<"callback_uri">>   => <<"http">>},
    ?assertEqual({error, missing_access_token}, yatael_auth:authorize(ReqMap)),
    ok.

test_mock_timeline() ->
    meck:new(httpc, [passthrough]),
    try
        ?assertEqual(true, meck:validate(httpc)),

        ok = meck:expect(httpc, request, match_expect(home_timeline)),
        ?assertMatch({ok, _, _}, yatael:get_timeline()),

        ok = meck:expect(httpc, request, match_expect(user_timeline)),
        ?assertMatch({ok, _, _}, yatael:get_timeline(<<"tajgur">>))
    after
        meck:unload(httpc)
    end.

test_mock_lookup() ->
    meck:new(httpc, [passthrough]),
    try
        ?assertEqual(true, meck:validate(httpc)),

        ok = meck:expect(httpc, request, match_expect(lookup_status)),
        ?assertMatch({ok, _, _}, yatael:lookup_status(#{foo=>bar}))
    after
        meck:unload(httpc)
    end.

test_mock_search() ->
    meck:new(httpc, [passthrough]),
    try
        ?assertEqual(true, meck:validate(httpc)),

        ok = meck:expect(httpc, request, match_expect(search)),
        ?assertMatch({ok, _, _}, yatael:search(#{<<"q">> => <<"noisesearch">>}))
    after
        meck:unload(httpc)
    end.

test_unauth() ->
    ?assertEqual(ok, yatael:unauthorize()),
    ok.

%%%============================================================================
%%% Internal functionality
%%%============================================================================
read_api_keys() ->
    case file:consult("api.txt") of
        {ok,[PL]} ->
            {proplists:get_value(consumer_key, PL),
             proplists:get_value(consumer_secret, PL)};
        _ ->
            throw("Unable to read credentials from api.txt file!")
    end.

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

setup() ->
    {ok, _} = application:ensure_all_started(yatael),
    ?assertMatch({ok, _Pid}, yatael:start_link()),
    {ConsumerKey, ConsumerSecret} = read_api_keys(),
    ?assertEqual(ok, yatael:set_oauth_credentials(ConsumerKey, ConsumerSecret)),
    ok.

terminate(_) ->
    ok = application:stop(yatael),
    ?assertEqual(ok, yatael:stop()),
    ok.
