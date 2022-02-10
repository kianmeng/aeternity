%%%-------------------------------------------------------------------
%%% @copyright (C) 2019, Aeternity Anstalt
%%% @doc Basic tests Sophia-to-Fate pipeline
%%% @end
%%%-------------------------------------------------------------------
-module(aefa_fate_chain_sim).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("apps/aecontract/include/aecontract.hrl").

-define(AE, 1000000000000000000).

%% -- Compiling and running --

compile_contracts(Contracts) ->
    compile_contracts(Contracts, default_options()).

compile_contracts(Contracts, Options) ->
    maps:from_list([ begin
                       {ok, CompiledMap} = compile_contract(Code, Options),
                       {pad_contract_name(Name), {maps:get(fate_code, CompiledMap), ?VM_FATE_SOPHIA_3}}
                     end || {Name, Code} <- Contracts ]).

make_contract(Name) -> aeb_fate_data:make_contract(pad_contract_name(Name)).

dummy_spec(Cache, Options) ->
    Caller = maps:get(caller, Options, <<123:256>>),
    #{ trees     => dummy_trees(Caller, Cache),
       caller    => Caller,
       origin    => Caller,
       gas_price => 1,
       fee       => 621,
       tx_env    => aetx_env:tx_env(1) }.

dummy_trees(Caller, Cache) ->
    %% All contracts and the caller must have accounts
    Trees = get_trees(),
    Pubkeys = [Caller | [X || X <- maps:keys(Cache)]],
    ATrees = lists:foldl(fun(Pubkey, Acc) ->
                             case aec_accounts_trees:lookup(Pubkey, Acc) of
                               none ->
                                 Account = aec_accounts:new(Pubkey, 10000 * ?AE),
                                 aec_accounts_trees:enter(Account, Acc);
                               _ ->
                                 Acc
                             end
                         end, aec_trees:accounts(Trees), Pubkeys),
    aec_trees:set_accounts(Trees, ATrees).

run(Cache, Contract, Function, Arguments) ->
    {_, Res} = timed_run(Cache, Contract, Function, Arguments, #{}),
    Res.

run(Cache, Contract, Function, Arguments, Store) ->
    {_, Res} = timed_run(Cache, Contract, Function, Arguments, Store),
    Res.

timed_run(Contract, Fun, Args) ->
  timed_run(Contract, Fun, Args, #{}).

timed_run(Contract, Fun, Args, Options) ->
    timed_run(get_cache(), Contract, Fun, Args, Options).

timed_run(Cache, Contract, Function, Arguments, Options) ->
    Spec = make_call_spec(Contract, Function, Arguments, Options),
    Env = dummy_spec(Cache, Options),
    try
        timer:tc(fun() -> aefa_fate:run_with_cache(Spec, Env, Cache) end)
    catch _:{error, Err} ->
              {0, {error, Err, []}}
    end.

default_options() ->
    [{debug, [scode, opt, opt_rules, compile]}, pp_fcode].

compile_contract(Code) ->
    compile_contract(Code, default_options()).

compile_contract(Code, Options) ->
    case aeso_compiler:from_string(Code, Options ++ [{backend, fate}]) of
        {ok, ContractMap} ->
            {ok, ContractMap};
        {error, Errs} ->
            Errors = lists:join("\n", [ aeso_errors:pp(E) || E <- Errs ]),
            io:format("~s", [Errors]),
            {error, {type_errors, Errs}}
    end.

-define(CALL_GAS, 6000000).
-define(CALL_FEE, 5000000).

make_call_spec(Contract, Function0, Arguments, Options) ->
    CtName  = pad_contract_name(Contract),
    CtStore = get_ctstore(CtName),
    Function = aeb_fate_code:symbol_identifier(Function0),
    EncArgs  = list_to_tuple([aefa_test_utils:encode(A) || A <- Arguments]),
    Calldata = {tuple, {Function, {tuple, EncArgs}}},
    SerCalldata = aeb_fate_encoding:serialize(Calldata),
    #{ contract   => CtName,
       gas        => ?CALL_GAS,
       fee        => ?CALL_FEE,
       value      => maps:get(value, Options, 0),
       call       => SerCalldata,
       store      => CtStore,
       vm_version => ?VM_FATE_SOPHIA_2,
       allow_init => true
     }.

pad_contract_name(AtomName) when is_atom(AtomName) ->
    pad_contract_name(atom_to_binary(AtomName, utf8));
pad_contract_name(Name) ->
    PadSize = 32 - byte_size(Name),
    iolist_to_binary([Name, lists:duplicate(PadSize, "_")]).

print_run_stats(Time, ES) ->
    GasUsed    = ?CALL_GAS - aefa_engine_state:gas(ES),
    Trace      = aefa_engine_state:trace(ES),
    Red        = fun({_, {reductions, R}}) -> R end,
    Reductions = Red(hd(Trace ++ [{bla, {reductions, 0}}])) - Red(lists:last([{bla, {reductions, 0}} | Trace])),
    Steps      = length(Trace),
    io:format("~p steps / ~p gas / ~p reductions / ~.2fms\n", [Steps, GasUsed, Reductions, Time / 1000]).

print_logs(_, []) -> ok;
print_logs(EventMap, Logs) ->
    io:format("Events:\n"),
    print_logs(EventMap, none, Logs).

print_logs(_, _, []) -> ok;
print_logs(EventMap, Ct, [{Ct, [Hash | Ixs], Payload} | Logs]) ->
    PayloadStr =
        case Payload of
            <<>> -> "";
            _    -> io_lib:format(", ~s", [Payload])
        end,
    io:format("    ~s(~s~s)\n",
        [maps:get(Hash, EventMap, Hash),
         string:join([integer_to_list(N) || <<N:256>> <- Ixs], ", "),
         PayloadStr]),
    print_logs(EventMap, Ct, Logs);
print_logs(EventMap, _, Logs = [{Ct, _, _} | _]) ->
    io:format("  ~p\n", [Ct]),
    print_logs(EventMap, Ct, Logs).

es_trees(ES) ->
    aefa_fate:final_trees(ES).

get_ctstore(Pubkey) ->
    CtTrees = aec_trees:contracts(get_trees()),
    case aect_state_tree:lookup_contract(Pubkey, CtTrees, [full_store_cache]) of
        none              -> aefa_stores:initial_contract_store();
        {value, Contract} -> aect_contracts:state(Contract)
    end.

add_new_contract(Pubkey) -> add_new_contract(Pubkey, <<>>).

add_new_contract(Pubkey, CMap) when is_map(CMap) ->
    add_new_contract(Pubkey, aeser_contract_code:serialize(CMap, 3));
add_new_contract(Pubkey, Code) ->
    Contract0 = aect_contracts:new(Pubkey, 1, #{vm => 8, abi => 3}, Code, 0),
    Contract1 = aect_contracts:set_pubkey(Pubkey, Contract0),
    Contract2 = aect_contracts:set_state(aefa_stores:initial_contract_store(), Contract1),
    Trees  = get_trees(),
    CTrees = aec_trees:contracts(Trees),
    CTrees1 = case aect_state_tree:is_contract(Pubkey, CTrees) of
                true  -> aect_state_tree:enter_contract(Contract2, CTrees);
                false -> aect_state_tree:insert_contract(Contract2, CTrees)
              end,
    put_trees(aec_trees:set_contracts(Trees, CTrees1)).

read_store(Pubkey, ES) ->
    try
        Trees        = aefa_fate:final_trees(ES),
        CtTrees      = aec_trees:contracts(Trees),
        Contract     = aect_state_tree:get_contract(Pubkey, CtTrees, [full_store_cache]),
        CtStore      = aect_contracts:state(Contract),
        Store        = aefa_stores:put_contract_store(Pubkey, CtStore, aefa_stores:new()),
        ES1          = aefa_engine_state:set_stores(Store, ES),
        Keys         = [ binary:decode_unsigned(Reg)
                         || <<0, Reg/binary>> <- maps:keys(aect_contracts_store:contents(CtStore)) ],
        Value = fun(Key) ->
                    {ok, Val, _} = aefa_stores:find_value(Pubkey, Key, Store),
                    {Val1, _}    = aefa_fate:unfold_store_maps(Val, ES1, unfold),
                    Val1
                end,
        {maps:from_list([ {Key, Value(Key)} || Key <- Keys, Key > 0 ]), CtStore}
    catch K:Err:ST ->
        io:format("~p:~p\n  ~p\n", [K, Err, ST]),
        {error, none}
    end.

run_file(File, Fun, Args) ->
    run_file(File, Fun, Args, []).

run_file(File, Fun, Args, Options) ->
    {ok, Code} = file:read_file(File),
    run_call(binary_to_list(Code), Fun, Args, Options).

run_call(Code, Fun, Args) ->
    run_call(Code, Fun, Args, []).

run_call(Code, Fun, Args, Options) ->
    Contract = pad_contract_name(<<"test">>),
    Cache = compile_contracts([{Contract, Code}], Options),
    EventMap = maps:from_list(
                 [{element(2, eblake2:blake2b(32, list_to_binary(Con))), Con}
                  || {con, _, Con} <- element(2, aeso_scan:scan(Code))]),
    add_new_contract(Contract),
    case timed_run(Cache, Contract, list_to_binary(Fun), Args, #{}) of
        {Time, {ok, ES}} ->
            print_run_stats(Time, ES),
            Logs = aefa_engine_state:logs(ES),
            {Store1, CtStore} = read_store(Contract, ES),
            put(contract_store, CtStore),
            io:format("Store:\n  ~p\n", [Store1]),
            print_logs(EventMap, Logs),
            aefa_engine_state:accumulator(ES);
        {Time, {revert, Reason, ES}} ->
            print_run_stats(Time, ES),
            io:format("Revert: ~ts\n", [Reason]),
            {error, revert};
        {Time, {error, <<"Out of gas">>, ES}} ->
            print_run_stats(Time, ES),
            {error, out_of_gas};
        {Time, {error, Err, ES}} ->
            print_run_stats(Time, ES),
            io:format("~s\n", [Err]),
            {error, Err, [I || {I, _} <- aefa_engine_state:trace(ES)]}
    end.

setup_contract(Tag, File) ->
    setup_contract(Tag, File, []).

setup_contract(Tag, File, InitArgs) ->
    setup_contract(Tag, File, InitArgs, []).

setup_contract(Tag, File, InitArgs, Options) ->
    {ok, CodeBin} = file:read_file(File),
    Code = binary_to_list(CodeBin),
    Contract = pad_contract_name(Tag),
    {ok, CompiledMap} = compile_contract(Code, Options),
    NewCache = #{Contract => {maps:get(fate_code, CompiledMap), ?VM_FATE_SOPHIA_3}},
    add_to_cache(NewCache),
    add_new_contract(Contract, CompiledMap),
    case timed_run(Contract, <<"init">>, InitArgs) of
        {Time, {ok, ES}} ->
            print_run_stats(Time, ES),
            {Store1, _CtStore} = read_store(Contract, ES),
            put_trees(es_trees(ES)),
            EventMap = maps:from_list(
                 [{element(2, eblake2:blake2b(32, list_to_binary(Con))), Con}
                  || {con, _, Con} <- element(2, aeso_scan:scan(Code))]),
            put_eventmap(Tag, EventMap),
            io:format("Initial state:\n  ~p\n", [Store1]);
        {Time, {error, Err, ES}} ->
            print_run_stats(Time, ES),
            io:format("~s\n", [Err]),
            io:format("~p\n", [ES]),
            {error, Err, [I || {I, _} <- aefa_engine_state:trace(ES)]}
    end.

call_contract(Tag, Fun, Args) ->
    call_contract(Tag, Fun, Args, #{}).

call_contract(Tag, Fun, Args, Options) ->
    Contract = pad_contract_name(Tag),
    case timed_run(Contract, list_to_binary(Fun), Args, Options) of
        {Time, {ok, ES}} ->
            print_run_stats(Time, ES),
            Logs = aefa_engine_state:logs(ES),
            {Store1, _CtStore} = read_store(Contract, ES),
            CC = aefa_engine_state:code_cache(ES),
            add_to_cache(CC),
            put_trees(es_trees(ES)),
            [io:format("State:\n  ~p\n", [Store1]) || maps:get(show_state, Options, true)],
            print_logs(get_eventmap(Tag), Logs),
            aefa_engine_state:accumulator(ES);
        {Time, {revert, Reason, ES}} ->
            print_run_stats(Time, ES),
            io:format("Revert: ~ts\n", [Reason]),
            {error, revert};
        {Time, {error, <<"Out of gas">>, ES}} ->
            print_run_stats(Time, ES),
            {error, out_of_gas};
        {Time, {error, Err, ES}} ->
            print_run_stats(Time, ES),
            io:format("~s\n", [Err]),
            {error, Err, [I || {I, _} <- aefa_engine_state:trace(ES)]}
    end.

put_cache(C) ->
    put('contract_cache', C),
    C.

get_cache() ->
    case get('contract_cache') of
        undefined ->
            #{};
        Cache ->
            Cache
    end.

put_trees(S) ->
    put('contract_trees', S),
    S.

get_trees() ->
    case get('contract_trees') of
        undefined ->
            aec_trees:new_without_backend();
        Trees ->
            Trees
    end.

put_eventmap(Tag, Map) ->
    EMap = get_eventmap(),
    put_eventmap(EMap#{Tag => Map}).

put_eventmap(S) ->
    put('contract_eventmap', S),
    S.

get_eventmap(Tag) ->
    maps:get(Tag, get_eventmap()).

get_eventmap() ->
    case get('contract_eventmap') of
        undefined ->
            #{};
        Store ->
            Store
    end.

add_to_cache(Cache0) ->
    NewCache = maps:merge(get_cache(), Cache0),
    put_cache(NewCache).

%% add_to_contracts(Cache0) ->
%%     NewCache = maps:merge(get_contracts(), Cache0),
%%     put_contracts(NewCache).

show_contracts() ->
    Cache = get_cache(),
    [ io:format("C: ~140p\n", [C]) || {C, _} <- maps:to_list(Cache) ],
    ok.

show_accounts() ->
    ATrees = aec_trees:accounts(get_trees()),
    [ io:format("~140p -> ~140p\n", [PK, Amount]) || {PK, Amount} <- aec_accounts_trees:get_all_accounts_balances(ATrees) ],
    ok.

reset() ->
    erase(contract_cache),
    erase(contract_eventmap),
    erase(contract_trees),
    ok.

%% Staking contract testing
test_staking() ->
    reset(),
    setup_contract(staking_validator, "test/contracts/StakingValidator.aes", [{address, <<0:256>>}]),
    setup_contract(main_staking, "test/contracts/MainStaking.aes", [{contract, pad_contract_name(staking_validator)}]),

    Validator1 = pad_contract_name(validator1),
    call_contract(main_staking, "new_validator", [], #{value => 1000 * ?AE, caller => Validator1}),

    Delegator1 = pad_contract_name(delegator1),
    call_contract(main_staking, "stake", [{address, Validator1}], #{value => 25 * ?AE, caller => Delegator1}),


    call_contract(main_staking, "reward", [{address, Validator1}], #{value => 10 * ?AE}),

    Delegator2 = pad_contract_name(delegator2),
    call_contract(main_staking, "stake", [{address, Validator1}], #{value => 50 * ?AE, caller => Delegator2}),

    State1 = call_contract(main_staking, "get_validator_state", [{address, Validator1}], #{}),
    io:format("Validator state: ~p\n", [State1]),

    call_contract(main_staking, "reward", [{address, Validator1}], #{value => 100 * ?AE}),
%%     show_accounts(),

    Validator2 = pad_contract_name(validator2),
    call_contract(main_staking, "new_validator", [], #{value => 1000 * ?AE, caller => Validator2}),

    Stakers = call_contract(main_staking, "validators", []),
    io:format("Stakers: ~p\n", [Stakers]),

    Payout1 = call_contract(main_staking, "unstake", [{address, Validator1}], #{caller => Delegator2}),
    Payout2 = call_contract(main_staking, "unstake", [{address, Validator1}], #{caller => Delegator1}),
    Payout3 = call_contract(main_staking, "unstake", [{address, Validator1}], #{caller => Validator1}),

%%     show_accounts(),
    io:format("Payouts: ~p / ~p / ~p\n", [Payout1, Payout2, Payout3]),

    ok.

