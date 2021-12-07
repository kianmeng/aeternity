%%% -*- erlang-indent-level:4; indent-tabs-mode: nil -*-
%%%-------------------------------------------------------------------
%%% @copyright (C) 2017, Aeternity Anstalt
%%% @doc
%%% API to the Aeternity node db
%%% @end
%%%-------------------------------------------------------------------
-module(aec_db).

-export([check_db/0,                    % called from setup hook
         start_db/0,                    %  ------ " ------
         initialize_db/1,               % assumes mnesia started
         load_database/0,               % called in aecore app start phase
         tables/1,                      % for e.g. test database setup
         clear_db/0,                    % mostly for test purposes
         tab_copies/1,                  % for create_tables hooks
         check_table/3,                 % for check_tables hooks
         tab/4,
         persisted_valid_genesis_block/0
        ]).

-export([ensure_transaction/1,
         ensure_activity/2]).

%% Mimicking the aec_persistence API used by aec_conductor_chain
-export([has_block/1,
         write_block/1,
         write_block/2,
         write_block_state/6,
         write_discovered_pof/2,
         write_genesis_hash/1,
         write_top_block_node/2,
         write_finalized_height/1,
         write_signal_count/2,
         find_block/1,
         find_block_tx_hashes/1,
         find_discovered_pof/1,
         find_header/1,
         dirty_find_header/1,
         find_headers_at_height/1,
         find_key_headers_and_hash_at_height/1,
         find_headers_and_hash_at_height/1,
         find_key_block/1,
         find_signed_tx/1,
         find_signal_count/1,
         get_block/1,
         get_header/1,
         get_genesis_hash/0,
         get_signed_tx/1,
         dirty_get_signed_tx/1,
         get_top_block_hash/0,
         get_top_block_node/0,
         get_finalized_height/0,
         dirty_get_finalized_height/0,
         get_block_state/1,
         get_block_state/2,
         get_block_state_partial/3,
         get_block_from_micro_header/2
        ]).

%% Location of chain transactions
-export([ add_tx_location/2
        , add_tx/1
        , remove_tx/1
        , add_tx_hash_to_mempool/1
        , is_in_tx_pool/1
        , find_tx_location/1
        , find_tx_with_location/1
        , remove_tx_from_mempool/1
        , remove_tx_location/1
        , gc_tx/1
        ]).

%% Only to be used from aec_tx_pool:init/1
-export([ fold_mempool/2
        ]).


%% MP trees backend
-export([ find_accounts_node/1
        , find_calls_node/1
        , find_channels_node/1
        , find_contracts_node/1
        , find_ns_node/1
        , find_ns_cache_node/1
        , find_oracles_node/1
        , find_oracles_cache_node/1
        , dirty_find_accounts_node/1
        , dirty_find_calls_node/1
        , dirty_find_channels_node/1
        , dirty_find_contracts_node/1
        , dirty_find_ns_node/1
        , dirty_find_ns_cache_node/1
        , dirty_find_oracles_node/1
        , dirty_find_oracles_cache_node/1
        , write_accounts_node/2
        , write_accounts_node/3
        , write_calls_node/2
        , write_channels_node/2
        , write_contracts_node/2
        , write_ns_node/2
        , write_ns_cache_node/2
        , write_oracles_node/2
        , write_oracles_cache_node/2
        ]).

-export([ find_block_state/1
        , find_block_state/2
        , find_block_state_partial/3
        , find_block_difficulty/1
        , find_block_fees/1
        , find_block_fork_id/1
        , find_block_fraud_status/1
        , find_block_state_and_data/1
        , find_block_state_and_data/2
        ]).

-export([ write_peer/1
        , delete_peer/1
        , read_all_peers/0
        ]).

%% Fork tracking and selection
-export([ find_chain_end_hashes/0
        , mark_chain_end_hash/1
        , unmark_chain_end_hash/1
        , start_chain_migration/1
        , finish_chain_migration/1
        , chain_migration_status/1
        ]).

%%
%% for testing
-export([backend_mode/0]).

-include("blocks.hrl").
-include("aec_db.hrl").

-define(IF_RDB(TrueExpr, FalseExpr), case get_backend_module() of mnesia_rocksdb ->
                                             TrueExpr;
                                          _ ->
                                             FalseExpr
                                     end).

%% - transactions
%% - headers
%% - block  [transaction_ids]
%% - oracle_state
%% - oracle_cache
%% - account_state
%% - channel_state
%% - name_service_state
%% - name_service_cache
%% - one per state tree
%% - untrusted peers

-define(TAB(Record),
        {Record, tab(Mode, Record, record_info(fields, Record), [])}).
-define(TAB(Record, Extra),
        {Record, tab(Mode, Record, record_info(fields, Record), Extra)}).

%% start a transaction if there isn't already one
-define(t(Expr), ensure_transaction(fun() -> Expr end)).

-define(TX_IN_MEMPOOL, []).
-define(PERSIST, true).

tables() -> tables(ram).

%% WARNING: We are migrating away from mnesia - currently some
%%          backends are bypasing the mnesia transaction manager and issuing
%%          a custom commit to the backend - as a results indexes are not
%%          updated automatically - If you add another index then you need
%%          to update the custom bypass logic
tables(Mode) when Mode==ram; Mode==disc ->
    tables(expand_mode(Mode));
tables(Mode) ->
    [?TAB(aec_blocks)
   , ?TAB(aec_headers, [{index, [height]}])
   , ?TAB(aec_chain_state)
   , ?TAB(aec_contract_state)
   , ?TAB(aec_call_state)
   , ?TAB(aec_block_state)
   , ?TAB(aec_oracle_cache)
   , ?TAB(aec_oracle_state)
   , ?TAB(aec_account_state)
   , ?TAB(aec_channel_state)
   , ?TAB(aec_name_service_cache)
   , ?TAB(aec_name_service_state)
   , ?TAB(aec_signed_tx)
   , ?TAB(aec_tx_location)
   , ?TAB(aec_tx_pool)
   , ?TAB(aec_discovered_pof)
   , ?TAB(aec_signal_count)
   , ?TAB(aec_peers)
    ].

tab(Mode0, Record, Attributes, Extra) ->
    Mode = expand_mode(Mode0),
    Type = tab_type(Record),
    Arity = length(Attributes),
    UserProps = opt_rocksdb_props(Mode, Record, Type, Arity,
                                  maps:get(user_properties, Mode, [])),
    UserProps1 = [{vsn, tab_vsn(Record)} | UserProps],
    [ tab_copies(Mode)
    , {type, Type}
    , {attributes, Attributes}
    , {user_properties, UserProps1}
    | Extra
    ].

opt_rocksdb_props(#{module := mnesia_rocksdb}, Tab, Type, Arity, Props) ->
    rocksdb_props(Tab, Type, Arity, Props);
opt_rocksdb_props(_, _, _, _, Props) ->
    Props.

rocksdb_props(Tab, Type, Arity, Props) ->
    [encoding(Tab, Type, Arity) | Props].

encoding(aec_chain_state, _, _) -> {term, {value, term}};
encoding(_Tab, set, 2) -> {raw, {value, term}};
encoding(_Tab, set, _) -> {raw, {object, term}}.
%% encoding(_, _, _) -> {sext, {object, sext}}.

tab_vsn(_) -> 1.

tab_type(_) -> set.

tab_copies(Mode) when Mode == ram; Mode == disc ->
    tab_copies(expand_mode(Mode));
tab_copies(#{alias := Alias}) -> {Alias, [node()]}.

clear_db() ->
    ?t(begin
           lists:map(
             fun({T, _}) ->
                     Keys = all_keys(T),
                     [delete(T, K) || K <- Keys]
             end, tables())
       end).

persisted_valid_genesis_block() ->
    case application:get_env(aecore, persist, ?PERSIST) of
        false ->
            true;
        true ->
            ExpectedGH = aec_consensus:get_genesis_hash(),
            case aec_db:get_genesis_hash() of
                undefined ->
                    lager:info("Loaded empty persisted chain"),
                    true;
                ExpectedGH ->
                    true;
                LoadedGH ->
                    lager:warning("Expected genesis block hash ~p, persisted genesis block hash ~p",
                                  [ExpectedGH, LoadedGH]),
                    false
            end
    end.

backend_mode() ->
    case application:get_env(aecore, persist, ?PERSIST) of
        false -> expand_mode(ram);
        true  -> expand_mode(disc)
    end.

disc_backend_mode() ->
    {ok, BackendExpr} =
        aeu_env:find_config([<<"chain">>, <<"db_backend">>], [user_config,
                                                              schema_default,
                                                              {value, <<"mnesia">>}]),
    Backend = select_backend(BackendExpr),
    backend_mode(Backend, #{persist => true}).

%% The `db_backend` config option can have the format
%% "<backend>" | "<platform>:<backend> | "<platform>:<backend> [ | <p1:b1> ]*"
%% The alternatives are matched in order, and the first match is chosen.
%% The <platform> pattern may be "*", which matches any platform.
%%
select_backend(Expr) ->
    {Family, Name} = os:type(),
    FamilyB = atom_to_binary(Family, utf8),
    NameB = atom_to_binary(Name, utf8),
    Alts0 = re:split(Expr, <<"\\h*\\|\\h*">>, [{return,binary}]),
    Alts = [re:split(A, <<"\\h*:\\h*">>, [{return,binary}])
            || A <- Alts0],
    match_alts(Alts, FamilyB, NameB).

%% Platform is determined by `os:type() -> {OSFamily, OSName}`
%% We match on EITHER `OSFamily` or `OSName`, even though you're normally
%% not supposed to match on the name. This is so that we can distinguish
%% MacOS (`{unix,darwin}`) from e.g. linux (usually `{unix,linux}`).
%%
%% It's generally better to match on the OS family.
match_alts([[X,B]|_]      , F, N) when X=:=F; X=:=N -> B;
match_alts([[<<"*">>,B]|_], _, _) -> B;
match_alts([[B]|_]        , _, _) -> B;
match_alts([_|T]          , F, N) -> match_alts(T, F, N);
match_alts([]             , _, _) -> erlang:error(no_matching_backend).

backend_mode(_ , #{persist := false} = M) ->
        M#{ module => mnesia
          , alias => ram_copies
          };
backend_mode(<<"rocksdb">>, #{persist := true } = M) ->
        M#{ module => mnesia_rocksdb
          , alias => rocksdb_copies
          %% , user_properties => [ {rocksdb_opts,
          %%                         [
          %%                         ]}
          %%                      ]
          };
backend_mode(<<"leveled">>, #{persist := true } = M) ->
        M#{ module => mnesia_leveled
          , alias => leveled_copies
          };
backend_mode(<<"mnesia">>, #{persist := true } = M) ->
        M#{ module => mnesia
          , alias => disc_copies
          }.

ensure_transaction(Fun) when is_function(Fun, 0) ->
    ensure_activity(get_backend_module(), transaction, Fun).

ensure_activity(Type, Fun) when is_function(Fun, 0) ->
    ensure_activity(get_backend_module(), Type, Fun).

ensure_activity(mnesia_rocksdb, Type, Fun) ->
    lager:debug("Backend = mnesia_rocksdb, Type = ~p, F = ~p:~p/0",
                [Type, fun_info(Fun,module), fun_info(Fun,name)]),
    case mrdb:current_context() of
        undefined ->
            case get(mnesia_activity_state) of
                undefined ->
                    mrdb_activity(Type, Fun);
                {_, _, non_transaction} ->
                    mrdb_activity(Type, Fun);
                _ ->
                    Fun()
            end;
        #{type := tx} ->
            Fun();
        _ when Type == async_dirty; Type == sync_dirty ->
            Fun();
        _ ->
            mrdb_activity(Type, Fun)
    end;
ensure_activity(Backend, transaction, Fun) when is_function(Fun, 0) ->
    lager:debug("Backend = ~p, Type = transaction", [Backend]),
    case get(mnesia_activity_state) of
        undefined ->
            mnesia:activity(transaction, Fun);
        {_, _, non_transaction} ->
            %% Transaction inside a dirty context; rely on mnesia to handle it
            mnesia:activity(transaction, Fun);
        _ ->
            %% We are already in a transaction.
            Fun()
    end;
ensure_activity(Backend, PreferredType, Fun) when is_function(Fun, 0) ->
    lager:debug("Backend = ~p, Pref.Type = ~p", [Backend, PreferredType]),
    case get(mnesia_activity_state) of
        undefined ->
            mnesia:activity(PreferredType, Fun);
        _ ->
            Fun()
    end.

fun_info(F, K) ->
    {K, V} = erlang:fun_info(F, K),
    V.

mrdb_activity(Type, Fun) ->
    mrdb:activity(Type, rocksdb_copies, Fun).

%% ======================================================================
%% mnesia access wrappers
-spec read(atom(), term()) -> [tuple()].
read(Tab, Key) ->
    ?IF_RDB(mrdb:read(Tab, Key), mnesia:read(Tab, Key)).

dirty_read(Tab, Key) ->
    ?IF_RDB(mrdb:read(Tab, Key), mnesia:dirty_read(Tab, Key)).

index_read(Tab, IxVal, Ix) ->
    ?IF_RDB(mrdb:index_read(Tab, IxVal, Ix), mnesia:index_read(Tab, IxVal, Ix)).

write(Obj) ->
    write(element(1, Obj), Obj, write).

write(Tab, Obj, LockKind) ->
    ?IF_RDB(mrdb:insert(Tab, Obj), mnesia:write(Tab, Obj, LockKind)).

delete(Tab, Key) ->
    delete(Tab, Key, write).

delete(Tab, Key, LockKind) ->
    ?IF_RDB(mrdb:delete(Tab, Key), mnesia:delete(Tab, Key, LockKind)).

dirty_select(Tab, Pat) ->
    ?IF_RDB(mrdb:select(Tab, Pat), mnesia:dirty_select(Tab, Pat)).

db_foldl(Fun, InitAcc, Tab) ->
    ?IF_RDB(mrdb:fold(Tab, Fun, InitAcc, [{'_',[],['$_']}]),
            mnesia:foldl(Fun, InitAcc, Tab)).

all_keys(Tab) ->
    ?IF_RDB(mrdb:select(Tab, [{'$1',[],[{element,2,'$_'}]}]), mnesia:all_keys(Tab)).

%%
%% ======================================================================
-spec write_block(aec_blocks:block()) -> ok.
write_block(Block) ->
    Header = aec_blocks:to_header(Block),
    {ok, Hash} = aec_headers:hash_header(Header),
    write_block(Block, Hash).

-spec write_block(aec_blocks:block(), aec_hash:hash()) -> ok.
write_block(Block, Hash) ->
    Header = aec_headers:strip_extra(aec_blocks:to_header(Block)),
    Height = aec_headers:height(Header),

    case aec_blocks:type(Block) of
        key ->
            Headers = #aec_headers{ key = Hash
                                  , value = Header
                                  , height = Height },
            ?t(begin
                   write(Headers),
                   write(#aec_chain_state{key = {key_header, Height, Hash}, value = Header})
               end);
        micro ->
            Txs = aec_blocks:txs(Block),
            SignedTxs = [#aec_signed_tx{key = aetx_sign:hash(STx), value = STx} || STx <- Txs],
            ?t(begin
                   TxHashes = [begin
                                   write(SignedTx),
                                   SignedTx#aec_signed_tx.key
                               end || SignedTx <- SignedTxs],
                   Block1 = #aec_blocks{ key = Hash
                                       , txs = TxHashes
                                       , pof = aec_blocks:pof(Block) },
                   Headers = #aec_headers{ key = Hash
                                         , value = Header
                                         , height = Height },
                   write(Block1),
                   write(Headers)
               end)
    end.

-spec get_block(binary()) -> aec_blocks:block().
get_block(Hash) ->
    ?t(begin
           [#aec_headers{value = DBHeader}] =
               read(aec_headers, Hash),
           Header = aec_headers:from_db_header(DBHeader),
           case aec_headers:type(Header) of
               key ->
                   aec_blocks:new_key_from_header(Header);
               micro ->
                   [#aec_blocks{txs = TxHashes, pof = PoF}] =
                       read(aec_blocks, Hash),
                   Txs = [begin
                              [#aec_signed_tx{value = DBSTx}] =
                                  read(aec_signed_tx, TxHash),
                              aetx_sign:from_db_format(DBSTx)
                          end || TxHash <- TxHashes],
                   aec_blocks:new_micro_from_header(Header, Txs, PoF)
           end
       end).

find_block_tx_hashes(Hash) ->
    ?t(case read(aec_blocks, Hash) of
           [#aec_blocks{txs = TxHashes}] -> {value, TxHashes};
           [] -> none
       end).

get_header(Hash) ->
    ?t(begin
           [#aec_headers{value = DBHeader}] =
               read(aec_headers, Hash),
           aec_headers:from_db_header(DBHeader)
       end).

has_block(Hash) ->
    case ?t(read(aec_headers, Hash)) of
        [] -> false;
        [_] -> true
    end.

-spec find_block(binary()) -> 'none' | {'value', aec_blocks:block()}.
find_block(Hash) ->
    ?t(case read(aec_headers, Hash) of
           [#aec_headers{value = DBHeader}] ->
               Header = aec_headers:from_db_header(DBHeader),
               case aec_headers:type(Header) of
                   key   -> {value, aec_blocks:new_key_from_header(Header)};
                   micro ->
                       [#aec_blocks{txs = TxHashes, pof = PoF}]
                           = read(aec_blocks, Hash),
                       Txs = [begin
                                  [#aec_signed_tx{value = DBSTx}] =
                                      read(aec_signed_tx, TxHash),
                                  aetx_sign:from_db_format(DBSTx)
                              end || TxHash <- TxHashes],
                       {value, aec_blocks:new_micro_from_header(Header, Txs, PoF)}
               end;
           [] -> none
       end).

-spec get_block_from_micro_header(binary(), aec_headers:micro_header()) -> aec_blocks:micro_block().
get_block_from_micro_header(Hash, MicroHeader) ->
    aec_headers:assert_micro_header(MicroHeader),
    ?t(begin
        [#aec_blocks{txs = TxHashes, pof = PoF}] = read(aec_blocks, Hash),
        Txs = [begin
                  [#aec_signed_tx{value = DBSTx}] =
                      read(aec_signed_tx, TxHash),
                  aetx_sign:from_db_format(DBSTx)
              end || TxHash <- TxHashes],
        aec_blocks:new_micro_from_header(MicroHeader, Txs, PoF)
       end).

-spec find_key_block(binary()) -> 'none' | {'value', aec_blocks:key_block()}.
find_key_block(Hash) ->
    ?t(case read(aec_headers, Hash) of
           [#aec_headers{value = DBHeader}] ->
               Header = aec_headers:from_db_header(DBHeader),
               case aec_headers:type(Header) of
                   key   -> {value, aec_blocks:new_key_from_header(Header)};
                   micro -> none
               end;
           [] -> none
       end).

-spec find_header(binary()) -> 'none' | {'value', aec_headers:header()}.
find_header(Hash) ->
    case ?t(read(aec_headers, Hash)) of
        [#aec_headers{value = DBHeader}] -> {value, aec_headers:from_db_header(DBHeader)};
        [] -> none
    end.

%% Dirty dirty reads bypass mnesia entirely for some backends
%% This yields observable performance improvements for the rocksdb backend
-define(dirty_dirty_read(TABLE, KEY),
    begin
        case get_backend_module() of
            mnesia_rocksdb ->
                mrdb:read(TABLE, KEY);
            _ ->
                %% Otherwise let mnesia handle it
                dirty_read(TABLE, KEY)
        end
    end).

-spec dirty_find_header(binary()) -> 'none' | {'value', aec_headers:header()}.
dirty_find_header(Hash) ->
    case ?dirty_dirty_read(aec_headers, Hash) of
        [#aec_headers{value = DBHeader}] -> {value, aec_headers:from_db_header(DBHeader)};
        [] -> none
    end.

-spec find_headers_at_height(pos_integer()) -> [aec_headers:header()].
find_headers_at_height(Height) when is_integer(Height), Height >= 0 ->
    ?t([aec_headers:from_db_header(H) || #aec_headers{value = H}
                 <- index_read(aec_headers, Height, height)]).

-spec find_headers_and_hash_at_height(pos_integer()) ->
                                             [{binary(), aec_headers:header()}].
find_headers_and_hash_at_height(Height) when is_integer(Height), Height >= 0 ->
    ?t([{K, aec_headers:from_db_header(H)} || #aec_headers{key = K, value = H}
                 <- index_read(aec_headers, Height, #aec_headers.height)]).

%% When benchmarked on an cloud SSD it is faster then mnesia:index_read followed by filter
-spec find_key_headers_and_hash_at_height(pos_integer()) -> [{binary(), aec_headers:key_header()}].
find_key_headers_and_hash_at_height(Height) when is_integer(Height), Height >= 0 ->
    case persistent_term:get({?MODULE, chain_migration, key_headers}, done) of
        in_progress ->
            R = dirty_select(aec_headers, [{ #aec_headers{key = '_',
                                                          value = '$1',
                                                          height = Height}
                                           , [{'=:=', {element, 1, '$1'}, key_header}]
                                           , ['$_']}]),
            [{Hash, aec_headers:from_db_header(Header)}
             || #aec_headers{key = Hash, value = Header} <- R];
        done ->
            R = dirty_select(aec_chain_state,
                             [{#aec_chain_state{key = {key_header, Height, '_'},
                                                value = '_'}
                              , []
                              , ['$_']}]),
            [{Hash, aec_headers:from_db_header(Header)}
             || #aec_chain_state{key = {key_header, _, Hash}, value = Header} <- R]
    end.

find_discovered_pof(Hash) ->
    case ?t(read(aec_discovered_pof, Hash)) of
        [#aec_discovered_pof{value = PoF}] -> {value, PoF};
        [] -> none
    end.

write_discovered_pof(Hash, PoF) ->
    ?t(write(#aec_discovered_pof{key = Hash, value = PoF})).

write_block_state(Hash, Trees, AccDifficulty, ForkId, Fees, Fraud) ->
    ?t(begin
           Trees1 = aec_trees:serialize_for_db(aec_trees:commit_to_db(Trees)),
           BlockState = #aec_block_state{ key = Hash
                                        , value = Trees1
                                        , difficulty = AccDifficulty
                                        , fork_id = ForkId
                                        , fees = Fees
                                        , fraud = Fraud },
           write(BlockState)
       end).

write_accounts_node(Hash, Node) ->
    ?t(write(#aec_account_state{key = Hash, value = Node})).

write_accounts_node(Table, Hash, Node) ->
    ?t(write(Table, #aec_account_state{key = Hash, value = Node}, write)).

write_calls_node(Hash, Node) ->
    ?t(write(#aec_call_state{key = Hash, value = Node})).

write_channels_node(Hash, Node) ->
    ?t(write(#aec_channel_state{key = Hash, value = Node})).

write_contracts_node(Hash, Node) ->
    ?t(write(#aec_contract_state{key = Hash, value = Node})).

write_ns_node(Hash, Node) ->
    ?t(write(#aec_name_service_state{key = Hash, value = Node})).

write_ns_cache_node(Hash, Node) ->
    ?t(write(#aec_name_service_cache{key = Hash, value = Node})).

write_oracles_node(Hash, Node) ->
    ?t(write(#aec_oracle_state{key = Hash, value = Node})).

write_oracles_cache_node(Hash, Node) ->
    ?t(write(#aec_oracle_cache{key = Hash, value = Node})).

write_genesis_hash(Hash) when is_binary(Hash) ->
    ?t(write(#aec_chain_state{key = genesis_hash, value = Hash})).

write_top_block_node(Hash, Hdr) when is_binary(Hash) ->
    ?t(write(#aec_chain_state{key = top_block_node, value = #{ hash => Hash
                                                             , header => Hdr} })).

write_finalized_height(0) ->
    lager:debug("clearing finalized height", []),
    ?t(delete(aec_chain_state, finalized_height, write));
write_finalized_height(Height) when is_integer(Height), Height > 0 ->
    lager:debug("Height = ~p", [Height]),
    ?t(write(#aec_chain_state{key = finalized_height, value = Height})).

mark_chain_end_hash(Hash) when is_binary(Hash) ->
    ?t(write(#aec_chain_state{key = {end_block_hash, Hash}, value = []})).

unmark_chain_end_hash(Hash) when is_binary(Hash) ->
    ?t(delete(aec_chain_state, {end_block_hash, Hash}, write)).

find_chain_end_hashes() ->
    dirty_select(aec_chain_state, [{ #aec_chain_state{key = {end_block_hash, '$1'}, _ = '_'}, [], ['$1'] }]).

start_chain_migration(Key) ->
    %% Writes occur before the error store is initialized - if error keys are present then this will crash
    %% Fortunately this write will be correctly handled by the rocksdb bypass logic
    ?t(write(#aec_chain_state{key = {chain_migration_lock, Key}, value = lock})),
    persistent_term:put({?MODULE, chain_migration, Key}, in_progress).

finish_chain_migration(Key) ->
    ?t(delete(aec_chain_state, {chain_migration_lock, Key}, write)),
    persistent_term:erase({?MODULE, chain_migration, Key}).

-spec chain_migration_status(atom()) -> in_progress | done.
chain_migration_status(Key) ->
    case ?t(read(aec_chain_state, {chain_migration_lock, Key})) of
        [#aec_chain_state{}] -> in_progress;
        _ -> done
    end.

write_signal_count(Hash, Count) when is_binary(Hash), is_integer(Count) ->
    ?t(write(#aec_signal_count{key = Hash, value = Count})).

get_genesis_hash() ->
    get_chain_state_value(genesis_hash).

get_top_block_hash() ->
    case get_chain_state_value(top_block_node) of
        #{hash := Hash} ->
            Hash;
        undefined ->
            undefined
    end.

get_top_block_node() ->
    get_chain_state_value(top_block_node).

%% Some migration code: Ideally, top_block_node is there, and we're done.
%% If not, we should find top_block_hash. Fetch the corresponding
%% header, delete the obsolete top_block_hash and put in the new top_block_node.
convert_top_block_entry() ->
    ?t(convert_top_block_entry_()).

convert_top_block_entry_() ->
    case get_chain_state_value(top_block_node) of
        undefined ->
            case get_chain_state_value(top_block_hash) of
                undefined ->
                    ok;
                Hash ->
                    case find_header(Hash) of
                        {value, Header} ->
                            delete_chain_state_value(top_block_hash),
                            write_top_block_node(Hash, Header),
                            #{ hash => Hash
                             , header => Header };
                        none ->
                            weird
                    end
            end;
        _Node ->
            ok
    end.

get_finalized_height() ->
    get_chain_state_value(finalized_height).

dirty_get_finalized_height() ->
    dirty_get_chain_state_value(finalized_height).

get_block_state(Hash) ->
    get_block_state(Hash, false).

get_block_state(Hash, DirtyBackend) ->
    DeserializeFun =
        fun(Trees) ->
           aec_trees:deserialize_from_db(Trees, DirtyBackend)
        end,
    get_block_state_(Hash, DeserializeFun).

get_block_state_partial(Hash, DirtyBackend, Elements) ->
    DeserializeFun =
        fun(Trees) ->
            aec_trees:deserialize_from_db_partial(Trees, DirtyBackend,
                                                  Elements)
        end,
    get_block_state_(Hash, DeserializeFun).

get_block_state_(Hash, DeserializeFun) ->
    ?t(begin
           [#aec_block_state{value = Trees}] =
               read(aec_block_state, Hash),
           DeserializeFun(Trees)
       end).

find_block_state(Hash) ->
    find_block_state(Hash, false).

find_block_state(Hash, DirtyBackend) ->
    DeserializeFun =
        fun(Trees) ->
            aec_trees:deserialize_from_db(Trees, DirtyBackend)
        end,
    find_block_state_(Hash, DeserializeFun).

find_block_state_partial(Hash, DirtyBackend, Elements) ->
    DeserializeFun =
        fun(Trees) ->
            aec_trees:deserialize_from_db_partial(Trees, DirtyBackend,
                                                  Elements)
        end,
    find_block_state_(Hash, DeserializeFun).

find_block_state_(Hash, DeserializeFun) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{value = Trees}] ->
            {value, DeserializeFun(Trees)};
        [] -> none
    end.

find_block_difficulty(Hash) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{difficulty = D}] -> {value, D};
        [] -> none
    end.

find_block_fees(Hash) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{fees = F}] -> {value, F};
        [] -> none
    end.

find_block_fork_id(Hash) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{fork_id = F}] -> {value, F};
        [] -> none
    end.

find_block_fraud_status(Hash) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{fraud = FS}] -> {value, FS};
        [] -> none
    end.

find_block_state_and_data(Hash) ->
    find_block_state_and_data(Hash, false).

find_block_state_and_data(Hash, DirtyBackend) ->
    case ?t(read(aec_block_state, Hash)) of
        [#aec_block_state{value = Trees, difficulty = D,
                          fork_id = FId, fees = Fees,
                          fraud = Fraud}] ->
            {value, aec_trees:deserialize_from_db(Trees, DirtyBackend), D, FId, Fees, Fraud};
        [] -> none
    end.

find_oracles_node(Hash) ->
    case ?t(read(aec_oracle_state, Hash)) of
        [#aec_oracle_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_oracles_node(Hash) ->
    case ?dirty_dirty_read(aec_oracle_state, Hash) of
        [#aec_oracle_state{value = Node}] -> {value, Node};
        [] -> none
    end.

find_oracles_cache_node(Hash) ->
    case ?t(read(aec_oracle_cache, Hash)) of
        [#aec_oracle_cache{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_oracles_cache_node(Hash) ->
    case ?dirty_dirty_read(aec_oracle_cache, Hash) of
        [#aec_oracle_cache{value = Node}] -> {value, Node};
        [] -> none
    end.

find_calls_node(Hash) ->
    case ?t(read(aec_call_state, Hash)) of
        [#aec_call_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_calls_node(Hash) ->
    case ?dirty_dirty_read(aec_call_state, Hash) of
        [#aec_call_state{value = Node}] -> {value, Node};
        [] -> none
    end.

find_channels_node(Hash) ->
    case ?t(read(aec_channel_state, Hash)) of
        [#aec_channel_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_channels_node(Hash) ->
    case ?dirty_dirty_read(aec_channel_state, Hash) of
        [#aec_channel_state{value = Node}] -> {value, Node};
        [] -> none
    end.

find_contracts_node(Hash) ->
    case ?t(read(aec_contract_state, Hash)) of
        [#aec_contract_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_contracts_node(Hash) ->
    case ?dirty_dirty_read(aec_contract_state, Hash) of
        [#aec_contract_state{value = Node}] -> {value, Node};
        [] -> none
    end.

find_ns_node(Hash) ->
    case ?t(read(aec_name_service_state, Hash)) of
        [#aec_name_service_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_ns_node(Hash) ->
    case ?dirty_dirty_read(aec_name_service_state, Hash) of
        [#aec_name_service_state{value = Node}] -> {value, Node};
        [] -> none
    end.

find_ns_cache_node(Hash) ->
    case ?t(read(aec_name_service_cache, Hash)) of
        [#aec_name_service_cache{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_ns_cache_node(Hash) ->
    case ?dirty_dirty_read(aec_name_service_cache, Hash) of
        [#aec_name_service_cache{value = Node}] -> {value, Node};
        [] -> none
    end.

find_accounts_node(Hash) ->
    case ?t(read(aec_account_state, Hash)) of
        [#aec_account_state{value = Node}] -> {value, Node};
        [] -> none
    end.

dirty_find_accounts_node(Hash) ->
    case ?dirty_dirty_read(aec_account_state, Hash) of
        [#aec_account_state{value = Node}] -> {value, Node};
        [] -> none
    end.

get_chain_state_value(Key) ->
    ?t(case read(aec_chain_state, Key) of
           [#aec_chain_state{value = Value}] ->
               Value;
           _ ->
               undefined
       end).

delete_chain_state_value(Key) ->
    ?t(delete(aec_chain_state, Key)).

dirty_get_chain_state_value(Key) ->
    case ?dirty_dirty_read(aec_chain_state, Key) of
        [#aec_chain_state{value = Value}] ->
            Value;
        [] ->
            undefined
    end.

gc_tx(TxHash) ->
    ?t(case find_tx_location(TxHash) of
           BlockHash when is_binary(BlockHash) ->
               {error, BlockHash};
           mempool ->
               delete(aec_tx_pool, TxHash);
           none ->
               ok;
           not_found ->
               {error, tx_not_found}
       end).

get_signed_tx(Hash) ->
    [#aec_signed_tx{value = DBSTx}] = ?t(read(aec_signed_tx, Hash)),
    aetx_sign:from_db_format(DBSTx).

dirty_get_signed_tx(Hash) ->
    case ?dirty_dirty_read(aec_signed_tx, Hash) of
        [#aec_signed_tx{value = DBSTx}] -> {ok, aetx_sign:from_db_format(DBSTx)};
        [] -> none
    end.

find_signed_tx(Hash) ->
    case ?t(read(aec_signed_tx, Hash)) of
        []                            -> none;
        [#aec_signed_tx{value = DBSTx}] -> {value, aetx_sign:from_db_format(DBSTx)}
    end.

find_signal_count(Hash) ->
    case ?t(read(aec_signal_count, Hash)) of
        [#aec_signal_count{value = Count}] ->
            {value, Count};
        [] ->
            none
    end.

add_tx_location(STxHash, BlockHash) when is_binary(STxHash),
                                         is_binary(BlockHash) ->
    ?t(write(#aec_tx_location{key = STxHash, value = BlockHash})).

remove_tx_location(TxHash) when is_binary(TxHash) ->
    ?t(delete(aec_tx_location, TxHash)).

find_tx_location(STxHash) ->
    ?t(case read(aec_tx_location, STxHash) of
           [] ->
               case read(aec_tx_pool, STxHash) of
                   [] -> case read(aec_signed_tx, STxHash) of
                             [] -> not_found;
                             [_] -> none
                         end;
                   [_] -> mempool
               end;
           [#aec_tx_location{value = BlockHash}] -> BlockHash
       end).

-spec find_tx_with_location(binary()) ->
                                   'none'
                                 | {'mempool', aetx_sign:signed_tx()}
                                 | {binary(), aetx_sign:signed_tx()}.
find_tx_with_location(STxHash) ->
    ?t(case read(aec_signed_tx, STxHash) of
           [#aec_signed_tx{value = DBSTx}] ->
               case read(aec_tx_location, STxHash) of
                   [] ->
                       case read(aec_tx_pool, STxHash) of
                           [] -> none;
                           [_] -> {mempool, aetx_sign:from_db_format(DBSTx)}
                       end;
                   [#aec_tx_location{value = BlockHash}] ->
                       {BlockHash, aetx_sign:from_db_format(DBSTx)}
               end;
           [] -> none
       end).

remove_tx(TxHash) ->
    ?t(begin
           remove_tx_location(TxHash),
           mnesia:delete({aec_signed_tx, TxHash})
       end).

add_tx(STx) ->
    Hash = aetx_sign:hash(STx),
    ?t(case read(aec_signed_tx, Hash) of
           [#aec_signed_tx{value = STx}] ->
              case read(aec_tx_location, Hash) of
                   [] -> %% the transaction had either been GCed or is in mempool
                      add_tx_hash_to_mempool(Hash), %% ensure in mempool
                      {ok, Hash};
                   [_] -> {error, already_exists}
              end;
           [] ->
               Obj = #aec_signed_tx{key = Hash, value = STx},
               write(Obj),
               add_tx_hash_to_mempool(Hash),
               {ok, Hash}
       end).

add_tx_hash_to_mempool(TxHash) when is_binary(TxHash) ->
    ?t(write(#aec_tx_pool{key = TxHash, value = ?TX_IN_MEMPOOL})).

is_in_tx_pool(TxHash) ->
    ?t(read(aec_tx_pool, TxHash)) =/= ?TX_IN_MEMPOOL.

remove_tx_from_mempool(TxHash) when is_binary(TxHash) ->
    ?t(delete(aec_tx_pool, TxHash)).

fold_mempool(FunIn, InitAcc) ->
    Fun = fun(#aec_tx_pool{key = Hash}, Acc) ->
                  FunIn(Hash, Acc)
          end,
    ?t(db_foldl(Fun, InitAcc, aec_tx_pool)).

%% start phase hook to load the database

load_database() ->
    lager:debug("load_database()", []),
    wait_for_tables(),
    convert_top_block_entry(),
    aec_db_gc:maybe_swap_nodes().

wait_for_tables() ->
    Tabs = mnesia:system_info(tables) -- [schema],
    lager:debug("wait_for_tables (~p)", [Tabs]),
    wait_for_tables(Tabs, 0, _TimePeriods = 5, _MaxWait = 60).

wait_for_tables(Tabs, Sofar, Period, Max) when Sofar < Max ->
    case mnesia:wait_for_tables(Tabs, timer:minutes(Period)) of
        ok ->
            ok;
        {timeout, NotLoaded} ->
            lager:warning("Tables not loaded after ~p minutes: ~p",
                          [Period, NotLoaded]),
            wait_for_tables(NotLoaded, Sofar + Period, Period, Max)
    end;
wait_for_tables(Tabs, Sofar, _, _) ->
    lager:error("Tables not loaded after ~p minutes: ~p", [Sofar, Tabs]),
    %% This is serious and user intervention needed. Stop the system instead
    %% of keeping retrying, but also raise an error for the crash log.
    init:stop(),
    erlang:error({tables_not_loaded, Tabs}).

%% Initialization routines

check_db() ->
    try
        %% We need to start lager here in case something goes wrong - otherwise instead of nice
        %% debugging logs we will get an erl_crash.dump with a truncated stack trace.
        lager:start(),
        Mode = backend_mode(),
        put_backend_module(Mode),
        Storage = ensure_schema_storage_mode(Mode),
        lager:info("Database persist mode ~p", [maps:get(persist, Mode)]),
        lager:info("Database backend ~p", [maps:get(module, Mode)]),
        lager:info("Database directory ~s", [mnesia:system_info(directory)]),
        ok = application:ensure_started(mnesia),
        ok = assert_schema_node_name(Mode),
        initialize_db(Mode, Storage)
    catch error:Reason:StackTrace ->
        error_logger:error_msg("CAUGHT error:~p / ~p~n", [Reason, StackTrace]),
        erlang:error(Reason)
    end.

start_db() ->
    load_database(),
    aefa_fate_op:load_pre_iris_map_ordering(),
    case aec_db:persisted_valid_genesis_block() of
        true ->
            aec_chain_state:ensure_chain_ends(),
            aec_chain_state:ensure_key_headers_height_store(),
            ok;
        false ->
            lager:error("Persisted chain has a different genesis block than "
                        ++ "the one being expected. Aborting", []),
            error(inconsistent_database)
    end.

put_backend_module(#{module := M}) ->
    persistent_term:put({?MODULE, backend_module}, M).

get_backend_module() ->
    persistent_term:get({?MODULE, backend_module}).

%% Test interface
initialize_db(ram) ->
    initialize_db(expand_mode(ram), ok).

initialize_db(Mode, Storage) ->
    add_backend_plugins(Mode),
    run_hooks('$aec_db_add_plugins', Mode),
    add_index_plugins(),
    run_hooks('$aec_db_add_index_plugins', Mode),
    ensure_mnesia_tables(Mode, Storage),
    ok.

expand_mode(ram)  -> backend_mode(<<"mnesia">>, #{persist => false});
expand_mode(disc) -> disc_backend_mode();
expand_mode(M) when is_map(M) -> M.

run_hooks(Hook, Mode) ->
    [M:F(Mode) || {_App, {M,F}} <- setup:find_env_vars(Hook)].

fold_hooks(Hook, Acc0) ->
    lists:foldl(
      fun({_App, {M,F}}, Acc) ->
              M:F(Acc)
      end, Acc0, setup:find_env_vars(Hook)).

add_backend_plugins(#{module := Mod, alias := Alias}) when Mod =/= mnesia ->
    Mod:register(Alias);
add_backend_plugins(_) ->
    ok.

add_index_plugins() ->
    ok.

ensure_mnesia_tables(Mode, Storage) ->
    Tables = tables(Mode),
    case Storage of
        existing_schema ->
            handle_table_errors(Tables, Mode, check_mnesia_tables(Tables, []));
        ok ->
            [{atomic,ok} = mnesia:create_table(T, Spec) || {T, Spec} <- Tables],
            run_hooks('$aec_db_create_tables', Mode),
            ok
    end.

handle_table_errors(_Tables, _Mode, []) ->
    ok;
handle_table_errors(Tables, Mode, [{missing_table, aec_signal_count = Table} | Tl]) ->
    %% The table is new in node version 5.1.0.
    new_table_migration(Table, Tables),
    handle_table_errors(Tables, Mode, Tl);
handle_table_errors(Tables, Mode, [{missing_table, aec_peers = Table} | Tl]) ->
    %% The table is new in node version 5.6.0.
    new_table_migration(Table, Tables),
    handle_table_errors(Tables, Mode, Tl);
handle_table_errors(Tables, Mode, [{missing_table, aesc_state_cache_v2} | Tl]) ->
    aesc_db:create_tables(Mode),
    handle_table_errors(Tables, Mode, Tl);
handle_table_errors(Tables, Mode, [{callback, {Mod, Fun, Args}} | Tl]) ->
    apply(Mod, Fun, Args),
    handle_table_errors(Tables, Mode, Tl);
handle_table_errors(_Tables, _Mode, Errors) ->
    lager:error("Database check failed: ~p", [Errors]),
    erlang:error({table_check, Errors}).

check_mnesia_tables([{Table, Spec}|Left], Acc) ->
    NewAcc = check_table(Table, Spec, Acc),
    check_mnesia_tables(Left, NewAcc);
check_mnesia_tables([], Acc) ->
    fold_hooks('$aec_db_check_tables', Acc).

check_table(Table, Spec, Acc) ->
    try
        UserProps = mnesia:table_info(Table, user_properties),
        UserPropsSpec = proplists:get_value(user_properties, Spec, []),
        Vsn = proplists:get_value(vsn, UserProps),
        VsnSpec = proplists:get_value(vsn, UserPropsSpec),
        if
            Vsn =:= undefined ->
                [{missing_version, Table, UserProps}|Acc];
            VsnSpec =:= undefined ->
                [{missing_version_in_spec, Table, UserProps}|Acc];
            Vsn =:= VsnSpec ->
                Acc;
            true ->
                %% old version and spec are not equal
                {vsn, Old} = VsnSpec,
                {vsn, New} = Vsn,
                [{vsn_fail, Table, [{expected, New}, {got, Old}]}|Acc]
        end
    catch
        _:_ ->
            [{missing_table, Table}|Acc]
    end.

assert_schema_node_name(#{persist := false}) ->
    ok;
assert_schema_node_name(#{persist := true}) ->
    [DbOwnerNode] = mnesia:table_info(schema, all_nodes),
    case DbOwnerNode =:= node() of
        true -> ok;
        false ->
            {ok,_DbDir} = aeu_env:find_config([<<"chain">>, <<"db_path">>],
                                              [user_config, schema_default]),
            error_logger:error_msg("Database cannot be loaded. "
                                   "It was created for the node ~p, and current node "
                                   "is ~p (these must not differ!).",
                        [DbOwnerNode, node()]),
            exit(wrong_db_owner_node)
    end.

ensure_schema_storage_mode(#{persist := false}) ->
    case disc_db_exists() of
        {true, Dir} ->
            lager:warning("Will not use existing Mnesia db (~s)", [Dir]),
            set_dummy_mnesia_dir(Dir);
        false ->
            ok
    end;
ensure_schema_storage_mode(#{persist := true}) ->
    case mnesia:create_schema([node()]) of
        {error, {_, {already_exists, _}}} -> existing_schema;
        ok -> ok
    end.

disc_db_exists() ->
    Dir = default_dir(),
    case f_exists(Dir) of
        true ->
            {true, Dir};
        false ->
            false
    end.

f_exists(F) ->
    case file:read_link_info(F) of
        {ok, _} -> true;
        _ -> false
    end.

set_dummy_mnesia_dir(Dir) ->
    TS = erlang:system_time(millisecond),
    NewDir = find_nonexisting(filename:absname(Dir), TS),
    application:set_env(mnesia, dir, NewDir).

find_nonexisting(Dir, N) ->
    Path = Dir ++ "-" ++ integer_to_list(N),
    case f_exists(Path) of
        true ->
            find_nonexisting(Dir, N+1);
        false ->
            Path
    end.

default_dir() ->
    case application:get_env(mnesia, dir) of
        undefined ->
            %% This is is how mnesia produces the default. The result will
            %% be the same as long as the current working directory doesn't
            %% change between now and when mnesia starts.
            filename:absname(lists:concat(["Mnesia.", node()]));
        {ok, Dir} ->
            Dir
    end.

write_peer(Peer) ->
    PeerId = aec_peer:id(Peer),
    ?t(write(#aec_peers{key = PeerId, value = Peer})).

delete_peer(Peer) ->
    PeerId = aec_peer:id(Peer),
    ?t(delete(aec_peers, PeerId)).

%% to be used only in aec_sync:init to load persisted peeers
read_all_peers() ->
    Fun = fun(#aec_peers{value = Peer}, Acc) ->
              [Peer | Acc]
          end,
    ?t(db_foldl(Fun, [], aec_peers)).

new_table_migration(Table, Tables) ->
    {Table, Spec} = lists:keyfind(Table, 1, Tables),
    {atomic, ok} = mnesia:create_table(Table, Spec).
