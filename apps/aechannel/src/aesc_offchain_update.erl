-module(aesc_offchain_update).

-export([ op_transfer/3
        , op_deposit/2
        , op_withdraw/2
        , op_new_contract/6
        , op_call_contract/6
        , op_call_contract/8
        , op_meta/1
        ]).

-export([serialize/1,
         deserialize/1,
         for_client/1,
         apply_on_trees/6]).

-export([is_call/1,
         is_contract_create/1,
         extract_call/1,
         extract_caller/1,
         extract_contract_pubkey/1,
         extract_amounts/1,
         extract_abi_version/1]).

-export([get_gas_price/1,
         set_gas_price/2]).

-export([from_db_format/1
        ]).

-ifdef(TEST).
-export([type2swagger_name/1]).
-endif.

-include_lib("aecontract/include/hard_forks.hrl").

-define(UPDATE_VSN_1, 1).
-define(UPDATE_VSN_2, 2).

-record(transfer, {
          from_id      :: aeser_id:id(),
          to_id        :: aeser_id:id(),
          amount       :: non_neg_integer()
         }).

-record(withdraw, {
          to_id        :: aeser_id:id(),
          amount       :: non_neg_integer()
         }).

-record(deposit, {
          from_id      :: aeser_id:id(),
          amount       :: non_neg_integer()
         }).

-record(create_contract, {
          owner_id     :: aeser_id:id(),
          vm_version   :: aect_contracts:vm_version(),
          abi_version  :: aect_contracts:abi_version(),
          code         :: binary(),
          deposit      :: non_neg_integer(),
          call_data    :: binary()
         }).

-record(call_contract, {
          caller_id    :: aeser_id:id(),
          contract_id  :: aeser_id:id(),
          abi_version  :: aect_contracts:abi_version(),
          amount       :: non_neg_integer(),
          call_data    :: binary(),
          call_stack   :: [non_neg_integer()],
          gas_price    :: non_neg_integer(),
          gas          :: non_neg_integer()
         }).

-record(meta, { data :: binary() }).

-opaque update() :: #transfer{}
                  | #withdraw{}
                  | #deposit{}
                  | #create_contract{}
                  | #call_contract{}
                  | #meta{}.

-type update_type() :: transfer | withdraw | deposit | create_contract |
                       call_contract | meta.

-type contract_result() :: {ok, any()} | {failed, any()}.
-type update_result() :: ok | contract_result().

-export_type([update/0]).

-spec from_db_format(update() | tuple()) -> update().
from_db_format(#transfer{} = U) ->
    U;
from_db_format(#withdraw{} = U) ->
    U;
from_db_format(#deposit{} = U) ->
    U;
from_db_format(#create_contract{} = U) ->
    U;
from_db_format(#call_contract{} = U) ->
    U;
from_db_format(#meta{} = U) ->
    U;
from_db_format(Tuple) ->
    OldType = element(1, Tuple),
    NewType = maps:get(OldType, #{0 => transfer,
                                  1 => withdraw,
                                  2 => deposit,
                                  3 => create_contract,
                                  4 => call_contract}),
    Updated = setelement(1, Tuple, NewType),
    case Updated of
        #transfer{} -> Updated;
        #withdraw{} -> Updated;
        #deposit{} -> Updated;
        #create_contract{} -> Updated;
        #call_contract{} -> Updated;
        _ ->
            error(illegal_db_format)
    end.

-spec op_transfer(aeser_id:id(), aeser_id:id(), non_neg_integer()) -> update().
op_transfer(From, To, Amount) ->
    account = aeser_id:specialize_type(From),
    account = aeser_id:specialize_type(To),
    #transfer{from_id = From,
              to_id   = To,
              amount  = Amount}.

-spec op_deposit(aeser_id:id(), non_neg_integer()) -> update().
op_deposit(FromId, Amount) ->
    account = aeser_id:specialize_type(FromId),
    #deposit{from_id = FromId, amount = Amount}.

-spec op_withdraw(aeser_id:id(), non_neg_integer()) -> update().
op_withdraw(ToId, Amount) ->
    account = aeser_id:specialize_type(ToId),
    #withdraw{to_id = ToId, amount = Amount}.

-spec op_new_contract(aeser_id:id(), aect_contracts:vm_version(), aect_contracts:abi_version(),
           binary(), non_neg_integer(), binary()) -> update().
op_new_contract(OwnerId, VmVersion, ABIVersion, Code, Deposit, CallData) ->
    account = aeser_id:specialize_type(OwnerId),
    #create_contract{owner_id    = OwnerId,
                     vm_version  = VmVersion,
                     abi_version = ABIVersion,
                     code        = Code,
                     deposit     = Deposit,
                     call_data   = CallData}.

-spec op_call_contract(aeser_id:id(), aeser_id:id(), aect_contracts:abi_version(),
                       non_neg_integer(), Call, [non_neg_integer()]) -> update()
    when Call :: _.
op_call_contract(CallerId, ContractId, ABIVersion, Amount, CallData, CallStack) ->
    op_call_contract(CallerId, ContractId, ABIVersion, Amount, CallData,
                     CallStack, 1, 1000000).
-spec op_call_contract(aeser_id:id(), aeser_id:id(), aect_contracts:abi_version(),
                       non_neg_integer(), Call,
                       [non_neg_integer()],
                       non_neg_integer(), non_neg_integer()) -> update()
    when Call :: _.
op_call_contract(CallerId, ContractId, ABIVersion, Amount, CallData, CallStack,
                 GasPrice, Gas) ->
    account = aeser_id:specialize_type(CallerId),
    contract = aeser_id:specialize_type(ContractId),
    #call_contract{caller_id = CallerId,
                   contract_id = ContractId,
                   abi_version = ABIVersion,
                   amount = Amount,
                   call_data = CallData,
                   call_stack = CallStack,
                   gas_price = GasPrice,
                   gas = Gas}.

op_meta(Data) ->
    #meta{ data = Data }.

-spec apply_on_trees(aesc_offchain_update:update(), aec_trees:trees(),
                     aec_trees:trees(), aetx_env:env(),
                     non_neg_integer(), non_neg_integer()) ->
          {update_result(), aec_trees:trees()}.
apply_on_trees(Update, Trees0, OnChainTrees, OnChainEnv, Round, Reserve) ->
    case Update of
        #transfer{from_id = FromId, to_id = ToId, amount = Amount} ->
            From = account_pubkey(FromId),
            To = account_pubkey(ToId),
            Trees = remove_tokens(From, Amount, Trees0, Reserve),
            {ok, add_tokens(To, Amount, Trees)};
        #deposit{from_id = FromId, amount = Amount} ->
            From = account_pubkey(FromId),
            {ok, add_tokens(From, Amount, Trees0)};
        #withdraw{to_id = ToId, amount = Amount} ->
            To = account_pubkey(ToId),
            {ok, remove_tokens(To, Amount, Trees0, Reserve)};
        #create_contract{owner_id = OwnerId, vm_version  = VmVersion,
                         abi_version = ABIVersion, code = Code,
                         deposit = Deposit, call_data   = CallData} ->
            Owner = account_pubkey(OwnerId),
            {ContractId, _Contract, Trees1} =
                aect_channel_contract:new(Owner, Round, #{vm => VmVersion, abi => ABIVersion},
                                          Code, Deposit, Trees0),
            ContractPubKey = contract_pubkey(ContractId),
            Trees2 = remove_tokens(Owner, Deposit, Trees1, Reserve),
            Trees3 = create_account(ContractPubKey, Trees2),
            Trees4 = add_tokens(ContractPubKey, Deposit, Trees3),
            Call = aect_call:new(OwnerId, Round, ContractId, Round, 0),
            Trees = aect_channel_contract:run_new(ContractPubKey, Call, CallData, Trees4,
                                                  OnChainTrees, OnChainEnv),
            {ok, Trees};
        #call_contract{caller_id = CallerId, contract_id = ContractId,
                       abi_version = ABIVersion, amount = Amount,
                       call_data = CallData, call_stack = CallStack,
                       gas_price = GasPrice, gas = Gas} ->
            Fee    = 0,
            Caller = account_pubkey(CallerId),
            ContractPubKey = contract_pubkey(ContractId),
            Trees1 = remove_tokens(Caller, Amount, Trees0, Reserve),
            Trees2 = add_tokens(ContractPubKey, Amount, Trees1),
            Call = aect_call:new(CallerId, Round, ContractId, Round, GasPrice),
            {Trees, CallRes}
                = aect_channel_contract:run(ContractPubKey, ABIVersion, Call,
                                            CallData, CallStack,
                                            Trees2, Amount, GasPrice, Fee, Gas,
                                            OnChainTrees, OnChainEnv,
                                            Caller),
            case aect_call:return_type(CallRes) of
                ok ->
                    {{ok, CallRes}, Trees};
                Failed when Failed =:= error;
                            Failed =:= revert ->
                    %% the off-chain contract call failed. Revert the amounts
                    %% this has impact on the on-chain when this is being used
                    %% as in a ForceProgress transaction. Active since Iris
                    case is_protocol_active(OnChainEnv, ?IRIS_PROTOCOL_VSN) of
                        true ->
                            %% the contract is not subject to the minimum
                            %% channel reserve and thus is allowed to go as
                            %% low as 0 tokens:
                            Trees3 = remove_tokens(ContractPubKey, Amount, Trees,
                                                   0),
                            Trees4 = add_tokens(Caller, Amount, Trees3),
                            {{Failed, CallRes}, Trees4};
                        false ->
                            {{Failed, CallRes}, Trees}
                    end
            end;
        #meta{} ->
            {ok, Trees0}
    end.

-spec for_client(update()) -> map().
for_client(#transfer{from_id = FromId, to_id = ToId, amount = Amount}) ->
    #{<<"op">>      => type2swagger_name(transfer),
      <<"from">>    => aeser_api_encoder:encode(id_hash, FromId),
      <<"to">>      => aeser_api_encoder:encode(id_hash, ToId),
      <<"amount">>  => Amount};
for_client(#withdraw{to_id = ToId, amount = Amount}) ->
    #{<<"op">>      => type2swagger_name(withdraw),
      <<"to">>      => aeser_api_encoder:encode(id_hash, ToId),
      <<"amount">>  => Amount};
for_client(#deposit{from_id = FromId, amount = Amount}) ->
    #{<<"op">>      => type2swagger_name(deposit),
      <<"from">>    => aeser_api_encoder:encode(id_hash, FromId),
      <<"amount">>  => Amount};
for_client(#create_contract{owner_id = OwnerId, vm_version  = VmVersion,
                         abi_version = ABIVersion, code = Code,
                         deposit = Deposit, call_data   = CallData}) ->
    #{<<"op">>          => type2swagger_name(create_contract),
      <<"owner">>       => aeser_api_encoder:encode(id_hash, OwnerId),
      <<"vm_version">>  => VmVersion,
      <<"abi_version">> => ABIVersion,
      <<"code">>        => aeser_api_encoder:encode(contract_bytearray, Code),
      <<"deposit">>     => Deposit,
      <<"call_data">>   => aeser_api_encoder:encode(contract_bytearray, CallData)};
for_client(#call_contract{caller_id = CallerId, contract_id = ContractId,
                          abi_version = ABIVersion, amount = Amount,
                          call_data = CallData, call_stack = CallStack,
                          gas_price = GasPrice, gas = Gas}) ->
    #{<<"op">>          => type2swagger_name(call_contract),
      <<"caller_id">>   => aeser_api_encoder:encode(id_hash, CallerId),
      <<"contract_id">> => aeser_api_encoder:encode(id_hash, ContractId),
      <<"abi_version">> => ABIVersion,
      <<"amount">>      => Amount,
      <<"gas">>         => Gas,
      <<"gas_price">>   => GasPrice,
      <<"call_data">>   => aeser_api_encoder:encode(contract_bytearray, CallData),
      <<"call_stack">>  => CallStack};
for_client(#meta{data = Data}) ->
    #{<<"op">>   => type2swagger_name(meta),
      <<"data">> => Data}.

vsn(#meta{}) -> ?UPDATE_VSN_2;
vsn(_) -> ?UPDATE_VSN_1.

-spec serialize(update()) -> binary().
serialize(Update) ->
    Fields = update2fields(Update),
    Vsn = vsn(Update),
    UpdateType = record_to_update_type(Update),
    aeser_chain_objects:serialize(
      ut2type(UpdateType),
      Vsn,
      update_serialization_template(Vsn, UpdateType),
      Fields).

-spec deserialize(binary()) -> update().
deserialize(Bin) ->
    {Type, Vsn, RawFields} =
        aeser_chain_objects:deserialize_type_and_vsn(Bin),
    UpdateType = type2ut(Type),
    Template = update_serialization_template(Vsn, UpdateType),
    Fields = aeserialization:decode_fields(Template, RawFields),
    fields2update(UpdateType, Fields).

update2fields(#transfer{from_id = FromId, to_id = ToId, amount = Amount}) ->
    [ {from,    FromId},
      {to,      ToId},
      {amount,  Amount}];
update2fields(#deposit{from_id = FromId, amount = Amount}) ->
    [ {from,    FromId},
      {amount,  Amount}];
update2fields(#withdraw{to_id = ToId, amount = Amount}) ->
    [ {to,      ToId},
      {amount,  Amount}];
update2fields(#create_contract{owner_id = OwnerId, vm_version  = VmVersion,
                               abi_version = ABIVersion, code = Code,
                               deposit = Deposit, call_data   = CallData}) ->
    [ {owner, OwnerId},
      {ct_version, aect_contracts:pack_vm_abi(#{vm => VmVersion, abi => ABIVersion})},
      {code, Code},
      {deposit, Deposit},
      {call_data, CallData}];
update2fields(#call_contract{caller_id = CallerId, contract_id = ContractId,
                             abi_version = ABIVersion, amount = Amount,
                             call_data = CallData, call_stack = CallStack,
                             gas_price = GasPrice, gas = Gas}) ->
    [ {caller, CallerId},
      {contract, ContractId},
      {abi_version, ABIVersion},
      {amount, Amount},
      {gas, Gas},
      {gas_price, GasPrice},
      {call_data, CallData},
      {call_stack, CallStack}];
update2fields(#meta{data = Data}) ->
    [ {data, Data} ].

-spec fields2update(update_type(), list()) -> update().
fields2update(transfer, [{from,   From},
                         {to,     To},
                         {amount, Amount}]) ->
    op_transfer(From, To, Amount);
fields2update(deposit, [{from,   From},
                        {amount, Amount}]) ->
    op_deposit(From, Amount);
fields2update(withdraw, [{to,    To},
                         {amount, Amount}]) ->
    op_withdraw(To, Amount);
fields2update(create_contract, [{owner, OwnerId},
                                {ct_version, CTVersion},
                                {code, Code},
                                {deposit, Deposit},
                                {call_data, CallData}]) ->
    #{vm := VmVersion, abi := ABIVersion} = aect_contracts:split_vm_abi(CTVersion),
    op_new_contract(OwnerId, VmVersion, ABIVersion, Code, Deposit, CallData);
fields2update(call_contract, [ {caller, CallerId},
                               {contract, ContractId},
                               {abi_version, ABIVersion},
                               {amount, Amount},
                               {gas, Gas},
                               {gas_price, GasPrice},
                               {call_data, CallData},
                               {call_stack, CallStack}]) ->
    op_call_contract(CallerId, ContractId, ABIVersion, Amount, CallData,
                     CallStack, GasPrice, Gas);
fields2update(meta, [{data, Data}]) ->
    op_meta(Data).

-spec ut2type(update_type())  -> atom().
ut2type(transfer)             -> channel_offchain_update_transfer;
ut2type(deposit)              -> channel_offchain_update_deposit;
ut2type(withdraw)             -> channel_offchain_update_withdraw;
ut2type(create_contract)      -> channel_offchain_update_create_contract;
ut2type(call_contract)        -> channel_offchain_update_call_contract;
ut2type(meta)                 -> channel_offchain_update_meta.

-spec type2ut(atom()) -> update_type().
type2ut(channel_offchain_update_transfer)         -> transfer;
type2ut(channel_offchain_update_deposit)          -> deposit;
type2ut(channel_offchain_update_withdraw)         -> withdraw;
type2ut(channel_offchain_update_create_contract)  -> create_contract;
type2ut(channel_offchain_update_call_contract)    -> call_contract;
type2ut(channel_offchain_update_meta)             -> meta.

-spec type2swagger_name(update_type()) -> binary().
type2swagger_name(transfer)        -> <<"OffChainTransfer">>;
type2swagger_name(deposit)         -> <<"OffChainDeposit">>;
type2swagger_name(withdraw)        -> <<"OffChainWithdrawal">>;
type2swagger_name(create_contract) -> <<"OffChainNewContract">>;
type2swagger_name(call_contract)   -> <<"OffChainCallContract">>;
type2swagger_name(meta)            -> <<"OffChainMeta">>.

-spec update_serialization_template(non_neg_integer(), update_type()) -> list().
update_serialization_template(V, transfer) when V =:= ?UPDATE_VSN_1 ->
    [ {from,    id},
      {to,      id},
      {amount,  int}];
update_serialization_template(V, deposit) when V =:= ?UPDATE_VSN_1 ->
    [ {from,    id},
      {amount,  int}];
update_serialization_template(V, withdraw) when V =:= ?UPDATE_VSN_1 ->
    [ {to,      id},
      {amount,  int}];
update_serialization_template(V, create_contract) when V =:= ?UPDATE_VSN_1 ->
    [ {owner,       id},
      {ct_version,  int},
      {code,        binary},
      {deposit,     int},
      {call_data,   binary}];
update_serialization_template(V, call_contract) when V =:= ?UPDATE_VSN_1 ->
    [ {caller,      id},
      {contract,    id},
      {abi_version, int},
      {amount,      int},
      {gas,         int},
      {gas_price,   int},
      {call_data,   binary},
      {call_stack,  [int]}];
update_serialization_template(?UPDATE_VSN_2, meta) ->
    [ {data, binary} ].

-spec record_to_update_type(update()) -> update_type().
record_to_update_type(#transfer{})        -> transfer;
record_to_update_type(#deposit{})         -> deposit;
record_to_update_type(#withdraw{})        -> withdraw;
record_to_update_type(#create_contract{}) -> create_contract;
record_to_update_type(#call_contract{})   -> call_contract;
record_to_update_type(#meta{})            -> meta.

check_min_amt(Amt, Reserve) ->
    if Amt < Reserve ->
            update_error(insufficient_balance);
       true ->
            Amt
    end.

create_account(Pubkey, Trees) ->
    AccountTrees = aec_trees:accounts(Trees),
    %TODO none = aec_accounts_trees:lookup(Pubkey, Trees),
    Acc = aec_accounts:new(Pubkey, 0),
    AccountTrees1 = aec_accounts_trees:enter(Acc, AccountTrees),
    aec_trees:set_accounts(Trees, AccountTrees1).


add_tokens(Pubkey, Amount, Trees) ->
    AccountTrees = aec_trees:accounts(Trees),
    Acc0 = aec_accounts_trees:get(Pubkey, AccountTrees), %% enforce account is present
    {ok, Acc} = aec_accounts:earn(Acc0, Amount),
    AccountTrees1 = aec_accounts_trees:enter(Acc, AccountTrees),
    aec_trees:set_accounts(Trees, AccountTrees1).

remove_tokens(Pubkey, Amount, Trees, Reserve) ->
    AccountTrees = aec_trees:accounts(Trees),
    Acc0 = aec_accounts_trees:get(Pubkey, AccountTrees),
    Balance = aec_accounts:balance(Acc0),
    check_min_amt(Balance - Amount, Reserve),
    Nonce = aec_accounts:nonce(Acc0),
    {ok, Acc} = aec_accounts:spend(Acc0, Amount, Nonce), %no nonce bump
    AccountTrees1 = aec_accounts_trees:enter(Acc, AccountTrees),
    aec_trees:set_accounts(Trees, AccountTrees1).

account_pubkey(Id) ->
    aeser_id:specialize(Id, account).

contract_pubkey(Id) ->
    aeser_id:specialize(Id, contract).

-spec extract_caller(update()) -> aec_keys:pubkey().
extract_caller(#call_contract{caller_id = CallerId}) ->
    account_pubkey(CallerId);
extract_caller(#create_contract{owner_id = OwnerId}) ->
    account_pubkey(OwnerId).

-spec is_call(update()) -> boolean().
is_call(#call_contract{}) ->
      true;
is_call(_) ->
      false.

-spec is_contract_create(update()) -> boolean().
is_contract_create(#create_contract{}) ->
      true;
is_contract_create(_) ->
      false.

-spec extract_call(aesc_offchain_update:update()) -> {aect_contracts:pubkey(), aec_keys:pubkey()}
                                                     | not_call.
extract_call(Update) ->
    case Update of
        #call_contract{caller_id = CallerId, contract_id = ContractId} ->
            {contract_pubkey(ContractId), account_pubkey(CallerId)};
        _ -> not_call
    end.

-spec extract_contract_pubkey(update()) -> aect_contracts:pubkey().
extract_contract_pubkey(#call_contract{contract_id = ContractId}) ->
    contract_pubkey(ContractId).

-spec extract_amounts(update()) -> {non_neg_integer(),
                                    non_neg_integer(),
                                    non_neg_integer()} | not_call.
extract_amounts(Update) ->
    case Update of
        #call_contract{amount = Amount, gas_price = GasPrice, gas = Gas}->
            {Amount, GasPrice, Gas};
        _ -> not_call
    end.

-spec extract_abi_version(update()) -> aect_contracts:abi_version().
extract_abi_version(#call_contract{abi_version = ABIVersion}) ->
    ABIVersion.

update_error(Err) ->
    error({off_chain_update_error, Err}).

-spec get_gas_price(update()) -> {ok, non_neg_integer()} | {error, not_a_call}.
get_gas_price(#call_contract{gas_price = GasPrice}) ->
    {ok, GasPrice};
get_gas_price(_) ->
    {error, not_a_call}.

-spec set_gas_price(non_neg_integer(), update()) -> update().
set_gas_price(NewGasPrice, #call_contract{} = Update) ->
    Update#call_contract{gas_price = NewGasPrice};
set_gas_price(_NewGasPrice, Update) ->
    Update.

is_protocol_active(OnChainEnv, Protocol) ->
    Height = aetx_env:height(OnChainEnv),
    aec_hard_forks:protocol_effective_at_height(Height) >= Protocol.
