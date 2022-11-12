unit openssl3.crypto.core_fetch;

interface
uses OpenSSL.Api;

type
  construct_data_st = record
    libctx       : POSSL_LIB_CTX;
    store        : POSSL_METHOD_STORE;
    operation_id,
    force_store  : integer;
    mcm          : POSSL_METHOD_CONSTRUCT_METHOD;
    mcm_data     : Pointer;
  end;
  Pconstruct_data_st = ^construct_data_st;

function ossl_method_construct_precondition( provider : POSSL_PROVIDER; operation_id : integer; cbdata : Pointer; _result : PInteger):integer;
procedure ossl_method_construct_this(provider : POSSL_PROVIDER;const algo : POSSL_ALGORITHM; no_store : integer; cbdata : Pointer);
function ossl_method_construct( libctx : POSSL_LIB_CTX; operation_id : integer; provider_rw : PPOSSL_PROVIDER; force_store : integer; mcm : POSSL_METHOD_CONSTRUCT_METHOD; mcm_data : Pointer):Pointer;
function ossl_method_construct_postcondition( provider : POSSL_PROVIDER; operation_id, no_store : integer; cbdata : Pointer; _result : PInteger):integer;

implementation
uses
   openssl3.crypto.core_algorithm,            OpenSSL3.common, OpenSSL3.Err,
   openssl3.crypto.provider_core;


function ossl_method_construct_postcondition( provider : POSSL_PROVIDER; operation_id, no_store : integer; cbdata : Pointer; _result : PInteger):integer;
begin
    if not ossl_assert(_result <> nil) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    _result^ := 1;
    Result := Int( (no_store <> 0)
                or (ossl_provider_set_operation_bit(provider, operation_id)>0) );
end;

procedure ossl_method_construct_this(provider : POSSL_PROVIDER;const algo : POSSL_ALGORITHM; no_store : integer; cbdata : Pointer);
var
  data : Pconstruct_data_st;
  method : Pointer;
begin
    data := cbdata;
    //openssl3.crypto.evp.evp_fetch.construct_evp_method
    method := data.mcm.construct(algo, provider, data.mcm_data);
    if method = nil then
        Exit;
    {
     * Note regarding putting the method in stores:
     *
     * we don't need to care if it actually got in or not here.
     * If it didn't get in, it will simply not be available when
     * ossl_method_construct() tries to get it from the store.
     *
     * It is *expected* that the put function increments the refcnt
     * of the passed method.
     }
    if (data.force_store > 0)  or  (0>= no_store) then
    begin
        { If we haven't been told not to store, add to the global store }
        //evp_fetch.put_evp_method_in_store
        data.mcm.put(nil, method, provider, algo.algorithm_names,
                       algo.property_definition, data.mcm_data);
    end
    else
    begin
        {
         * If we have been told not to store the method 'permanently', we
         * ask for a temporary store, and store the method there.
         * The owner of |data.mcm| is completely responsible for managing
         * that temporary store.
         }
        data.store := data.mcm.get_tmp_store(data.mcm_data);
        if data.store = nil then
            exit;
        data.mcm.put(data.store, method, provider, algo.algorithm_names,
                       algo.property_definition, data.mcm_data);
    end;
    { PostDec(refcnt) because we're dropping the reference }
    data.mcm.destruct(method, data.mcm_data);
end;

function ossl_method_construct_precondition( provider : POSSL_PROVIDER; operation_id : integer; cbdata : Pointer; _result : PInteger):integer;
begin
    if not ossl_assert(_result <> nil) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if 0>= ossl_provider_test_operation_bit(provider, operation_id, _result) then
        Exit(0);
    {
     * The result we get tells if methods have already been constructed.
     * However, we want to tell whether construction should happen (true)
     * or not (false), which is the opposite of what we got.
     }
     //*result = !*result;
    _result^ := Int(not Boolean(_result^));
    Result := 1;
end;

function ossl_method_construct( libctx : POSSL_LIB_CTX; operation_id : integer; provider_rw : PPOSSL_PROVIDER; force_store : integer; mcm : POSSL_METHOD_CONSTRUCT_METHOD; mcm_data : Pointer):Pointer;
var
    method   : Pointer;
    provider : POSSL_PROVIDER;
    cbdata   : construct_data_st;
begin
    method := nil;
    //evp_fetch.get_evp_method_from_store
    method := mcm.get(nil, provider_rw, mcm_data);
    if (method =nil) then
    begin
        if provider_rw <> nil then
           provider :=  provider_rw^
        else
           provider := nil;
        cbdata.store := nil;
        cbdata.force_store := force_store;
        cbdata.mcm := mcm;
        cbdata.mcm_data := mcm_data;
        ossl_algorithm_do_all(libctx, operation_id, provider,
                              ossl_method_construct_precondition,
                              ossl_method_construct_this,
                              ossl_method_construct_postcondition,
                              @cbdata);
        { If there is a temporary store, try there first }
        if cbdata.store <> nil then
           method := mcm.get(cbdata.store, provider_rw, mcm_data);
        { If no method was found yet, try the global store }
        if method = nil then
           method := mcm.get(nil, provider_rw, mcm_data);
    end;
    Result := method;
end;


end.
