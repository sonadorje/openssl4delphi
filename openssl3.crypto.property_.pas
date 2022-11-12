unit openssl3.crypto.property_;

interface
uses OpenSSL.Api;

const IMPL_CACHE_FLUSH_THRESHOLD = 500;

type
   Tproperty_hfn = function(const a: Pointer ): ulong;
   Tproperty_cfn = function(const a, b: Pointer ): int;
   OSSL_PROPERTY_IDX = int;
   Tproperty_node_func = procedure(p: PPointer);
   Tproperty_leaf_func2 = procedure(p1: ossl_uintmax_t; p2, p3: Pointer);
   Tproperty_leaf_func1 = procedure(p1: ossl_uintmax_t; p2: Pointer);
   Tmethod_up_ref = function(p1: Pointer): int;
   Tmethod_destruct = procedure(p1: Pointer);
   Tproperty_fn = procedure(id: int; method, fnarg: Pointer);
   //void (*fn)(QUERY *, IMPL_CACHE_FLUSH *)
   PIMPL_CACHE_FLUSH = ^TIMPL_CACHE_FLUSH;
   TIMPL_CACHE_FLUSH_fn = procedure( c : PQUERY; state : PIMPL_CACHE_FLUSH);

   alg_do_each_data_st = record
     fn: Tproperty_fn;
     fnarg: Pointer;
   end;
   Palg_do_each_data_st = ^alg_do_each_data_st;

   TIMPL_CACHE_FLUSH = record
    cache: Plhash_st_QUERY;
    nelem: NativeUInt;
    seed: UInt32;
   end;


  Tdoall_func = procedure(p1: PQUERY);
  Tdoallarg_func = procedure(p1: PQUERY; p2: Pointer);

  sk_IMPLEMENTATION_compfunc = function (const  a, b: PIMPLEMENTATION):integer;
  sk_IMPLEMENTATION_freefunc = procedure(a: PIMPLEMENTATION);
  sk_IMPLEMENTATION_copyfunc = function(const a: PIMPLEMENTATION): PIMPLEMENTATION;

 procedure ossl_method_store_free( store : POSSL_METHOD_STORE);

 function ossl_sa_ALGORITHM_new:Psparse_array_st_ALGORITHM;
  procedure ossl_sa_ALGORITHM_free( sa : Psparse_array_st_ALGORITHM);
  procedure ossl_sa_ALGORITHM_free_leaves( sa : Psparse_array_st_ALGORITHM);
  function ossl_sa_ALGORITHM_num(const sa : Psparse_array_st_ALGORITHM):size_t;
  procedure ossl_sa_ALGORITHM_doall(const sa : Psparse_array_st_ALGORITHM; leaf_func: Tproperty_leaf_func1);
  procedure ossl_sa_ALGORITHM_doall_arg(const sa : Psparse_array_st_ALGORITHM; leaf_func: Tproperty_leaf_func2;  arg: Pointer);
  function ossl_sa_ALGORITHM_get(const sa : Psparse_array_st_ALGORITHM; n : ossl_uintmax_t):PALGORITHM;
  function ossl_sa_ALGORITHM_set(sa : Psparse_array_st_ALGORITHM; n : ossl_uintmax_t;val : PALGORITHM):integer;
  procedure alg_cleanup( idx : ossl_uintmax_t; a : Pointer);

  function sk_IMPLEMENTATION_num( sk : Pointer):integer;
  function sk_IMPLEMENTATION_value( sk : Pointer;idx: integer):PIMPLEMENTATION;
  function sk_IMPLEMENTATION_new( cmp : sk_IMPLEMENTATION_compfunc):PSTACK_st_IMPLEMENTATION;
  function sk_IMPLEMENTATION_new_null:PSTACK_st_IMPLEMENTATION;
  function sk_IMPLEMENTATION_new_reserve( cmp : sk_IMPLEMENTATION_compfunc; n : integer):PSTACK_st_IMPLEMENTATION;
  function sk_IMPLEMENTATION_reserve( sk : Pointer; n : integer):integer;
  procedure sk_IMPLEMENTATION_free( sk : Pointer);
  procedure sk_IMPLEMENTATION_zero( sk : Pointer);
  function sk_IMPLEMENTATION_delete( sk : Pointer; i : integer):PIMPLEMENTATION;
  function sk_IMPLEMENTATION_delete_ptr( sk, ptr : Pointer):PIMPLEMENTATION;
  function sk_IMPLEMENTATION_push( sk, ptr : Pointer):integer;
  function sk_IMPLEMENTATION_unshift( sk, ptr : Pointer):integer;
  function sk_IMPLEMENTATION_pop( sk : Pointer):PIMPLEMENTATION;
  function sk_IMPLEMENTATION_shift( sk : Pointer):PIMPLEMENTATION;
  procedure sk_IMPLEMENTATION_pop_free( sk : Pointer; freefunc : sk_IMPLEMENTATION_freefunc);
  function sk_IMPLEMENTATION_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_IMPLEMENTATION_set( sk : Pointer; idx : integer; ptr : Pointer):PIMPLEMENTATION;
  function sk_IMPLEMENTATION_find( sk, ptr : Pointer):integer;
  function sk_IMPLEMENTATION_find_ex( sk, ptr : Pointer):integer;
  function sk_IMPLEMENTATION_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_IMPLEMENTATION_sort( sk : Pointer);
  function sk_IMPLEMENTATION_is_sorted( sk : Pointer):integer;
  function sk_IMPLEMENTATION_dup( sk : Pointer):PSTACK_st_IMPLEMENTATION;
  function sk_IMPLEMENTATION_deep_copy( sk : Pointer; copyfunc : sk_IMPLEMENTATION_copyfunc; freefunc : sk_IMPLEMENTATION_freefunc):PSTACK_st_IMPLEMENTATION;
  function sk_IMPLEMENTATION_set_cmp_func( sk : Pointer; cmp : sk_IMPLEMENTATION_compfunc):sk_IMPLEMENTATION_compfunc;
  procedure ossl_method_free( method : P_METHOD);
  procedure impl_free( impl : PIMPLEMENTATION);

  function lh_QUERY_new(hfn: Tproperty_hfn; cfn: Tproperty_cfn ): Plhash_st_QUERY;
  procedure lh_QUERY_free( lh : Plhash_st_QUERY);
  procedure lh_QUERY_flush( lh : Plhash_st_QUERY);
  function lh_QUERY_insert( lh : Plhash_st_QUERY; d : PQUERY):PQUERY;
  function lh_QUERY_delete(lh : Plhash_st_QUERY;const d : PQUERY):PQUERY;
  function lh_QUERY_retrieve(lh : Plhash_st_QUERY;const d : PQUERY):PQUERY;
  function lh_QUERY_error( lh : Plhash_st_QUERY):integer;
  function lh_QUERY_num_items( lh : Plhash_st_QUERY):uint64;
  procedure lh_QUERY_node_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
  procedure lh_QUERY_node_usage_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
  procedure lh_QUERY_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
  function lh_QUERY_get_down_load( lh : Plhash_st_QUERY):uint64;
  procedure lh_QUERY_set_down_load( lh : Plhash_st_QUERY; dl : uint64);
  procedure lh_QUERY_doall( lh : Plhash_st_QUERY; doall : Tdoall_func);
  procedure lh_QUERY_doall_arg( lh : Plhash_st_QUERY; doallarg : Tdoallarg_func; arg : Pointer);
  procedure impl_cache_free( elem : PQUERY);
  function ossl_method_store_new( ctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
  function ossl_method_store_fetch(store : POSSL_METHOD_STORE; nid : integer;prop_query : PUTF8Char; prov_rw : PPOSSL_PROVIDER;var method : Pointer):integer;
  function ossl_property_read_lock( p : POSSL_METHOD_STORE):integer;
  function ossl_method_store_retrieve( store : POSSL_METHOD_STORE; nid : integer):PALGORITHM;
  function ossl_property_unlock( p : POSSL_METHOD_STORE):integer;
  function ossl_ctx_global_properties( libctx : POSSL_LIB_CTX; loadconfig : integer):PPOSSL_PROPERTY_LIST;
  function ossl_ctx_global_properties_new( ctx : POSSL_LIB_CTX):Pointer;
  procedure ossl_ctx_global_properties_free( vglobp : Pointer);
  function ossl_method_up_ref(_method : P_METHOD):integer;
   function ossl_method_store_add(store : POSSL_METHOD_STORE;const prov : POSSL_PROVIDER; nid : integer; properties : PUTF8Char; method : Pointer; method_up_ref : Tmethod_up_ref; method_destruct : Tmethod_destruct):integer;
  function ossl_property_write_lock( p : POSSL_METHOD_STORE):integer;
  procedure ossl_method_cache_flush( store : POSSL_METHOD_STORE; nid : integer);
  procedure impl_cache_flush_alg( idx : ossl_uintmax_t; alg, arg : Pointer);
  function query_hash(const a : Pointer):Cardinal;
  function query_cmp(const a, b : Pointer):integer;
  function ossl_method_store_insert( store : POSSL_METHOD_STORE; alg : PALGORITHM):int;
   function ossl_method_store_flush_cache( store : POSSL_METHOD_STORE; all : integer):integer;
  function ossl_method_store_cache_get(store : POSSL_METHOD_STORE; prov : POSSL_PROVIDER; nid : integer;const prop_query : PUTF8Char;var method : Pointer):integer;

 const ossl_ctx_global_properties_method: TOSSL_LIB_CTX_METHOD  = (
    priority:OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func:ossl_ctx_global_properties_new;
    free_func: ossl_ctx_global_properties_free
);

procedure ossl_method_store_do_all( store : POSSL_METHOD_STORE; fn : Tproperty_fn; fnarg : Pointer);
procedure alg_do_each( idx : ossl_uintmax_t;alg, arg : Pointer);
procedure alg_do_one( alg : PALGORITHM; impl : PIMPLEMENTATION; fn : Tproperty_fn; fnarg : Pointer);
function ossl_method_store_cache_set(store : POSSL_METHOD_STORE; prov : POSSL_PROVIDER; nid : integer;const prop_query : PUTF8Char; method : Pointer; method_up_ref : Tmethod_up_ref; method_destruct : Tmethod_destruct):integer;
procedure ossl_method_cache_flush_some( store : POSSL_METHOD_STORE);

procedure impl_cache_flush_one_alg( idx : ossl_uintmax_t; alg : PALGORITHM; v : Pointer);
procedure lh_QUERY_doall_IMPL_CACHE_FLUSH( lh : Plhash_st_QUERY; fn : TIMPL_CACHE_FLUSH_fn; arg : PIMPL_CACHE_FLUSH);
procedure impl_cache_flush_cache( c : PQUERY; state : PIMPL_CACHE_FLUSH);



function ossl_global_properties_no_mirrored( libctx : POSSL_LIB_CTX):integer;
procedure ossl_global_properties_stop_mirroring( libctx : POSSL_LIB_CTX);

implementation

uses
   openssl3.crypto.sparse_array,   openssl3.crypto.stack,
   openssl3.crypto.mem,            openssl3.crypto.lh_stats,
   openssl3.crypto.lhash,          openssl3.crypto._property.defn_cache,
   openssl3.crypto.property_parse, openssl3.crypto.context,
   OpenSSL3.threads_none,          openssl3.crypto.init,
   openssl3.crypto.property_query, OpenSSL3.common,
   openssl3.crypto.cpuid,
   openssl3.crypto.provider_core;

procedure ossl_global_properties_stop_mirroring( libctx : POSSL_LIB_CTX);
var
  globp : POSSL_GLOBAL_PROPERTIES;
begin
    globp := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES,
                                @ossl_ctx_global_properties_method);
    if globp <> nil then
       globp.no_mirrored := 1;
end;


function ossl_global_properties_no_mirrored( libctx : POSSL_LIB_CTX):integer;
var
  globp : POSSL_GLOBAL_PROPERTIES;
begin
    globp := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES,
                                @ossl_ctx_global_properties_method);
    Result := get_result( (globp <> nil)  and  (globp.no_mirrored > 0) , 1 , 0);
end;



procedure impl_cache_flush_cache( c : PQUERY; state : PIMPL_CACHE_FLUSH);
var
  n : uint32;
begin
    {
     * Implement the 32 bit xorshift as suggested by George Marsaglia in:
     *      https://doi.org/10.18637/jss.v008.i14
     *
     * This is a very fast PRNG so there is no need to extract bits one at a
     * time and use the entire value each time.
     }
    n := state.seed;
    n  := n xor (n shl 13);
    n  := n xor (n  shr  17);
    n  := n xor (n shl 5);
    state.seed := n;
    if n and 1 <> 0 then
        impl_cache_free(lh_QUERY_delete(state.cache, c))
    else
        Inc(state.nelem);
end;


procedure lh_QUERY_doall_IMPL_CACHE_FLUSH( lh : Plhash_st_QUERY; fn : TIMPL_CACHE_FLUSH_fn; arg : PIMPL_CACHE_FLUSH);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer(arg));
end;




procedure impl_cache_flush_one_alg( idx : ossl_uintmax_t; alg : PALGORITHM; v : Pointer);
var
  state : PIMPL_CACHE_FLUSH;
begin
    state := PIMPL_CACHE_FLUSH (v);
    state.cache := alg.cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state.cache, @impl_cache_flush_cache,
                                    state);
end;


procedure ossl_method_cache_flush_some( store : POSSL_METHOD_STORE);
var
  state : TIMPL_CACHE_FLUSH;
begin
    state.nelem := 0;
    state.seed := OPENSSL_rdtsc();
    if state.seed =  0 then
        state.seed := 1;
    ossl_provider_clear_all_operation_bits(store.ctx);
    store.need_flush := 0;
    ossl_sa_ALGORITHM_doall_arg(store.algs, @impl_cache_flush_one_alg, @state);
    store.nelem := state.nelem;
end;



function ossl_method_store_cache_set(store : POSSL_METHOD_STORE;
                                     prov : POSSL_PROVIDER; nid : integer;
                                     const prop_query : PUTF8Char;
                                     method : Pointer;
                                     method_up_ref : Tmethod_up_ref;
                                     method_destruct : Tmethod_destruct):integer;
var
  elem : TQUERY;
  old, p : PQUERY;
  alg : PALGORITHM;
  len : size_t;
  res : integer;
  label _err, _end;
begin
    p := nil;
    res := 1;
    if (nid <= 0)  or  (store = nil) then Exit(0);
    if prop_query = nil then
       Exit(1);
    if not ossl_assert(prov <> nil) then
        Exit(0);
    if 0>=ossl_property_write_lock(store) then
        Exit(0);
    if store.need_flush > 0 then
       ossl_method_cache_flush_some(store);
    alg := ossl_method_store_retrieve(store, nid);
    if alg = nil then
       goto _err;
    if method = nil then
    begin
        elem.query := prop_query;
        elem.provider := prov;
        old := lh_QUERY_delete(alg.cache, @elem);
        if old <> nil then
        begin
            impl_cache_free(old);
            Dec(store.nelem);
        end;
        goto _end;
    end;
    len := StrSize(prop_query);
    p := OPENSSL_malloc(sizeof( p^));
    if p <> nil then
    begin
        p.query := @p.body[0];
        p.provider := prov;
        p.method.method := method;
        p.method.up_ref := method_up_ref;
        p.method.free := method_destruct;
        if 0>=ossl_method_up_ref(@p.method) then
            goto _err;
        p.query := OPENSSL_malloc(len);
        memcpy(@p.query[0], prop_query, len);
        old := lh_QUERY_insert(alg.cache, p);
        if old  <> nil then  begin
            impl_cache_free(old);
            goto _end;
        end;
        if 0>=lh_QUERY_error(alg.cache) then
        begin
            if PreInc(store.nelem) >= IMPL_CACHE_FLUSH_THRESHOLD then
                store.need_flush := 1;
            goto _end;
        end;
        ossl_method_free(@p.method);
    end;

_err:
    res := 0;
    OPENSSL_free(p);

_end:
    ossl_property_unlock(store);
    Result := res;
end;


procedure alg_do_one( alg : PALGORITHM; impl : PIMPLEMENTATION; fn : Tproperty_fn; fnarg : Pointer);
begin
    fn(alg.nid, impl.method.method, fnarg);
end;

procedure alg_do_each( idx : ossl_uintmax_t; alg, arg : Pointer);
var
  data : Palg_do_each_data_st;
  i, _end : integer;
  impl : PIMPLEMENTATION;
begin
    data := arg;
    _end := sk_IMPLEMENTATION_num(PALGORITHM(alg).impls);
    for i := 0 to _end-1 do begin
        impl := sk_IMPLEMENTATION_value(PALGORITHM(alg).impls, i);
        alg_do_one(alg, impl, data.fn, data.fnarg);
    end;
end;

procedure ossl_method_store_do_all( store : POSSL_METHOD_STORE; fn : Tproperty_fn; fnarg : Pointer);
var
  data : alg_do_each_data_st;
begin
    data.fn := fn;
    data.fnarg := fnarg;
    if store <> nil then
       ossl_sa_ALGORITHM_doall_arg(store.algs, alg_do_each, @data);
end;

function ossl_method_store_cache_get(store : POSSL_METHOD_STORE; prov : POSSL_PROVIDER; nid : integer;const prop_query : PUTF8Char;var method : Pointer):integer;
var
  alg : PALGORITHM;
  elem: TQUERY;
  r : PQUERY;
  res : integer;
  label _err;
begin
    res := 0;
    if (nid <= 0)  or  (store = nil) then
       Exit(0);
    if  0>= ossl_property_read_lock(store) then
        Exit(0);
    alg := ossl_method_store_retrieve(store, nid);
    if alg = nil then
       goto _err;
    if prop_query <> nil then
       elem.query := prop_query
    else
       elem.query := '';
    elem.provider := prov;
    r := lh_QUERY_retrieve(alg.cache, @elem);
    if r = nil then
       goto _err;
    if (ossl_method_up_ref(@r.method)) > 0 then
    begin
        method := r.method.method;
        res := 1;
    end;

_err:
    ossl_property_unlock(store);
    Result := res;
end;

function ossl_method_store_flush_cache( store : POSSL_METHOD_STORE; all : integer):integer;
var
  arg : Pointer;
begin
    if all <> 0 then
       arg := store.algs
    else
       arg := nil;
    if  0>= ossl_property_write_lock(store)  then
        Exit(0);
    ossl_provider_clear_all_operation_bits(store.ctx);
    ossl_sa_ALGORITHM_doall_arg(store.algs, impl_cache_flush_alg, arg);
    store.nelem := 0;
    ossl_property_unlock(store);
    Result := 1;
end;

function ossl_method_store_insert( store : POSSL_METHOD_STORE; alg : PALGORITHM):int;
begin
    Result := ossl_sa_ALGORITHM_set(store.algs, alg.nid, alg);
end;

function query_cmp(const a, b : Pointer):integer;
var
  res, n : integer;
begin
{$POINTERMATH ON}
    res := strcmp(PQUERY(a).query, PQUERY(b).query);
    if (res = 0)  and  (PQUERY(a).provider <> nil)  and  (PQUERY(b).provider <> nil )then
    begin
       n   := get_result(PQUERY(b).provider < PQUERY(a).provider , -1, 0);
       res := get_result(PQUERY(b).provider > PQUERY(a).provider , 1 , n );
    end;
    Result := res;
{$POINTERMATH OFF}
end;

function query_hash(const a : Pointer):Cardinal;
begin
    Result := OPENSSL_LH_strhash(PQUERY(a).query);
end;

procedure impl_cache_flush_alg( idx : ossl_uintmax_t; alg, arg : Pointer);
var
   algs: Psparse_array_st_ALGORITHM;
begin
    algs := arg;
    lh_QUERY_doall(PALGORITHM(alg).cache, &impl_cache_free);
    if algs <> nil then
    begin
        sk_IMPLEMENTATION_pop_free(PALGORITHM(alg).impls, &impl_free);
        lh_QUERY_free(PALGORITHM(alg).cache);
        OPENSSL_free(alg);
        ossl_sa_ALGORITHM_set(algs, idx, nil);
    end
    else
    begin
        lh_QUERY_flush(PALGORITHM(alg).cache);
    end;
end;

procedure ossl_method_cache_flush( store : POSSL_METHOD_STORE; nid : integer);
var
  alg : PALGORITHM;
begin
    alg := ossl_method_store_retrieve(store, nid);
    if alg <> nil then
    begin
        ossl_provider_clear_all_operation_bits(store.ctx);
        store.nelem  := store.nelem - (lh_QUERY_num_items(alg.cache));
        impl_cache_flush_alg(0, alg, nil);
    end;
end;

function ossl_property_write_lock( p : POSSL_METHOD_STORE):integer;
begin
    Result := get_result( p <> nil , CRYPTO_THREAD_write_lock(p.lock) , 0);
end;

function ossl_method_store_add(store : POSSL_METHOD_STORE;const prov : POSSL_PROVIDER; nid : integer; properties : PUTF8Char; method : Pointer; method_up_ref : Tmethod_up_ref; method_destruct : Tmethod_destruct):integer;
var
  alg : PALGORITHM;
  impl, tmpimpl : PIMPLEMENTATION;
  ret, i, num, ok, tmp : integer;
  label _err;
begin
    alg := nil;
    ret := 0;
    if (nid <= 0)  or  (method = nil)  or  (store = nil) then Exit(0);
    if properties = nil then
       properties := '';
    if  not ossl_assert(prov <> nil)  then
        Exit(0);
    { Create new entry }
    impl := OPENSSL_malloc(sizeof( impl^));
    if impl = nil then Exit(0);
    impl.method.method := method;
    impl.method.up_ref := method_up_ref;
    impl.method.free := method_destruct;
    if  0>= ossl_method_up_ref(@impl.method) then
    begin
        OPENSSL_free(impl);
        Exit(0);
    end;
    impl.provider := prov;
    { Insert into the hash table if required }
    if  0>= ossl_property_write_lock(store) then
    begin
        OPENSSL_free(impl);
        Exit(0);
    end;
    ossl_method_cache_flush(store, nid);
    impl.properties := ossl_prop_defn_get(store.ctx, properties);
    if impl.properties =  nil then
    begin
        impl.properties := ossl_parse_property(store.ctx, properties);
        if impl.properties = nil then
            goto _err;
        tmp := ossl_prop_defn_set(store.ctx, properties, impl.properties);
    end;

    alg := ossl_method_store_retrieve(store, nid);
    {if nid = 81 then
       Writeln('catch bug: ', nid)
    else
       Writeln('openssl3.crypto.property_.ossl_method_store_add: nid=', nid);
    }
    if alg = nil then
    begin
       alg := OPENSSL_zalloc(sizeof( alg^));
       alg.impls := sk_IMPLEMENTATION_new_null() ; //POPENSSL_STACK
       alg.cache := lh_QUERY_new(query_hash, query_cmp);
       if (alg  = nil) or  (alg.impls = nil) or  (alg.cache = nil) then
             goto _err;
        alg.nid := nid;
        if  0>= ossl_method_store_insert(store, alg)  then
            goto _err;
    end;
    { Push onto stack if there isn't one there already }

    i := 0;
    num := sk_IMPLEMENTATION_num(alg.impls);
    for i := 0 to num - 1 do
    begin
        tmpimpl := sk_IMPLEMENTATION_value(alg.impls, i);
        if (tmpimpl.provider = impl.provider) and  (
            tmpimpl.properties = impl.properties) then
            break;
    end;

    //满足条件i=num才执行push
    if (i = num ) and (sk_IMPLEMENTATION_push(alg.impls, impl) > 0) then
        ret := 1;
    ossl_property_unlock(store);
    if ret = 0 then
       impl_free(impl);
    Exit(ret);

_err:
    ossl_property_unlock(store);
    alg_cleanup(0, alg);
    impl_free(impl);
    Result := 0;
end;

function ossl_method_up_ref(_method : P_METHOD):integer;
begin
    Result := _method.up_ref(_method.method);
end;

procedure ossl_ctx_global_properties_free( vglobp : Pointer);
var
  globp : POSSL_GLOBAL_PROPERTIES;
begin
    globp := vglobp;
    if globp <> nil then
    begin
        ossl_property_free(globp.list);
        OPENSSL_free(globp);
    end;
end;

function ossl_ctx_global_properties_new( ctx : POSSL_LIB_CTX):Pointer;
begin
    Result := OPENSSL_zalloc(sizeof(TOSSL_GLOBAL_PROPERTIES));
end;



function ossl_ctx_global_properties( libctx : POSSL_LIB_CTX; loadconfig : integer):PPOSSL_PROPERTY_LIST;
var
  globp : POSSL_GLOBAL_PROPERTIES;
begin
{$IFNDEF FIPS_MODULE}
    if (loadconfig>0)  and
       (0>= OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil) )  then
        Exit(nil);
{$ENDIF}
    globp := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES,
                                  @ossl_ctx_global_properties_method);
    if globp <> nil then
       Result :=  @globp.list
    else
       Result :=  nil;
end;

function ossl_property_unlock( p : POSSL_METHOD_STORE):integer;
begin
    Result := get_result(p <> nil , CRYPTO_THREAD_unlock(p.lock) , 0);
end;

function ossl_method_store_retrieve( store : POSSL_METHOD_STORE; nid : integer):PALGORITHM;
begin
    Result := ossl_sa_ALGORITHM_get(store.algs, nid);
end;

function ossl_property_read_lock( p : POSSL_METHOD_STORE):integer;
begin
    Result := get_result(p <> nil , CRYPTO_THREAD_read_lock(p.lock) , 0);
end;

function ossl_method_store_fetch(store : POSSL_METHOD_STORE; nid : integer;prop_query : PUTF8Char; prov_rw : PPOSSL_PROVIDER;var method : Pointer):integer;
var
  plp       : PPOSSL_PROPERTY_LIST;
  alg       : PALGORITHM;
  impl,
  best_impl : PIMPLEMENTATION;
  pq,p2     : POSSL_PROPERTY_LIST;
  prov      : POSSL_PROVIDER;
  ret, j, best, score, optional  : integer;

  label _fin;
begin
    best_impl := nil;
    pq := nil; p2 := nil;
    if prov_rw <> nil then
       prov :=  prov_rw^
    else
       prov := nil;
    ret := 0;
    best := -1;
{$IFNDEF FIPS_MODULE}
    if  0>= OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil)  then
        Exit(0);
{$ENDIF}
    if (nid <= 0)  or  {(method = nil)  or}  (store = nil) then
       Exit(0);
    { This only needs to be a read lock, because the query won't create anything }
    if  0>= ossl_property_read_lock(store)  then
        Exit(0);
    alg := ossl_method_store_retrieve(store, nid);
    if alg = nil then
    begin
        ossl_property_unlock(store);
        Exit(0);
    end;
    if prop_query <> nil then
    begin
       pq := ossl_parse_query(store.ctx, prop_query, 0);
       p2 := pq;
    end;
    plp := ossl_ctx_global_properties(store.ctx, 0);
    if (plp <> nil)  and  (plp^ <> nil) then
    begin
        if pq = nil then
        begin
            pq := plp^;
        end
        else
        begin
            p2 := ossl_property_merge(pq, plp^);
            ossl_property_free(pq);
            if p2 = nil then
               goto _fin;
            pq := p2;
        end;
    end;
    if pq = nil then
    begin
        for j := 0 to sk_IMPLEMENTATION_num(alg.impls)-1 do
        begin
            impl := sk_IMPLEMENTATION_value(alg.impls, j);
            if ( impl  <> nil )    and
               ( (prov = nil)  or  (impl.provider = prov) )then
            begin
                best_impl := impl;
                ret := 1;
                break;
            end;
        end;
        goto _fin;
    end;
    optional := ossl_property_has_optional(pq);
    for j := 0 to sk_IMPLEMENTATION_num(alg.impls)-1 do
    begin
        impl := sk_IMPLEMENTATION_value(alg.impls, j );
        if  (impl  <> nil)  and
            ( (prov = nil)  or  (impl.provider = prov)) then
        begin
            score := ossl_property_match_count(pq, impl.properties);
            if score > best then
            begin
                best_impl := impl;
                best := score;
                ret := 1;
                if  0>= optional then
                   goto _fin;
            end;
        end;
    end;

_fin:
    if (ret>0)  and  (ossl_method_up_ref(@best_impl.method)>0 )then
    begin
        method := best_impl.method.method;
        if prov_rw <> nil then
           prov_rw^ := best_impl.provider;
    end
    else
    begin
        ret := 0;
    end;
    ossl_property_unlock(store);
    ossl_property_free(p2);
    Result := ret;
end;

function ossl_method_store_new( ctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
begin
    Result := OPENSSL_zalloc(sizeof( Result^));
    if Result <> nil then
    begin
        Result.ctx := ctx;
        Result.algs := ossl_sa_ALGORITHM_new();
        if Result.algs = nil then
        begin
            OPENSSL_free(Result);
            Exit(nil);
        end;
        Result.lock := CRYPTO_THREAD_lock_new( );
        if Result.lock = nil then
        begin
            ossl_sa_ALGORITHM_free(Result.algs);
            OPENSSL_free(Result);
            Exit(nil);
        end;
    end;

end;





procedure impl_cache_free( elem : PQUERY);
begin
    if elem <> nil then
    begin
        ossl_method_free(@elem.method);
        OPENSSL_free(elem);
    end;
end;

function lh_QUERY_new(hfn: Tproperty_hfn; cfn: Tproperty_cfn ): Plhash_st_QUERY;
begin
   Result := Plhash_st_QUERY (
            OPENSSL_LH_new(TOPENSSL_LH_HASHFUNC(hfn), TOPENSSL_LH_COMPFUNC(cfn)));
end;

procedure lh_QUERY_free( lh : Plhash_st_QUERY);
begin
   OPENSSL_LH_free(POPENSSL_LHASH(lh));
end;


procedure lh_QUERY_flush( lh : Plhash_st_QUERY);
begin
   OPENSSL_LH_flush(POPENSSL_LHASH(lh));
end;


function lh_QUERY_insert( lh : Plhash_st_QUERY; d : PQUERY):PQUERY;
begin
   Result := PQUERY (OPENSSL_LH_insert(POPENSSL_LHASH(lh), d));
end;


function lh_QUERY_delete(lh : Plhash_st_QUERY;const d : PQUERY):PQUERY;
begin
   Result := PQUERY (OPENSSL_LH_delete(POPENSSL_LHASH(lh), d));
end;


function lh_QUERY_retrieve(lh : Plhash_st_QUERY;const d : PQUERY):PQUERY;
begin
   Result := PQUERY (OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d));
end;


function lh_QUERY_error( lh : Plhash_st_QUERY):integer;
begin
   Result := OPENSSL_LH_error(POPENSSL_LHASH(lh));
end;


function lh_QUERY_num_items( lh : Plhash_st_QUERY):uint64;
begin
   Result := OPENSSL_LH_num_items(POPENSSL_LHASH(lh));
end;


procedure lh_QUERY_node_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
begin
   OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_QUERY_node_usage_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
begin
   OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_QUERY_stats_bio(const lh : Plhash_st_QUERY; _out : PBIO);
begin
   OPENSSL_LH_stats_bio(POPENSSL_LHASH (lh), _out);
end;


function lh_QUERY_get_down_load( lh : Plhash_st_QUERY):uint64;
begin
   Result := OPENSSL_LH_get_down_load(POPENSSL_LHASH(lh));
end;


procedure lh_QUERY_set_down_load( lh : Plhash_st_QUERY; dl : uint64);
begin
   OPENSSL_LH_set_down_load(POPENSSL_LHASH(lh), dl);
end;


procedure lh_QUERY_doall( lh : Plhash_st_QUERY; doall : Tdoall_func);
begin
   OPENSSL_LH_doall(lh, TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_QUERY_doall_arg( lh : Plhash_st_QUERY; doallarg : Tdoallarg_func; arg : Pointer);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh),
                             TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;


procedure ossl_method_free( method : P_METHOD);
begin
    method^.free(method.method);
end;

procedure impl_free( impl : PIMPLEMENTATION);
begin
    if impl <> nil then
    begin
        ossl_method_free(@impl.method);
        SetLength(impl.properties.properties, 0);
        OPENSSL_free(impl);
    end;
end;

function sk_IMPLEMENTATION_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_IMPLEMENTATION_value( sk : Pointer; idx: integer):PIMPLEMENTATION;
begin
   Result := OPENSSL_sk_value(POPENSSL_STACK(sk), idx);
end;


function sk_IMPLEMENTATION_new( cmp : sk_IMPLEMENTATION_compfunc):PSTACK_st_IMPLEMENTATION;
begin
   Result := OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp));
end;


function sk_IMPLEMENTATION_new_null:PSTACK_st_IMPLEMENTATION;
begin
   Result := OPENSSL_sk_new_null();
end;


function sk_IMPLEMENTATION_new_reserve( cmp : sk_IMPLEMENTATION_compfunc; n : integer):PSTACK_st_IMPLEMENTATION;
begin
   Result := PSTACK_st_IMPLEMENTATION (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_IMPLEMENTATION_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_IMPLEMENTATION_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_IMPLEMENTATION_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_IMPLEMENTATION_delete( sk : Pointer; i : integer):PIMPLEMENTATION;
begin
   Result := PIMPLEMENTATION(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_IMPLEMENTATION_delete_ptr( sk, ptr : Pointer):PIMPLEMENTATION;
begin
   Result := PIMPLEMENTATION(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_IMPLEMENTATION_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), ptr)
end;


function sk_IMPLEMENTATION_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_IMPLEMENTATION_pop( sk : Pointer):PIMPLEMENTATION;
begin
   Result := PIMPLEMENTATION(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_IMPLEMENTATION_shift( sk : Pointer):PIMPLEMENTATION;
begin
   Result := PIMPLEMENTATION(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_IMPLEMENTATION_pop_free( sk : Pointer; freefunc : sk_IMPLEMENTATION_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_IMPLEMENTATION_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_IMPLEMENTATION_set( sk : Pointer; idx : integer; ptr : Pointer):PIMPLEMENTATION;
begin
   Result := PIMPLEMENTATION(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_IMPLEMENTATION_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_IMPLEMENTATION_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_IMPLEMENTATION_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_IMPLEMENTATION_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_IMPLEMENTATION_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_IMPLEMENTATION_dup( sk : Pointer):PSTACK_st_IMPLEMENTATION;
begin
   Result := PSTACK_st_IMPLEMENTATION (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_IMPLEMENTATION_deep_copy( sk : Pointer; copyfunc : sk_IMPLEMENTATION_copyfunc; freefunc : sk_IMPLEMENTATION_freefunc):PSTACK_st_IMPLEMENTATION;
begin
   Result := PSTACK_st_IMPLEMENTATION (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_IMPLEMENTATION_set_cmp_func( sk : Pointer; cmp : sk_IMPLEMENTATION_compfunc):sk_IMPLEMENTATION_compfunc;
begin
   Result := sk_IMPLEMENTATION_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

procedure alg_cleanup( idx : ossl_uintmax_t; a : Pointer);
begin
    if a <> nil then
    begin
        sk_IMPLEMENTATION_pop_free(PALGORITHM(a).impls, @impl_free);
        lh_QUERY_doall(PALGORITHM(a).cache, impl_cache_free);
        lh_QUERY_free(PALGORITHM(a).cache);
        OPENSSL_free(a);
    end;
end;

function ossl_sa_ALGORITHM_new:Psparse_array_st_ALGORITHM;
begin
   Result :=  ossl_sa_new();
end;


procedure ossl_sa_ALGORITHM_free( sa : Psparse_array_st_ALGORITHM);
begin
        ossl_sa_free(POPENSSL_SA (sa));
end;


procedure ossl_sa_ALGORITHM_free_leaves( sa : Psparse_array_st_ALGORITHM);
begin
        ossl_sa_free_leaves(POPENSSL_SA (sa));
end;


function ossl_sa_ALGORITHM_num(const sa : Psparse_array_st_ALGORITHM):size_t;
begin
   Result :=  ossl_sa_num(POPENSSL_SA (sa));
end;


procedure ossl_sa_ALGORITHM_doall(const sa : Psparse_array_st_ALGORITHM; leaf_func: Tproperty_leaf_func1);
begin
   //(void ( *)(ossl_uintmax_t, void *))leaf
   ossl_sa_doall(POPENSSL_SA (sa), leaf_func );
end;

//static  __inline void ossl_sa_ALGORITHM_doall_arg(const struct sparse_array_st_ALGORITHM *sa,
//void (*leaf)(ossl_uintmax_t, ALGORITHM *, void *), void *arg)
{ ossl_sa_doall_arg((OPENSSL_SA *)sa, (void (*)(ossl_uintmax_t, void *, void *))leaf, arg); }

procedure ossl_sa_ALGORITHM_doall_arg(const sa : Psparse_array_st_ALGORITHM;leaf_func: Tproperty_leaf_func2; arg: Pointer);
begin
   ossl_sa_doall_arg(POPENSSL_SA(sa), leaf_func, arg);
end;


function ossl_sa_ALGORITHM_get(const sa : Psparse_array_st_ALGORITHM; n : ossl_uintmax_t):PALGORITHM;
begin
   Result := ossl_sa_get(sa, n);
end;


function ossl_sa_ALGORITHM_set(sa : Psparse_array_st_ALGORITHM; n : ossl_uintmax_t;val : PALGORITHM):integer;
begin
   Result :=  ossl_sa_set(POPENSSL_SA (sa), n, Pointer(val) );
end;



procedure ossl_method_store_free( store : POSSL_METHOD_STORE);
begin
    if store <> nil then
    begin
        ossl_sa_ALGORITHM_doall(store.algs, &alg_cleanup);
        ossl_sa_ALGORITHM_free(store.algs);
        CRYPTO_THREAD_lock_free(store.lock);
        OPENSSL_free(store);
    end;
end;


end.
