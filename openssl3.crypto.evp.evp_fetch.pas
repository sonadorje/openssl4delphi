unit openssl3.crypto.evp.evp_fetch;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses  OpenSSL.Api, SysUtils;

type
  filter_data_st = record
    operation_id: int ;
    user_fn: procedure(method: Pointer; arg : Pointer);
    user_arg: Pointer;
  end;
  Pfilter_data_st = ^filter_data_st;

  Tevp_fetch_new_method    = function (name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
  Tevp_fetch_up_ref_method = function ( p1 : Pointer):integer;
  Tevp_fetch_free_method   = procedure ( p1 : Pointer);
  Tevp_fetch_fn            = procedure(const p1: PUTF8Char; arg: Pointer);

function evp_method_store_new( ctx : POSSL_LIB_CTX):Pointer;
procedure evp_method_store_free( vstore : Pointer);
function inner_evp_generic_fetch(methdata : Pevp_method_data_st; prov : POSSL_PROVIDER; operation_id, name_id : integer;{const} name, properties : PUTF8Char; new_method : Tevp_fetch_new_method ; up_ref_method : Tevp_fetch_up_ref_method; free_method : Tevp_fetch_free_method):Pointer;
function get_evp_method_store(libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
function evp_is_a(prov : POSSL_PROVIDER; number : integer;const legacy_name, name : PUTF8Char):Boolean;
function evp_method_id( name_id : integer; operation_id : uint32):uint32;
function get_tmp_evp_method_store( data : Pointer):Pointer;
function get_evp_method_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
function put_evp_method_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
function evp_method_store_flush( libctx : POSSL_LIB_CTX):integer;
function construct_evp_method(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
procedure destruct_evp_method( method, data : Pointer);
function evp_generic_fetch(libctx : POSSL_LIB_CTX; operation_id : integer;const name, properties : PUTF8Char; new_method : Tevp_fetch_new_method ; up_ref_method : Tevp_fetch_up_ref_method; free_method : Tevp_fetch_free_method): Pointer;
function evp_names_do_all( prov : POSSL_PROVIDER; number : integer; fn : Tevp_fetch_fn; data : Pointer):integer;
function evp_generic_fetch_from_prov(prov : POSSL_PROVIDER; operation_id : integer;const name, properties : PUTF8Char; new_method : Tevp_fetch_new_method ; up_ref_method : Tevp_fetch_up_ref_method; free_method : Tevp_fetch_free_method):Pointer;
procedure evp_generic_do_all( libctx : POSSL_LIB_CTX; operation_id : integer; user_fn : Tuser_fn; user_arg : Pointer; new_method : Tevp_fetch_new_method ; up_ref_method : Tevp_fetch_up_ref_method; free_method : Tevp_fetch_free_method);
function evp_get_global_properties_str( libctx : POSSL_LIB_CTX; loadconfig : integer):PUTF8Char;
procedure filter_on_operation_id( id : integer; method, arg : Pointer);
procedure dealloc_tmp_evp_method_store( store : Pointer);
function evp_default_properties_enable_fips_int( libctx : POSSL_LIB_CTX; enable, loadconfig : integer):integer;
function evp_default_properties_merge(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; loadconfig : integer):integer;
function evp_set_default_properties_int(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; loadconfig, mirrored : integer):integer;
function evp_set_parsed_default_properties( libctx : POSSL_LIB_CTX; def_prop : POSSL_PROPERTY_LIST; loadconfig, mirrored : integer):integer;
function EVP_set_default_properties(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

const evp_method_store_method: TOSSL_LIB_CTX_METHOD  = (
    (* We want evp_method_store to be cleaned up before the provider store *)
    priority: OSSL_LIB_CTX_METHOD_PRIORITY_2;
    new_func: evp_method_store_new;
    free_func: evp_method_store_free
);

implementation
uses openssl3.crypto.provider_core, openssl3.crypto.core_namemap,
     openssl3.crypto.context,       openssl3.crypto.property_,
     openssl3.crypto.o_str,         openssl3.crypto.property_parse,
     openssl3.crypto.mem,           OpenSSL3.Err,
     OpenSSL3.common,               openssl3.crypto.core_fetch;

function EVP_set_default_properties(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    Result := evp_set_default_properties_int(libctx, propq, 1, 0);
end;


function evp_set_parsed_default_properties( libctx : POSSL_LIB_CTX; def_prop : POSSL_PROPERTY_LIST; loadconfig, mirrored : integer):integer;
var
  store : POSSL_METHOD_STORE;
  plp : PPOSSL_PROPERTY_LIST;
  propstr : PUTF8Char;
  strsz : size_t;
begin
    store := get_evp_method_store(libctx);
    plp := ossl_ctx_global_properties(libctx, loadconfig);
    if (plp <> nil)  and  (store <> nil) then
    begin
{$IFNDEF FIPS_MODULE}
        propstr := nil;
        if mirrored > 0 then
        begin
            if ossl_global_properties_no_mirrored(libctx) > 0 then
                Exit(0);
        end
        else
        begin
            {
             * These properties have been explicitly set on this libctx, so
             * don't allow any mirroring from a parent libctx.
             }
            ossl_global_properties_stop_mirroring(libctx);
        end;
        strsz := ossl_property_list_to_string(libctx, def_prop, nil, 0);
        if strsz > 0 then
           propstr := OPENSSL_malloc(strsz* Char_Size);
        if propstr = nil then begin
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        if ossl_property_list_to_string(libctx, def_prop, propstr,
                                         strsz) = 0  then
        begin
            OPENSSL_free(propstr);
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        ossl_provider_default_props_update(libctx, propstr);
        OPENSSL_free(propstr);
{$ENDIF}
        ossl_property_free( plp^);
        plp^ := def_prop;
        if store <> nil then Exit(ossl_method_store_flush_cache(store, 0));
    end;
    ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
    Result := 0;
end;



function evp_set_default_properties_int(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; loadconfig, mirrored : integer):integer;
var
  pl : POSSL_PROPERTY_LIST;
begin
    pl := nil;
    pl := ossl_parse_query(libctx, propq, 1);
    if (propq <> nil)  and  (pl = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DEFAULT_QUERY_PARSE_ERROR);
        Exit(0);
    end;
    if 0>=evp_set_parsed_default_properties(libctx, pl, loadconfig, mirrored) then
    begin
        ossl_property_free(pl);
        Exit(0);
    end;
    Result := 1;
end;



function evp_default_properties_merge(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; loadconfig : integer):integer;
var
  plp : PPOSSL_PROPERTY_LIST;
  pl1, pl2 : POSSL_PROPERTY_LIST;
begin
    plp := ossl_ctx_global_properties(libctx, loadconfig);
    if propq = nil then Exit(1);
    if (plp = nil)  or  (plp^ = nil) then
       Exit(evp_set_default_properties_int(libctx, propq, 0, 0));
    pl1 := ossl_parse_query(libctx, propq, 1 );
    if pl1 = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DEFAULT_QUERY_PARSE_ERROR);
        Exit(0);
    end;
    pl2 := ossl_property_merge(pl1, plp^);
    ossl_property_free(pl1);
    if pl2 = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>=evp_set_parsed_default_properties(libctx, pl2, 0, 0 )then
    begin
        ossl_property_free(pl2);
        Exit(0);
    end;
    Result := 1;
end;


function evp_default_properties_enable_fips_int( libctx : POSSL_LIB_CTX; enable, loadconfig : integer):integer;
var
  query : PUTF8Char;
begin
    query := get_result(enable <> 0 , 'fips=yes' , '-fips');
    Result := evp_default_properties_merge(libctx, query, loadconfig);
end;


procedure dealloc_tmp_evp_method_store( store : Pointer);
begin
    if store <> nil then
       ossl_method_store_free(store);
end;


procedure filter_on_operation_id( id : integer; method, arg : Pointer);
var
  data : Pfilter_data_st;
begin
    data := arg;
    if id and METHOD_ID_OPERATION_MASK = data.operation_id then
        data.user_fn(method, data.user_arg);
end;


function evp_get_global_properties_str( libctx : POSSL_LIB_CTX; loadconfig : integer):PUTF8Char;
var
  propstr : PUTF8Char;
  plp: PPOSSL_PROPERTY_LIST;
  sz : size_t;
begin
    plp := ossl_ctx_global_properties(libctx, loadconfig);
    propstr := nil;
    if plp = nil then
       Exit('');//  OPENSSL_strdup(''));
    sz := ossl_property_list_to_string(libctx, plp^, nil, 0);
    if sz = 0 then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    propstr := OPENSSL_malloc(sz);
    if propstr = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if ossl_property_list_to_string(libctx, plp^, propstr, sz) = 0  then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(propstr);
        Exit(nil);
    end;
    Result := propstr;
end;

procedure evp_generic_do_all( libctx : POSSL_LIB_CTX; operation_id : integer;
                              user_fn : Tuser_fn; user_arg : Pointer;
                              new_method : Tevp_fetch_new_method ;
                              up_ref_method : Tevp_fetch_up_ref_method;
                              free_method : Tevp_fetch_free_method);
var
    methdata : evp_method_data_st;
    data     : filter_data_st;
    store    : POSSL_METHOD_STORE;
begin
    methdata.libctx := libctx;
    methdata.tmp_store := nil;
    inner_evp_generic_fetch(@methdata, nil, operation_id, 0, nil, nil,
                             new_method, up_ref_method, free_method);
    data.operation_id := operation_id;
    data.user_fn := user_fn;
    data.user_arg := user_arg;
    if methdata.tmp_store <> nil then
       ossl_method_store_do_all(methdata.tmp_store, filter_on_operation_id, @data);

    store := get_evp_method_store(libctx);
    ossl_method_store_do_all(store, filter_on_operation_id, @data);
    dealloc_tmp_evp_method_store(methdata.tmp_store);
end;

function evp_generic_fetch_from_prov(prov : POSSL_PROVIDER; operation_id : integer;
                                     const name, properties : PUTF8Char;
                                     new_method : Tevp_fetch_new_method ;
                                     up_ref_method : Tevp_fetch_up_ref_method;
                                     free_method : Tevp_fetch_free_method): Pointer;
var
    methdata : evp_method_data_st;
    method   : Pointer;
begin
    methdata.libctx := ossl_provider_libctx(prov);
    methdata.tmp_store := nil;
    method := inner_evp_generic_fetch(@methdata, prov, operation_id,
                                     0, name, properties,
                                     new_method, up_ref_method, free_method);
    dealloc_tmp_evp_method_store(methdata.tmp_store);
    Result := method;
end;


function evp_names_do_all( prov : POSSL_PROVIDER; number : integer; fn : Tevp_fetch_fn; data : Pointer):integer;
var
  libctx : POSSL_LIB_CTX;
  namemap : POSSL_NAMEMAP;
begin
    libctx := ossl_provider_libctx(prov);
    namemap := ossl_namemap_stored(libctx);
    Result := ossl_namemap_doall_names(namemap, number, fn, data);
end;

function evp_generic_fetch(libctx : POSSL_LIB_CTX; operation_id : integer;
                           const name, properties : PUTF8Char;
                           new_method : Tevp_fetch_new_method ;
                           up_ref_method : Tevp_fetch_up_ref_method;
                           free_method : Tevp_fetch_free_method): Pointer;
var
    methdata : evp_method_data_st;
begin
    methdata.libctx := libctx;
    methdata.tmp_store := nil;
    Result := inner_evp_generic_fetch(@methdata, nil, operation_id,
                                     0, name, properties,
                                     new_method, up_ref_method, free_method);
    dealloc_tmp_evp_method_store(methdata.tmp_store);

end;

procedure destruct_evp_method( method, data : Pointer);
var
  methdata : Pevp_method_data_st;
begin
    methdata := data;
    methdata.destruct_method(method);
end;


function construct_evp_method(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pevp_method_data_st;
    libctx   : POSSL_LIB_CTX;
    namemap  : POSSL_NAMEMAP;
    names    : PUTF8Char;
    name_id  : integer;
    method   : Pointer;
    namenum  : POPENSSL_LHASH;
begin
    {
     * This function is only called if get_evp_method_from_store() returned
     * nil, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that ossl_namemap_add_name() will return its corresponding
     * number.
     }
    methdata := data;
    libctx := ossl_provider_libctx(prov);
    namemap := ossl_namemap_stored(libctx);
    namenum := POPENSSL_LHASH(namemap.namenum);

    names := algodef.algorithm_names;
    name_id := ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);

    //construct_evp_method
    //if name_id = 149 then
      // Writeln('catch bug!!');
    method := methdata.method_from_algorithm(name_id, algodef, prov);
    {
     * Flag to indicate that there was actual construction errors.  This
     * helps inner_evp_generic_fetch() determine what error it should
     * record on inaccessible algorithms.
     }
    if method = nil then
       methdata.flag_construct_error_occurred := 1;
    Result := method;
end;

function evp_method_store_flush( libctx : POSSL_LIB_CTX):integer;
var
  store : POSSL_METHOD_STORE;
begin
    store := get_evp_method_store(libctx);
    if store <> nil then
       Exit(ossl_method_store_flush_cache(store, 1));
    Result := 1;
end;

function put_evp_method_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
var
    methdata : Pevp_method_data_st;
    namemap  : POSSL_NAMEMAP;
    name_id  : integer;
    meth_id  : uint32;
    l        : size_t;
    q        : PUTF8Char;
begin
    methdata := data;
    l := 0;
    {
     * put_evp_method_in_store() is only called with an EVP method that was
     * successfully created by construct_method() below, which means that
     * all the names should already be stored in the namemap with the same
     * numeric identity, so just use the first to get that identity.
     }
    if names <> nil then
    begin
        q := strchr(names, NAME_SEPARATOR);
        l := get_result(q = nil , length(names) , size_t(q - names));
    end;
    namemap := ossl_namemap_stored(methdata.libctx) ;
    name_id := ossl_namemap_name2num_n(namemap, names, l);
    meth_id := evp_method_id(name_id, methdata.operation_id);
    if (namemap = nil ) or  (name_id = 0) or  (meth_id = 0) then
        Exit(0);
    if (store = nil) then
    begin
        store := get_evp_method_store(methdata.libctx );
        if (store = nil) then
           Exit(0);
    end;
    Result := ossl_method_store_add(store, prov, meth_id, propdef, method,
                    methdata.refcnt_up_method, methdata.destruct_method);
end;

function get_evp_method_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pevp_method_data_st;
    method   : Pointer;
    name_id  : integer;
    meth_id  : uint32;
    namemap  : POSSL_NAMEMAP;
    names,
    q        : PUTF8Char;
    l        : size_t;
begin
    methdata := data;
    method := nil;
    //name_id := 0;
    {
     * get_evp_method_from_store() is only called to try and get the method
     * that evp_generic_fetch() is asking for, and the operation id as well
     * as the name or name id are passed via methdata.
     }
    name_id := methdata.name_id;
    if (name_id = 0)  and  (methdata.names <> nil) then
    begin
        namemap := ossl_namemap_stored(methdata.libctx);
        names := methdata.names;
        q := strchr(names, NAME_SEPARATOR);
        l := get_result(q = nil , length(names) , size_t(q - names));
        if namemap = nil then Exit(nil);
        name_id := ossl_namemap_name2num_n(namemap, names, l);
    end;

    meth_id := evp_method_id(name_id, methdata.operation_id );
    if (name_id = 0 )  or (meth_id = 0) then
        Exit(nil);
    if (store = nil) then
    begin
       store := get_evp_method_store(methdata.libctx );
       if (store = nil)  then
          Exit(nil);
    end;
    if  0>= ossl_method_store_fetch(store, meth_id, methdata.propquery, prov, method) then
        Exit(nil);
    Result := method;
end;

function get_tmp_evp_method_store( data : Pointer):Pointer;
var
  methdata : Pevp_method_data_st;
begin
    methdata := data;
    if methdata.tmp_store = nil then
       methdata.tmp_store := ossl_method_store_new(methdata.libctx);
    Result := methdata.tmp_store;
end;

function evp_method_id( name_id : integer; operation_id : uint32):uint32;
begin
    if  not ossl_assert( (name_id > 0)  and (name_id <= METHOD_ID_NAME_MAX) ) or
        not ossl_assert( (operation_id > 0) and (operation_id <= METHOD_ID_OPERATION_MAX) ) then
        Exit(0);
    Result := ( (name_id  shl  METHOD_ID_NAME_OFFSET) and METHOD_ID_NAME_MASK )
            or( (operation_id and METHOD_ID_OPERATION_MASK) );
end;

procedure evp_method_store_free( vstore : Pointer);
begin
    ossl_method_store_free(vstore);
end;

function evp_method_store_new( ctx : POSSL_LIB_CTX):Pointer;
begin
    Result := ossl_method_store_new(ctx);
end;



function get_evp_method_store(libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
begin
   Result := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX,
                                 @evp_method_store_method);
end;


function inner_evp_generic_fetch(methdata : Pevp_method_data_st; prov : POSSL_PROVIDER;
                                 operation_id, name_id : integer;{const} name, properties : PUTF8Char;
                                 new_method : Tevp_fetch_new_method ; up_ref_method :Tevp_fetch_up_ref_method;
                                 free_method : Tevp_fetch_free_method):Pointer;
var
    store       : POSSL_METHOD_STORE;
    namemap     : POSSL_NAMEMAP;
    method      : Pointer;
    unsupported : Boolean;
    mcm         : TOSSL_METHOD_CONSTRUCT_METHOD;
    code        : integer;
    meth_id     : uint32_t;
    fmt: string;
    s, nm, prop: PUTF8Char;
    ret: int;
begin
    store   := get_evp_method_store(methdata.libctx);
    namemap := ossl_namemap_stored(methdata.libctx);
    meth_id := 0;
    method := nil;
    unsupported := Boolean(0);
    mcm.get_tmp_store := get_tmp_evp_method_store;
    mcm.get           := get_evp_method_from_store;
    mcm.put           := put_evp_method_in_store;
    mcm.construct     := construct_evp_method;
    mcm.destruct      := destruct_evp_method ;

    if (store = nil)  or  (namemap = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(nil);
    end;
    {
     * If there's ever an operation_id = 0 passed, we have an internal
     * programming error.
     }
    if  not ossl_assert(operation_id > 0 ) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    {
     * If we have been passed both a name_id and a name, we have an
     * internal programming error.
     }
    if  not ossl_assert( (name_id = 0)  or  (name = nil) ) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    { If we haven't received a name id yet, try to get one for the name }
    if (name_id = 0)  and  (name <> nil) then
        name_id := ossl_namemap_name2num(namemap, name);
    {
     * If we have a name id, calculate a method id with evp_method_id().
     *
     * evp_method_id returns 0 if we have too many operations (more than
     * about 2^8) or too many names (more than about 2^24).  In that case,
     * we can't create any new method.
     * For all intents and purposes, this is an internal error.
     }
    meth_id := evp_method_id(name_id, operation_id);
    if (name_id <> 0)  and  (meth_id = 0) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    {
     * If we haven't found the name yet, chances are that the algorithm to
     * be fetched is unsupported.
     }
    if name_id = 0 then
       unsupported := Boolean(1);
    ret := ossl_method_store_cache_get(store, prov, meth_id, properties, method);
    if (meth_id = 0) or (0 >= ret)then
    begin
        methdata.operation_id := operation_id;
        methdata.name_id := name_id;
        methdata.names := name;
        methdata.propquery := properties;
        methdata.method_from_algorithm := new_method;
        methdata.refcnt_up_method := up_ref_method;
        methdata.destruct_method := free_method;
        methdata.flag_construct_error_occurred := 0;
        method := ossl_method_construct(methdata.libctx, operation_id,
                                        @prov, 0, { !force_cache }
                                        @mcm, methdata);
        if (method <> nil)   then
        begin
            {
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_evp_method_from_store() and
             * put_evp_method_in_store() above.
             }
            if name_id = 0 then
                name_id := ossl_namemap_name2num(namemap, name);
            meth_id := evp_method_id(name_id, operation_id);
            if name_id <> 0 then
               ossl_method_store_cache_set(store, prov, meth_id, properties,
                                            method, up_ref_method, free_method);
        end;
        {
         * If we never were in the constructor, the algorithm to be fetched
         * is unsupported.
         }
        unsupported := not Boolean(methdata.flag_construct_error_occurred);
    end;

    if ( (name_id <> 0)  or  (name <> nil) ) and  (method = nil) then
    begin
        code := get_result(unsupported, ERR_R_UNSUPPORTED , ERR_R_FETCH_FAILED);
        if name = nil then
            name := ossl_namemap_num2name(namemap, name_id, 0);

        s := ossl_lib_ctx_get_descriptor(methdata.libctx);
        nm := get_result(name = nil , 'NULL' , name);
        prop := get_result(properties = nil , 'NULL' , properties);
        fmt := Format('%s, Algorithm (%s : %d), Properties (%s)', [s,  nm, name_id, prop]);
        ERR_raise_data(ERR_LIB_EVP, code, fmt);
    end;
    Result := method;
end;


function evp_is_a(prov : POSSL_PROVIDER; number : integer;const legacy_name, name : PUTF8Char):Boolean;
var
  libctx : POSSL_LIB_CTX;
  namemap : POSSL_NAMEMAP;
begin
    libctx := ossl_provider_libctx(prov);
    namemap := ossl_namemap_stored(libctx);
    if prov = nil then
       number := ossl_namemap_name2num(namemap, legacy_name);
    Result := ossl_namemap_name2num(namemap, name) = number;
end;

end.
