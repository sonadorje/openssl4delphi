unit openssl3.crypto.encode_decode.encoder_meth;

interface
uses OpenSSL.Api, SysUtils;

type
  encoder_data_st = record
     libctx                        : POSSL_LIB_CTX;
     id                            : integer;
     names,
     propquery                     : PUTF8Char;
     tmp_store                     : POSSL_METHOD_STORE;
     flag_construct_error_occurred : uint32;
  end;
  Pencoder_data_st = ^encoder_data_st;

  do_one_data_st = record
    user_fn: procedure(encoder: POSSL_ENCODER; arg: Pointer);
    user_arg: Pointer;
  end;
  Pdo_one_data_st = ^do_one_data_st;

  Tencoder_meth_user_fn = procedure(method: POSSL_ENCODER; arg : Pointer);

function OSSL_ENCODER_CTX_set_params(ctx : POSSL_ENCODER_CTX;const params : POSSL_PARAM):integer;
function OSSL_ENCODER_get0_provider(const encoder : POSSL_ENCODER):POSSL_PROVIDER;
 function OSSL_ENCODER_is_a(const encoder : POSSL_ENCODER;const name : PUTF8Char):integer;
function OSSL_ENCODER_up_ref( encoder : Pointer{ POSSL_ENCODER}):integer;
function ossl_encoder_parsed_properties(const encoder : POSSL_ENCODER):POSSL_PROPERTY_LIST;
function OSSL_ENCODER_get0_name(const encoder : POSSL_ENCODER):PUTF8Char;
function OSSL_ENCODER_get0_properties(const encoder : POSSL_ENCODER):PUTF8Char;
procedure OSSL_ENCODER_free( encoder :Pointer{ POSSL_ENCODER});
 procedure OSSL_ENCODER_do_all_provided( libctx : POSSL_LIB_CTX; user_fn : Tencoder_meth_user_fn; user_arg : Pointer);
 function inner_ossl_encoder_fetch(methdata : Pencoder_data_st; id : integer;{const} name, properties : PUTF8Char):POSSL_ENCODER;
 function get_encoder_store( libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
 procedure encoder_store_free( vstore : Pointer);
  function encoder_store_new( ctx : POSSL_LIB_CTX):Pointer;
 function get_tmp_encoder_store( data : Pointer):Pointer;
 function get_encoder_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
  function put_encoder_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
 function construct_encoder(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
  function encoder_from_algorithm(id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
  function ossl_encoder_new:POSSL_ENCODER;
 procedure destruct_encoder( method, data : Pointer);
  function up_ref_encoder( method : Pointer):integer;
  procedure free_encoder( method : Pointer);
   procedure do_one( id : integer; method, arg : Pointer);
   procedure dealloc_tmp_encoder_store( store : Pointer);
   procedure OSSL_ENCODER_CTX_free( ctx : POSSL_ENCODER_CTX);

const  encoder_store_method: TOSSL_LIB_CTX_METHOD = (
    (* We want encoder_store to be cleaned up before the provider store *)
    priority: OSSL_LIB_CTX_METHOD_PRIORITY_2;
    new_func: encoder_store_new;
    free_func: encoder_store_free
);

implementation
uses OpenSSL3.common, OpenSSL3.Err, openssl3.crypto.encode_decode.encoder_lib,
     openssl3.crypto.provider_core, openssl3.crypto.core_namemap,
     openssl3.crypto.property_parse, OpenSSL3.threads_none,
     openssl3.crypto.context, openssl3.crypto.property_,
     openssl3.crypto.passphrase,
     openssl3.crypto.core_algorithm, openssl3.crypto.core_fetch,
     openssl3.include.internal.refcount, openssl3.crypto.mem;


procedure OSSL_ENCODER_CTX_free( ctx : POSSL_ENCODER_CTX);
begin
    if ctx <> nil then
    begin
        sk_OSSL_ENCODER_INSTANCE_pop_free(ctx.encoder_insts,
                                          ossl_encoder_instance_free);
        OPENSSL_free(ctx.construct_data);
        ossl_pw_clear_passphrase_data(@ctx.pwdata);
        OPENSSL_free(ctx);
    end;
end;

procedure dealloc_tmp_encoder_store( store : Pointer);
begin
    if store <> nil then
       ossl_method_store_free(store);
end;

procedure do_one( id : integer; method, arg : Pointer);
var
  data : Pdo_one_data_st;
begin
    data := arg;
    data.user_fn(method, data.user_arg);
end;

function up_ref_encoder( method : Pointer):integer;
begin
    Result := OSSL_ENCODER_up_ref(method);
end;


procedure free_encoder( method : Pointer);
begin
    OSSL_ENCODER_free(method);
end;


procedure destruct_encoder( method, data : Pointer);
begin
    OSSL_ENCODER_free(method);
end;




function ossl_encoder_new:POSSL_ENCODER;
var
  encoder : POSSL_ENCODER;
begin
    encoder := nil;
    encoder := OPENSSL_zalloc(sizeof(encoder^) );
    encoder.base.lock := CRYPTO_THREAD_lock_new();
    if (encoder =  nil) or  (encoder.base.lock = nil) then
    begin
        OSSL_ENCODER_free(encoder);
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    encoder.base.refcnt := 1;
    Result := encoder;
end;

function encoder_from_algorithm(id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  encoder : POSSL_ENCODER;
  fns : POSSL_DISPATCH;
  libctx : POSSL_LIB_CTX;
begin
    encoder := nil;
     fns := algodef._implementation;
    libctx := ossl_provider_libctx(prov);
    encoder := ossl_encoder_new();
    if encoder = nil then
        Exit(nil);
    encoder.base.id := id;
    encoder.base.name := ossl_algorithm_get1_first_name(algodef);
    if encoder.base.name = nil then
    begin
        OSSL_ENCODER_free(encoder);
        Exit(nil);
    end;
    encoder.base.algodef := algodef;
    encoder.base.parsed_propdef := ossl_parse_property(libctx, algodef.property_definition);
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_ENCODER_NEWCTX:
        begin
            if not Assigned(encoder.newctx ) then
               encoder.newctx := _OSSL_FUNC_encoder_newctx(fns);
        end;
        OSSL_FUNC_ENCODER_FREECTX:
        begin
            if not Assigned(encoder.freectx ) then
               encoder.freectx := _OSSL_FUNC_encoder_freectx(fns);
        end;
        OSSL_FUNC_ENCODER_GET_PARAMS:
        begin
            if not Assigned(encoder.get_params ) then
               encoder.get_params := _OSSL_FUNC_encoder_get_params(fns);
        end;
        OSSL_FUNC_ENCODER_GETTABLE_PARAMS:
        begin
            if not Assigned(encoder.gettable_params ) then
               encoder.gettable_params := _OSSL_FUNC_encoder_gettable_params(fns);
        end;
        OSSL_FUNC_ENCODER_SET_CTX_PARAMS:
        begin
            if not Assigned(encoder.set_ctx_params ) then
               encoder.set_ctx_params := _OSSL_FUNC_encoder_set_ctx_params(fns);
        end;
        OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS:
        begin
            if not Assigned(encoder.settable_ctx_params ) then
               encoder.settable_ctx_params := _OSSL_FUNC_encoder_settable_ctx_params(fns);
        end;
        OSSL_FUNC_ENCODER_DOES_SELECTION:
        begin
            if not Assigned(encoder.does_selection ) then
               encoder.does_selection := _OSSL_FUNC_encoder_does_selection(fns);
        end;
        OSSL_FUNC_ENCODER_ENCODE:
        begin
            if not Assigned(encoder.encode ) then
               encoder.encode := _OSSL_FUNC_encoder_encode(fns);
        end;
        OSSL_FUNC_ENCODER_IMPORT_OBJECT:
        begin
            if not Assigned(encoder.import_object ) then
               encoder.import_object := _OSSL_FUNC_encoder_import_object(fns);
        end;
        OSSL_FUNC_ENCODER_FREE_OBJECT:
        begin
            if not Assigned(encoder.free_object ) then
               encoder.free_object := _OSSL_FUNC_encoder_free_object(fns);
        end;
        end;
        Inc(fns);
    end;
    {
     * Try to check that the method is sensible.
     * If you have a constructor, you must have a destructor and vice versa.
     * You must have the encoding driver functions.
     }
    if not ( ( (Addr(encoder.newctx) = nil)  and  (Addr(encoder.freectx) = nil) )  or
             ( (Addr(encoder.newctx) <> nil) and  (Addr(encoder.freectx) <> nil) ) or
             ( (Addr(encoder.import_object) <> nil)  and (Addr(encoder.free_object) <> nil) ) or
             ( (Addr(encoder.import_object) = nil)  and  (Addr(encoder.free_object) = nil) )
           ) or  (Addr(encoder.encode) = nil) then
    begin
        OSSL_ENCODER_free(encoder);
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    if (prov <> nil)  and  (0>= ossl_provider_up_ref(prov)) then
    begin
        OSSL_ENCODER_free(encoder);
        Exit(nil);
    end;
    encoder.base.prov := prov;
    Result := encoder;
end;




function construct_encoder(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pencoder_data_st;
    libctx   : POSSL_LIB_CTX;
    namemap  : POSSL_NAMEMAP;
    names    : PUTF8Char;
    id       : integer;
    method   : Pointer;
begin
    {
     * This function is only called if get_encoder_from_store() returned
     * nil, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that ossl_namemap_add() will return its corresponding number.
     }
    methdata := data;
    libctx := ossl_provider_libctx(prov);
    namemap := ossl_namemap_stored(libctx);
    names := algodef.algorithm_names;
    id := ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    method := nil;
    if id <> 0 then
       method := encoder_from_algorithm(id, algodef, prov);
    {
     * Flag to indicate that there was actual construction errors.  This
     * helps inner_evp_generic_fetch() determine what error it should
     * record on inaccessible algorithms.
     }
    if method = nil then
       methdata.flag_construct_error_occurred := 1;
    Result := method;
end;



function put_encoder_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
var
    methdata : Pencoder_data_st;
    namemap  : POSSL_NAMEMAP;
    id       : integer;
    l        : size_t;
    q        : PUTF8Char;
begin
    methdata := data;
    l := 0;
    {
     * put_encoder_in_store() is only called with an OSSL_ENCODER method that
     * was successfully created by construct_encoder() below, which means that
     * all the names should already be stored in the namemap with the same
     * numeric identity, so just use the first to get that identity.
     }
    if names <> nil then
    begin
        q := strchr(names, NAME_SEPARATOR);
        if q = nil then
           l :=  strlen(names)
        else
           l := size_t(q - names);
    end;
    namemap := ossl_namemap_stored(methdata.libctx);
    id := ossl_namemap_name2num_n(namemap, names, l);
    if (namemap = nil) or  (id = 0) then
        Exit(0);
    if (store = nil) then
    begin
       store := get_encoder_store(methdata.libctx);
       if (store = nil) then
        Exit(0);
    end;
    Exit(ossl_method_store_add(store, prov, id, propdef, method,
                                 OSSL_ENCODER_up_ref,
                                 OSSL_ENCODER_free));
end;




function get_encoder_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pencoder_data_st;
    method   : Pointer;
    id       : integer;
    namemap  : POSSL_NAMEMAP;
    names,
    q        : PUTF8Char;
    l        : size_t;
begin
    methdata := data;
    method := nil;
    {
     * get_encoder_from_store() is only called to try and get the method
     * that OSSL_ENCODER_fetch() is asking for, and the name or name id are
     * passed via methdata.
     }
     id := methdata.id;
    if (id  = 0)  and  (methdata.names <> nil) then
    begin
        namemap := ossl_namemap_stored(methdata.libctx);
        names := methdata.names;
        q := strchr(names, NAME_SEPARATOR);
        l := get_result(q = nil , length(names) , size_t(q - names));
        if namemap = nil then Exit(nil);
        id := ossl_namemap_name2num_n(namemap, methdata.names, l);
    end;
    if id = 0 then Exit(nil);
    if (store = nil) then
    begin
        store := get_encoder_store(methdata.libctx);
        if (store = nil) then
           Exit(nil);
    end;
    if 0>= ossl_method_store_fetch(store, id, methdata.propquery, prov, method) then
        Exit(nil);
    Result := method;
end;




function get_tmp_encoder_store( data : Pointer):Pointer;
var
  methdata : Pencoder_data_st;
begin
    methdata := data;
    if methdata.tmp_store = nil then
       methdata.tmp_store := ossl_method_store_new(methdata.libctx);
    Result := methdata.tmp_store;
end;




procedure encoder_store_free( vstore : Pointer);
begin
    ossl_method_store_free(vstore);
end;


function encoder_store_new( ctx : POSSL_LIB_CTX):Pointer;
begin
    Result := ossl_method_store_new(ctx);
end;


function get_encoder_store( libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
begin
    Exit(ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX,
                                 @encoder_store_method));
end;




function inner_ossl_encoder_fetch(methdata : Pencoder_data_st; id : integer;{const} name, properties : PUTF8Char):POSSL_ENCODER;
var
    store       : POSSL_METHOD_STORE;
    namemap     : POSSL_NAMEMAP;
    method      : Pointer;
    unsupported : integer;
    mcm         : TOSSL_METHOD_CONSTRUCT_METHOD;
    prov        : POSSL_PROVIDER;
    code        : integer;
begin
    store := get_encoder_store(methdata.libctx);
    namemap := ossl_namemap_stored(methdata.libctx);
    method := nil;
    unsupported := 0;
    if (store = nil)  or  (namemap = nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(nil);
    end;
    {
     * If we have been passed both an id and a name, we have an
     * internal programming error.
     }
    if not ossl_assert( (id = 0)  or  (name = nil) ) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    if id = 0 then id := ossl_namemap_name2num(namemap, name);
    {
     * If we haven't found the name yet, chances are that the algorithm to
     * be fetched is unsupported.
     }
    if id = 0 then unsupported := 1;
    if (id = 0)   or
        (0>= ossl_method_store_cache_get(store, nil, id, properties, method) ) then
    begin
        begin
          mcm.get_tmp_store := get_tmp_encoder_store;
          mcm.get := get_encoder_from_store;
          mcm.put := put_encoder_in_store;
          mcm.construct :=  construct_encoder;
          mcm.destruct :=  destruct_encoder;
        end;

        prov := nil;
        methdata.id := id;
        methdata.names := name;
        methdata.propquery := properties;
        method := ossl_method_construct(methdata.libctx, OSSL_OP_ENCODER,
                                 @prov, 0 { !force_cache }, @mcm, methdata);
        methdata.flag_construct_error_occurred := 0;
        if (method <> nil) then
        begin
            {
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_encoder_from_store() and
             * put_encoder_in_store() above.
             }
            if id = 0 then
                id := ossl_namemap_name2num(namemap, name);
            ossl_method_store_cache_set(store, prov, id, properties, method,
                                        up_ref_encoder, free_encoder);
        end;
        {
         * If we never were in the constructor, the algorithm to be fetched
         * is unsupported.
         }
        unsupported := not methdata.flag_construct_error_occurred;
    end;
    if (id <> 0)  or  (name <> nil)  and ( method = nil) then
    begin
        code := get_result(unsupported>0 , ERR_R_UNSUPPORTED , ERR_R_FETCH_FAILED);
        if name = nil then name := ossl_namemap_num2name(namemap, id, 0);
        ERR_raise_data(ERR_LIB_OSSL_ENCODER, code,
                     Format(  ' %s, Name (%s : %d), Properties (%s)' ,
                       [ossl_lib_ctx_get_descriptor(methdata.libctx),
                     get_result(name = nil , ' <null>'  , name), id,
                     get_result(properties = nil ,' <null>'  ,properties)]));
    end;
    Result := method;
end;



procedure OSSL_ENCODER_do_all_provided( libctx : POSSL_LIB_CTX; user_fn : Tencoder_meth_user_fn; user_arg : Pointer);
var
    methdata : encoder_data_st;

    data     : do_one_data_st;
begin
    methdata.libctx := libctx;
    methdata.tmp_store := nil;
    inner_ossl_encoder_fetch(@methdata, 0, nil, nil { properties } );
    data.user_fn := user_fn;
    data.user_arg := user_arg;
    if methdata.tmp_store <> nil then
       ossl_method_store_do_all(methdata.tmp_store, @do_one, @data);
    ossl_method_store_do_all(get_encoder_store(libctx), @do_one, @data);
    dealloc_tmp_encoder_store(methdata.tmp_store);
end;




procedure OSSL_ENCODER_free( encoder : Pointer{ POSSL_ENCODER});
var
  ref : integer;
begin
    ref := 0;
    if encoder = nil then exit;
    CRYPTO_DOWN_REF(POSSL_ENCODER(encoder).base.refcnt, ref, POSSL_ENCODER(encoder).base.lock);
    if ref > 0 then exit;
    OPENSSL_free(POSSL_ENCODER(encoder).base.name);
    ossl_property_free(POSSL_ENCODER(encoder).base.parsed_propdef);
    ossl_provider_free(POSSL_ENCODER(encoder).base.prov);
    CRYPTO_THREAD_lock_free(POSSL_ENCODER(encoder).base.lock);
    OPENSSL_free(encoder);
end;




function OSSL_ENCODER_get0_properties(const encoder : POSSL_ENCODER):PUTF8Char;
begin
    if not ossl_assert(encoder <> nil ) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := encoder.base.algodef.property_definition;
end;




function OSSL_ENCODER_get0_name(const encoder : POSSL_ENCODER):PUTF8Char;
begin
    Result := encoder.base.name;
end;

function ossl_encoder_parsed_properties(const encoder : POSSL_ENCODER):POSSL_PROPERTY_LIST;
begin
    if not ossl_assert(encoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := encoder.base.parsed_propdef;
end;

function OSSL_ENCODER_up_ref( encoder : Pointer):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(POSSL_ENCODER(encoder).base.refcnt, ref, POSSL_ENCODER(encoder).base.lock);
    Result := 1;
end;



function OSSL_ENCODER_is_a(const encoder : POSSL_ENCODER; const name : PUTF8Char):integer;
var
  libctx : POSSL_LIB_CTX;

  namemap : POSSL_NAMEMAP;
begin
    if encoder.base.prov <> nil then
    begin
        libctx := ossl_provider_libctx(encoder.base.prov);
        namemap := ossl_namemap_stored(libctx);
        Exit(Int(ossl_namemap_name2num(namemap, name) = encoder.base.id));
    end;
    Result := 0;
end;


function OSSL_ENCODER_get0_provider(const encoder : POSSL_ENCODER):POSSL_PROVIDER;
begin
    if not ossl_assert(encoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := encoder.base.prov;
end;

function OSSL_ENCODER_CTX_set_params(ctx : POSSL_ENCODER_CTX;const params : POSSL_PARAM):integer;
var
    ok           : integer;
    i,
    l            : size_t;
    encoder_inst : POSSL_ENCODER_INSTANCE;
    encoder      : POSSL_ENCODER;
    encoderctx   : Pointer;
begin
    ok := 1;
    if not ossl_assert(ctx <> nil ) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if ctx.encoder_insts = nil then
       Exit(1);
    l := OSSL_ENCODER_CTX_get_num_encoders(ctx);
    for i := 0 to l-1 do
    begin
        encoder_inst := sk_OSSL_ENCODER_INSTANCE_value(ctx.encoder_insts, i);
        encoder := OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
        encoderctx := OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);
        if (encoderctx = nil)  or  (not Assigned(encoder.set_ctx_params)) then
           continue;
        if 0>= encoder.set_ctx_params(encoderctx, params) then
            ok := 0;
    end;
    Result := ok;
end;

end.
