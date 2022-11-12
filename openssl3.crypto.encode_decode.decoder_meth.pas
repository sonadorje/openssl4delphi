unit openssl3.crypto.encode_decode.decoder_meth;

interface
uses OpenSSL.Api, SysUtils;

type
  Tuser_fn = procedure(decoder: POSSL_DECODER; arg : Pointer);
  decoder_data_st = record
    libctx    : POSSL_LIB_CTX;
    id        : integer;
    names,
    propquery : PUTF8Char;
    tmp_store : POSSL_METHOD_STORE;
    flag_construct_error_occurred: uint32;
  end;
  Pdecoder_data_st = ^decoder_data_st;

  do_one_data_st = record
    user_fn:  Tuser_fn;
    user_arg: Pointer;
  end;
  Pdo_one_data_st = ^do_one_data_st;

 function inner_ossl_decoder_fetch(methdata : Pdecoder_data_st; id : integer; name, properties : PUTF8Char):POSSL_DECODER;
 function OSSL_DECODER_get0_provider(const decoder : POSSL_DECODER):POSSL_PROVIDER;
 function OSSL_DECODER_get0_name(const decoder : POSSL_DECODER):PUTF8Char;
 function OSSL_DECODER_get0_properties(const decoder : POSSL_DECODER):PUTF8Char;
 function OSSL_DECODER_is_a(const decoder : POSSL_DECODER; name : PUTF8Char):integer;
 function OSSL_DECODER_up_ref( decoder : Pointer):integer;
 function ossl_decoder_parsed_properties(const decoder : POSSL_DECODER):POSSL_PROPERTY_LIST;
 procedure OSSL_DECODER_free( decoder : POSSL_DECODER);
 procedure OSSL_DECODER_do_all_provided( libctx : POSSL_LIB_CTX; user_fn : Tuser_fn; user_arg : Pointer);
 function get_decoder_store( libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
 procedure decoder_store_free( vstore : Pointer);
 function decoder_store_new( ctx : POSSL_LIB_CTX):Pointer;
 function get_tmp_decoder_store( data : Pointer):Pointer;
 function get_decoder_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
 function put_decoder_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
 function construct_decoder(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
 function ossl_decoder_from_algorithm(id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
 function ossl_decoder_new:POSSL_DECODER;
 procedure destruct_decoder( method, data : Pointer);
 function up_ref_decoder( method : Pointer):integer;
 procedure free_decoder( method : Pointer);
 procedure do_one( id : integer; method, arg : Pointer);
  procedure dealloc_tmp_decoder_store( store : Pointer);
 function OSSL_DECODER_CTX_new:POSSL_DECODER_CTX;
 procedure OSSL_DECODER_CTX_free( ctx : POSSL_DECODER_CTX);

 const
   decoder_store_method: TOSSL_LIB_CTX_METHOD  = (
    (* We want decoder_store to be cleaned up before the provider store *)
    priority : OSSL_LIB_CTX_METHOD_PRIORITY_2;
    new_func : decoder_store_new;
    free_func : decoder_store_free
);

implementation
uses OpenSSL3.common, OpenSSL3.Err,     openssl3.crypto.provider_core,
     openssl3.crypto.mem,               openssl3.crypto.property_parse,
     OpenSSL3.threads_none,             openssl3.crypto.context,
     openssl3.crypto.passphrase,        openssl3.crypto.core_fetch,

     openssl3.crypto.property_,         openssl3.crypto.core_algorithm,
     openssl3.crypto.core_namemap,      openssl3.include.internal.refcount,
     openssl3.crypto.encode_decode.decoder_lib;

procedure OSSL_DECODER_CTX_free( ctx : POSSL_DECODER_CTX);
begin
    if ctx <> nil then
    begin
        if Assigned(ctx.cleanup) then
            ctx.cleanup(ctx.construct_data);
        sk_OSSL_DECODER_INSTANCE_pop_free(ctx.decoder_insts,
                                          ossl_decoder_instance_free);
        ossl_pw_clear_passphrase_data(@ctx.pwdata);
        OPENSSL_free(ctx);
    end;
end;

function OSSL_DECODER_CTX_new:POSSL_DECODER_CTX;
var
  ctx : POSSL_DECODER_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof(ctx^));
    if ctx = nil then
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
    ctx^ := default(TOSSL_DECODER_CTX);
    Result := ctx;
end;


procedure dealloc_tmp_decoder_store( store : Pointer);
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



function up_ref_decoder( method : Pointer):integer;
begin
    Result := OSSL_DECODER_up_ref(method);
end;


procedure free_decoder( method : Pointer);
begin
    OSSL_DECODER_free(method);
end;



procedure destruct_decoder( method, data : Pointer);
begin
    OSSL_DECODER_free(method);
end;


function ossl_decoder_new:POSSL_DECODER;
var
  decoder : POSSL_DECODER;
begin
    decoder := nil;
    decoder := OPENSSL_zalloc(sizeof(decoder^)) ;
    decoder.base.lock := CRYPTO_THREAD_lock_new();
    if (decoder = nil) or  (decoder.base.lock = nil) then
    begin
        OSSL_DECODER_free(decoder);
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    decoder.base.refcnt := 1;
    Result := decoder;
end;

function ossl_decoder_from_algorithm(id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  decoder : POSSL_DECODER;
  fns : POSSL_DISPATCH;
  libctx : POSSL_LIB_CTX;
begin
    decoder := nil;
    fns := algodef._implementation;
    libctx := ossl_provider_libctx(prov);
    decoder := ossl_decoder_new();
    if decoder = nil then
        Exit(nil);
    decoder.base.id := id;
    decoder.base.name := ossl_algorithm_get1_first_name(algodef) ;
    if decoder.base.name =  nil then
    begin
        OSSL_DECODER_free(decoder);
        Exit(nil);
    end;
    decoder.base.algodef := algodef;
    decoder.base.parsed_propdef := ossl_parse_property(libctx, algodef.property_definition);
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
            OSSL_FUNC_DECODER_NEWCTX:
                if not Assigned(decoder.newctx) then
                   decoder.newctx := _OSSL_FUNC_decoder_newctx(fns);
                //break;
            OSSL_FUNC_DECODER_FREECTX:
                if not Assigned(decoder.freectx) then
                   decoder.freectx := _OSSL_FUNC_decoder_freectx(fns);
                //break;
            OSSL_FUNC_DECODER_GET_PARAMS:
                if not Assigned(decoder.get_params) then
                    decoder.get_params := _OSSL_FUNC_decoder_get_params(fns);
                //break;
            OSSL_FUNC_DECODER_GETTABLE_PARAMS:
                if not Assigned(decoder.gettable_params) then
                   decoder.gettable_params := _OSSL_FUNC_decoder_gettable_params(fns);
                //break;
            OSSL_FUNC_DECODER_SET_CTX_PARAMS:
                if not Assigned(decoder.set_ctx_params) then
                    decoder.set_ctx_params := _OSSL_FUNC_decoder_set_ctx_params(fns);
                //break;
            OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS:
                if not Assigned(decoder.settable_ctx_params) then
                   decoder.settable_ctx_params := _OSSL_FUNC_decoder_settable_ctx_params(fns);
                //break;
            OSSL_FUNC_DECODER_DOES_SELECTION:
                if not Assigned(decoder.does_selection) then
                   decoder.does_selection := _OSSL_FUNC_decoder_does_selection(fns);
                //break;
            OSSL_FUNC_DECODER_DECODE:
                if not Assigned(decoder.decode) then
                   decoder.decode := _OSSL_FUNC_decoder_decode(fns);
                //break;
            OSSL_FUNC_DECODER_EXPORT_OBJECT:
                if not Assigned(decoder.export_object) then
                   decoder.export_object := _OSSL_FUNC_decoder_export_object(fns);
                //break;
        end;
        Inc(fns);
    end;
    {
     * Try to check that the method is sensible.
     * If you have a constructor, you must have a destructor and vice versa.
     * You must have at least one of the encoding driver functions.
     }
    if NOT ( ( (not Assigned(decoder.newctx))  and  (not Assigned(decoder.freectx)) )  or
             ( (    Assigned(decoder.newctx))      and  (Assigned(decoder.freectx)) ))
         or  (not Assigned(decoder.decode))  then
    begin
        OSSL_DECODER_free(decoder);
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    if (prov <> nil)  and  (0>= ossl_provider_up_ref(prov)) then
    begin
        OSSL_DECODER_free(decoder);
        Exit(nil);
    end;
    decoder.base.prov := prov;
    Result := decoder;
end;

function construct_decoder(const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pdecoder_data_st;
    libctx   : POSSL_LIB_CTX;
    namemap  : POSSL_NAMEMAP;
    names    : PUTF8Char;
    id       : integer;
    method   : Pointer;
begin
    {
     * This function is only called if get_decoder_from_store() returned
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
    //if id = 20 then
      // writeln('vatch..');
    if id <> 0 then
       method := ossl_decoder_from_algorithm(id, algodef, prov);
    {
     * Flag to indicate that there was actual construction errors.  This
     * helps inner_evp_generic_fetch() determine what error it should
     * record on inaccessible algorithms.
     }
    if method = nil then
       methdata.flag_construct_error_occurred := 1;

    Result := method;
end;




function put_decoder_in_store(store, method : Pointer;const prov : POSSL_PROVIDER; names, propdef : PUTF8Char; data : Pointer):integer;
var
    methdata : Pdecoder_data_st;
    namemap  : POSSL_NAMEMAP;
    id       : integer;
    l        : size_t;
    q        : PUTF8Char;
begin
    methdata := data;
    l := 0;
    {
     * put_decoder_in_store() is only called with an OSSL_DECODER method that
     * was successfully created by construct_decoder() below, which means that
     * all the names should already be stored in the namemap with the same
     * numeric identity, so just use the first to get that identity.
     }
    if names <> nil then
    begin
         q := strchr(names, NAME_SEPARATOR);
         if q = nil  then
            l := strlen(names)
         else
            l := size_t(q - names);
    end;
    namemap := ossl_namemap_stored(methdata.libctx);
    id := ossl_namemap_name2num_n(namemap, names, l);
    if (namemap = nil) or  (id =  0) then
        Exit(0);
    if store = nil  then
    begin
      store := get_decoder_store(methdata.libctx);
      if store = nil  then
         Exit(0);
    end;
    Result := ossl_method_store_add(store, prov, id, propdef, method,
                               OSSL_DECODER_up_ref,
                               @OSSL_DECODER_free);
end;





function get_decoder_from_store(store : Pointer;const prov : PPOSSL_PROVIDER; data : Pointer):Pointer;
var
    methdata : Pdecoder_data_st;
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
     * get_decoder_from_store() is only called to try and get the method
     * that OSSL_DECODER_fetch() is asking for, and the name or name id are
     * passed via methdata.
     }
    id := methdata.id;
    if (id = 0)  and  (methdata.names <> nil) then
    begin
        namemap := ossl_namemap_stored(methdata.libctx);
       names := methdata.names;
        q := strchr(names, NAME_SEPARATOR);
        l := get_result(q = nil , size_t(Length(names)) , size_t(q - names));
        if namemap = nil then
           Exit(nil);
        id := ossl_namemap_name2num_n(namemap, names, l);
    end;
    if id = 0 then Exit(nil);
    if store = nil then
    begin
       store := get_decoder_store(methdata.libctx);
       if store = nil then
          Exit(nil);
    end;
    if 0>= ossl_method_store_fetch(store, id, methdata.propquery, prov, method )then
        Exit(nil);
    Result := method;
end;



function get_tmp_decoder_store( data : Pointer):Pointer;
var
  methdata : Pdecoder_data_st;
begin
    methdata := data;
    if methdata.tmp_store = nil then
       methdata.tmp_store := ossl_method_store_new(methdata.libctx);
    Result := methdata.tmp_store;
end;


procedure decoder_store_free( vstore : Pointer);
begin
    ossl_method_store_free(vstore);
end;


function decoder_store_new( ctx : POSSL_LIB_CTX):Pointer;
begin
    Result := ossl_method_store_new(ctx);
end;



function get_decoder_store( libctx : POSSL_LIB_CTX):POSSL_METHOD_STORE;
begin
    Result := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX,
                                 @decoder_store_method);
end;





function inner_ossl_decoder_fetch(methdata : Pdecoder_data_st; id : integer; name, properties : PUTF8Char):POSSL_DECODER;
var
    store       : POSSL_METHOD_STORE;
    namemap     : POSSL_NAMEMAP;
    method      : Pointer;
    unsupported : Boolean;
    //mcm         : TOSSL_METHOD_CONSTRUCT_METHOD;
    prov        : POSSL_PROVIDER;
    code        : integer;
const
    mcm: TOSSL_METHOD_CONSTRUCT_METHOD = (
            get_tmp_store:get_tmp_decoder_store;
            get: get_decoder_from_store;
            put: put_decoder_in_store;
            construct: construct_decoder;
            destruct: destruct_decoder
   );
begin
    store := get_decoder_store(methdata.libctx);
    namemap := ossl_namemap_stored(methdata.libctx);
    method := nil;
    unsupported := Boolean(0);
    if (store = nil)  or  (namemap = nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(nil);
    end;
    {
     * If we have been passed both an id and a name, we have an
     * internal programming error.
     }
    if not ossl_assert( (id = 0)  or  (name = nil) ) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    if (id = 0)  and  (name <> nil) then
       id := ossl_namemap_name2num(namemap, name);
    {
     * If we haven't found the name yet, chances are that the algorithm to
     * be fetched is unsupported.
     }
    if id = 0 then
       unsupported := Boolean(1);
    if (id = 0)
         or  (0>= ossl_method_store_cache_get(store, nil, id, properties, method)) then
    begin

        prov := nil;
        methdata.id := id;
        methdata.names := name;
        methdata.propquery := properties;
        methdata.flag_construct_error_occurred := 0;
        method := ossl_method_construct(methdata.libctx, OSSL_OP_DECODER,
                                            @prov, 0 { !force_cache } ,
                                            @mcm, methdata);
        if (method <> nil) then
        begin
            {
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_decoder_from_store() and
             * put_decoder_in_store() above.
             }
            if (id = 0)  and (name <> nil) then
                id := ossl_namemap_name2num(namemap, name);
            if id <> 0 then
               ossl_method_store_cache_set(store, prov, id, properties, method,
                                            up_ref_decoder, free_decoder);
        end;
        {
         * If we never were in the constructor, the algorithm to be fetched
         * is unsupported.
         }
        unsupported := not Boolean(methdata.flag_construct_error_occurred);
    end;
    if (id <> 0)  or  (name <> nil) and  (method = nil) then
    begin
        code := get_result(unsupported , ERR_R_UNSUPPORTED , ERR_R_FETCH_FAILED);
        if name = nil then
           name := ossl_namemap_num2name(namemap, id, 0);
        ERR_raise_data(ERR_LIB_OSSL_DECODER, code,
                     Format('%s, Name (%s : %d), Properties (%s)',
                       [ossl_lib_ctx_get_descriptor(methdata.libctx),
                       get_result(name = nil , '<null>' , name), id,
                       get_result(properties = nil , '<null>' , properties)]));
    end;
    Result := method;
end;

procedure OSSL_DECODER_do_all_provided( libctx : POSSL_LIB_CTX; user_fn : Tuser_fn; user_arg : Pointer);
var
    methdata : decoder_data_st;
    data     : do_one_data_st;
begin
    methdata.libctx := libctx;
    methdata.tmp_store := nil;
    inner_ossl_decoder_fetch(@methdata, 0, nil, nil { properties });
    data.user_fn := user_fn;
    data.user_arg := user_arg;
    if methdata.tmp_store <> nil then
       ossl_method_store_do_all(methdata.tmp_store, do_one, @data);
    ossl_method_store_do_all(get_decoder_store(libctx), do_one, @data);
    dealloc_tmp_decoder_store(methdata.tmp_store);
end;

procedure OSSL_DECODER_free( decoder : POSSL_DECODER);
var
  ref : integer;
begin
    ref := 0;
    if decoder = nil then
       exit;
    CRYPTO_DOWN_REF((decoder).base.refcnt, ref, (decoder).base.lock);
    if ref > 0 then
       Exit;
    OPENSSL_free(decoder.base.name);
    ossl_property_free(decoder.base.parsed_propdef);
    ossl_provider_free(decoder.base.prov);
    CRYPTO_THREAD_lock_free(decoder.base.lock);
    OPENSSL_free(decoder);
end;

function ossl_decoder_parsed_properties(const decoder : POSSL_DECODER):POSSL_PROPERTY_LIST;
begin
    if not ossl_assert(decoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := decoder.base.parsed_propdef;
end;



function OSSL_DECODER_up_ref( decoder : Pointer):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(POSSL_DECODER(decoder).base.refcnt, ref, POSSL_DECODER(decoder).base.lock);
    Result := 1;
end;




function OSSL_DECODER_is_a(const decoder : POSSL_DECODER; name : PUTF8Char):integer;
var
  libctx : POSSL_LIB_CTX;
  namemap : POSSL_NAMEMAP;
begin
    if decoder.base.prov <> nil then
    begin
        libctx := ossl_provider_libctx(decoder.base.prov);
        namemap := ossl_namemap_stored(libctx);
        Exit(Int(ossl_namemap_name2num(namemap, name) = decoder.base.id));
    end;
    Result := 0;
end;

function OSSL_DECODER_get0_properties(const decoder : POSSL_DECODER):PUTF8Char;
begin
    if not ossl_assert(decoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := decoder.base.algodef.property_definition;
end;

function OSSL_DECODER_get0_name(const decoder : POSSL_DECODER):PUTF8Char;
begin
    Result := decoder.base.name;
end;

function OSSL_DECODER_get0_provider(const decoder : POSSL_DECODER):POSSL_PROVIDER;
begin
    if not ossl_assert(decoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := decoder.base.prov;
end;

end.
