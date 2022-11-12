unit openssl3.crypto.encode_decode.decoder_pkey;

interface
uses OpenSSL.Api, SysUtils;

type
  collect_decoder_data_st = record
      names          : Pstack_st_OPENSSL_CSTRING;
      ctx            : POSSL_DECODER_CTX;
      total          : integer;
      error_occurred : uint32;
  end;
  Pcollect_decoder_data_st = ^collect_decoder_data_st;
  Tdecoder_pkey_fn  = procedure(kem: PEVP_KEYMGMT; arg: Pointer);
  Tfn_default  = procedure(kem: Pointer; arg: Pointer);
  Tfree_default = procedure (p1 : Pointer);


  function OSSL_DECODER_CTX_set_passphrase(ctx : POSSL_DECODER_CTX;const kstr : PByte; klen : size_t):integer;
  function OSSL_DECODER_CTX_set_passphrase_ui(ctx : POSSL_DECODER_CTX;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
  function OSSL_DECODER_CTX_set_pem_password_cb( ctx : POSSL_DECODER_CTX; cb : Tpem_password_cb; cbarg : Pointer):integer;
  function OSSL_DECODER_CTX_set_passphrase_cb( ctx : POSSL_DECODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function decoder_construct_pkey(decoder_inst : POSSL_DECODER_INSTANCE;const params : POSSL_PARAM; construct_data : Pointer):integer;
  procedure decoder_clean_pkey_construct_arg( construct_data : Pointer);
  procedure collect_name(const name : PUTF8Char; arg : Pointer);
  procedure collect_keymgmt( keymgmt : PEVP_KEYMGMT; arg : Pointer);
  procedure collect_decoder( decoder : POSSL_DECODER; arg : Pointer);
  function ossl_decoder_ctx_setup_for_pkey(ctx : POSSL_DECODER_CTX; pkey : PPEVP_PKEY;const keytype : PUTF8Char; libctx : POSSL_LIB_CTX;const propquery : PUTF8Char):integer;
  function OSSL_DECODER_CTX_new_for_pkey(pkey : PPEVP_PKEY;const input_type, input_structure, keytype : PUTF8Char; selection : integer; libctx : POSSL_LIB_CTX;const propquery : PUTF8Char):POSSL_DECODER_CTX;
  function sk_EVP_KEYMGMT_num(const sk : Pstack_st_EVP_KEYMGMT):integer;
  function sk_EVP_KEYMGMT_value(const sk : Pstack_st_EVP_KEYMGMT; idx : integer):PEVP_KEYMGMT;
  procedure sk_EVP_KEYMGMT_pop_free( sk : Pstack_st_EVP_KEYMGMT; freefunc : sk_EVP_KEYMGMT_freefunc);
  function sk_EVP_KEYMGMT_push( sk : Pstack_st_EVP_KEYMGMT; ptr : PEVP_KEYMGMT):integer;
  function sk_EVP_KEYMGMT_new_null:Pstack_st_EVP_KEYMGMT;
  procedure EVP_KEYMGMT_do_all_provided( libctx : POSSL_LIB_CTX; fn : Tdecoder_pkey_fn; arg : Pointer);


implementation
uses openssl3.crypto.passphrase, openssl3.crypto.encode_decode.decoder_lib,
     openssl3.crypto.encode_decode.decoder_meth, openssl3.crypto.params,
     openssl3.crypto.mem, openssl3.crypto.stack,  OpenSSL3.Err,
     openssl3.crypto.bio.bio_print,  openssl3.crypto.o_str,
     openssl3.crypto.evp.evp_fetch,  openssl3.crypto.safestack,
     openssl3.crypto.evp.keymgmt_meth, openssl3.crypto.provider;

procedure EVP_KEYMGMT_do_all_provided( libctx : POSSL_LIB_CTX; fn : Tdecoder_pkey_fn; arg : Pointer);
begin
   //evp_generic_do_all(libctx, OSSL_OP_KEYMGMT,
     //                  (void (*)(void *, void *))fn, arg,
     //                  keymgmt_from_algorithm,
     //                  (int (*)(void *))EVP_KEYMGMT_up_ref,
     //                  (void (*)(void *))EVP_KEYMGMT_free);

    evp_generic_do_all(libctx, OSSL_OP_KEYMGMT,
                       @fn, arg,
                       keymgmt_from_algorithm,
                       @EVP_KEYMGMT_up_ref,
                       EVP_KEYMGMT_free);
end;




function sk_EVP_KEYMGMT_new_null:Pstack_st_EVP_KEYMGMT;
begin
    Result := Pstack_st_EVP_KEYMGMT(OPENSSL_sk_new_null);
end;



function sk_EVP_KEYMGMT_push( sk : Pstack_st_EVP_KEYMGMT; ptr : PEVP_KEYMGMT):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr));
end;


procedure sk_EVP_KEYMGMT_pop_free( sk : Pstack_st_EVP_KEYMGMT; freefunc : sk_EVP_KEYMGMT_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;



function sk_EVP_KEYMGMT_value(const sk : Pstack_st_EVP_KEYMGMT; idx : integer):PEVP_KEYMGMT;
begin
   Result := PEVP_KEYMGMT(OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;



function sk_EVP_KEYMGMT_num(const sk : Pstack_st_EVP_KEYMGMT):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;

function OSSL_DECODER_CTX_set_passphrase(ctx : POSSL_DECODER_CTX;const kstr : PByte; klen : size_t):integer;
begin
    Result := ossl_pw_set_passphrase(@ctx.pwdata, kstr, klen);
end;


function OSSL_DECODER_CTX_set_passphrase_ui(ctx : POSSL_DECODER_CTX;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
begin
    Result := ossl_pw_set_ui_method(@ctx.pwdata, ui_method, ui_data);
end;


function OSSL_DECODER_CTX_set_pem_password_cb( ctx : POSSL_DECODER_CTX; cb : Tpem_password_cb; cbarg : Pointer):integer;
begin
    Result := ossl_pw_set_pem_password_cb(@ctx.pwdata, cb, cbarg);
end;


function OSSL_DECODER_CTX_set_passphrase_cb( ctx : POSSL_DECODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    Result := ossl_pw_set_ossl_passphrase_cb(@ctx.pwdata, cb, cbarg);
end;


function decoder_construct_pkey(decoder_inst : POSSL_DECODER_INSTANCE;
                                const params : POSSL_PARAM; construct_data : Pointer):integer;
var
    data          : Pdecoder_pkey_data_st;
    decoder       : POSSL_DECODER;
    decoderctx    : Pointer;
    decoder_prov  : POSSL_PROVIDER;
    keymgmt       : PEVP_KEYMGMT;
    keymgmt_prov  : POSSL_PROVIDER;
    i,
    _end          : integer;
    object_ref    : Pointer;
    object_ref_sz : size_t;
    p             : POSSL_PARAM;
    object_type   : PUTF8Char;
    pkey          : PEVP_PKEY;
    keydata       : Pointer;
    import_data   : evp_keymgmt_util_try_import_data_st;
begin
    data := construct_data;
    decoder := OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);
    decoderctx := OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst);
    decoder_prov := OSSL_DECODER_get0_provider(decoder);
    keymgmt := nil;
     keymgmt_prov := nil;
    {
     * |object_ref| points to a provider reference to an object, its exact
     * contents entirely opaque to us, but may be passed to any provider
     * function that expects this (such as OSSL_FUNC_keymgmt_load().
     *
     * This pointer is considered volatile, i.e. whatever it points at
     * is assumed to be freed as soon as this function returns.
     }
    object_ref := nil;
    object_ref_sz := 0;
    p := OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    if p <> nil then
    begin
        object_type := nil;
        if 0>= OSSL_PARAM_get_utf8_string(p, @object_type, 0 ) then
            Exit(0);
        OPENSSL_free(data.object_type);
        data.object_type := object_type;
    end;
    {
     * For stuff that should end up in an EVP_PKEY, we only accept an object
     * reference for the moment.  This enforces that the key data itself
     * remains with the provider.
     }
    p := OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p = nil)  or  (p.data_type <> OSSL_PARAM_OCTET_STRING) then
       Exit(0);
    object_ref := p.data;
    object_ref_sz := p.data_size;
    {
     * First, we try to find a keymgmt that comes from the same provider as
     * the decoder that passed the params.
     }
    _end := sk_EVP_KEYMGMT_num(data.keymgmts);
    for i := 0 to _end-1 do
    begin
        keymgmt := sk_EVP_KEYMGMT_value(data.keymgmts, i);
        keymgmt_prov := EVP_KEYMGMT_get0_provider(keymgmt);
        if (keymgmt_prov = decoder_prov)
             and  (evp_keymgmt_has_load(keymgmt)>0) and  (EVP_KEYMGMT_is_a(keymgmt, data.object_type))  then
            break;
    end;
    if i < _end then
    begin
        { To allow it to be freed further down }
        if 0>= EVP_KEYMGMT_up_ref(keymgmt) then
            Exit(0);
    end
    else
    begin
       keymgmt := EVP_KEYMGMT_fetch(data.libctx,
                                            data.object_type,
                                            data.propq);
       if (keymgmt <> nil) then
           keymgmt_prov := EVP_KEYMGMT_get0_provider(keymgmt);
    end;
    if keymgmt <> nil then
    begin
        pkey := nil;
        keydata := nil;
        {
         * If the EVP_KEYMGMT and the OSSL_DECODER are from the
         * same provider, we assume that the KEYMGMT has a key loading
         * function that can handle the provider reference we hold.
         *
         * Otherwise, we export from the decoder and import the
         * result in the keymgmt.
         }
        if keymgmt_prov = decoder_prov then
        begin
            keydata := evp_keymgmt_load(keymgmt, object_ref, object_ref_sz);
        end
        else
        begin
            import_data.keymgmt := keymgmt;
            import_data.keydata := nil;
            import_data.selection := data.selection;
            {
             * No need to check for errors here, the value of
             * |import_data.keydata| is as much an indicator.
             }
            decoder.export_object(decoderctx,
                                         object_ref, object_ref_sz,
                                         @evp_keymgmt_util_try_import,
                                         @import_data);
            keydata := import_data.keydata;
            import_data.keydata := nil;
        end;
        pkey := evp_keymgmt_util_make_pkey(keymgmt, keydata);
        if (keydata <> nil) and  (pkey = nil) then
            evp_keymgmt_freedata(keymgmt, keydata);
        data._object^ := pkey;
        {
         * evp_keymgmt_util_make_pkey() increments the reference count when
         * assigning the EVP_PKEY, so we can free the keymgmt here.
         }
        EVP_KEYMGMT_free(keymgmt);
    end;
    {
     * We successfully looked through, |*ctx.object| determines if we
     * actually found something.
     }
    Result := int(data._object^ <> nil);
end;


procedure decoder_clean_pkey_construct_arg( construct_data : Pointer);
var
  data : Pdecoder_pkey_data_st;
begin
    data := construct_data;
    if data <> nil then
    begin
        sk_EVP_KEYMGMT_pop_free(data.keymgmts, EVP_KEYMGMT_free);
        OPENSSL_free(data.propq);
        OPENSSL_free(data.object_type);
        OPENSSL_free(data);
    end;
end;


procedure collect_name(const name : PUTF8Char; arg : Pointer);
var
  names : Pstack_st_OPENSSL_CSTRING;
begin
    names := arg;
    sk_OPENSSL_CSTRING_push(names, name);
end;


procedure collect_keymgmt( keymgmt : PEVP_KEYMGMT; arg : Pointer);
var
  keymgmts : Pstack_st_EVP_KEYMGMT;
begin
    keymgmts := arg;
    if 0>= EVP_KEYMGMT_up_ref(keymgmt) then { PostInc(ref) }
        Exit;
    if sk_EVP_KEYMGMT_push(keymgmts, keymgmt) <= 0  then
    begin
        EVP_KEYMGMT_free(keymgmt);   { PostDec(ref) }
        Exit;
    end;
end;


procedure collect_decoder( decoder : POSSL_DECODER; arg : Pointer);
var
    data       : Pcollect_decoder_data_st;
    i,
    end_i      : size_t;
    prov       : POSSL_PROVIDER;
    provctx    : Pointer;
    name       : PUTF8Char;
    decoderctx : Pointer;
    di         : POSSL_DECODER_INSTANCE;
    trc_out    : PBIO;
begin
    data := arg;
    prov := OSSL_DECODER_get0_provider(decoder);
    provctx := OSSL_PROVIDER_get0_provider_ctx(prov);
    if data.error_occurred > 0 then
       Exit;
    if data.names = nil then
    begin
        data.error_occurred := 1;
        exit;
    end;
    {
     * Either the caller didn't give a selection, or if they did,
     * the decoder must tell us if it supports that selection to
     * be accepted.  If the decoder doesn't have |does_selection|,
     * it's seen as taking anything.
     }
    if (Assigned(decoder.does_selection))
             and  (0>= decoder.does_selection(provctx, data.ctx.selection)) then
        exit;
    trc_out := Pointer(0);
    if Boolean(0) then
    begin
        BIO_printf(trc_out,
                   '(ctx %p) Checking out decoder %p:'#10'    %s with %s'#10,
                   [Pointer( data.ctx), Pointer( decoder),
                   OSSL_DECODER_get0_name(decoder),
                   OSSL_DECODER_get0_properties(decoder)]);
    end;

    end_i := sk_OPENSSL_CSTRING_num(data.names);
    for i := 0 to end_i-1 do
    begin
        name := sk_OPENSSL_CSTRING_value(data.names, i);
        if OSSL_DECODER_is_a(decoder, name) >0 then
        begin
            decoderctx := nil;
            di := nil;
            decoderctx := decoder.newctx(provctx);
            if decoderctx = nil then
            begin
                data.error_occurred := 1;
                exit;
            end;
            di := ossl_decoder_instance_new(decoder, decoderctx);
            if di =  nil then
            begin
                decoder.freectx(decoderctx);
                data.error_occurred := 1;
                exit;
            end;
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                        '(ctx %p) Checking out decoder %p:'#10+
                           '    %s with %s'#10,
                           [Pointer( data.ctx), Pointer( decoder),
                           OSSL_DECODER_get0_name(decoder),
                           OSSL_DECODER_get0_properties(decoder)]);
            end;
            //OSSL_TRACE_END(DECODER);
            if 0>= ossl_decoder_ctx_add_decoder_inst(data.ctx, di) then
            begin
                ossl_decoder_instance_free(di);
                data.error_occurred := 1;
                exit;
            end;
            Inc(data.total);
            { Success }
            Exit;
        end;
    end;
    { Decoder not suitable - but not a fatal error }
    data.error_occurred := 0;
end;


function ossl_decoder_ctx_setup_for_pkey(ctx : POSSL_DECODER_CTX; pkey : PPEVP_PKEY;const keytype : PUTF8Char; libctx : POSSL_LIB_CTX;const propquery : PUTF8Char):integer;
var
  process_data         : Pdecoder_pkey_data_st;
  names                : Pstack_st_OPENSSL_CSTRING;
  input_type,
  input_structure      : PUTF8Char;
  ok,
  isecoid,
  i,
  _end                 : integer;
  keymgmt              : PEVP_KEYMGMT;
  collect_decoder_data  : collect_decoder_data_st;
  trc_out: PBIO;
  label _err;
  function get_propq: PUTF8Char;
  begin
     OPENSSL_strdup(process_data.propq ,propquery);
     Result := process_data.propq;
  end;
begin
    process_data := nil;
    names := nil;
    input_type := ctx.start_input_type;
    input_structure := ctx.input_structure;
    ok := 0;
    isecoid := 0;
    if (keytype <> nil) and
       ( (strcmp(keytype, 'id-ecPublicKey') = 0)  or
       (strcmp(keytype, '1.2.840.10045.2.1') = 0) ) then
        isecoid := 1;
    if Boolean(0) then
    begin
        BIO_printf(trc_out,
                   '(ctx %p) Looking for decoders producing %s%s%s%s%s%s'#10,
                   [Pointer( ctx),
                   get_result(keytype <> nil , keytype , ''),
                   get_result(keytype <> nil , ' keys' , 'keys of any type'),
                   get_result(input_type <> nil , ' from ' , ''),
                   get_result(input_type <> nil , input_type , ''),
                   get_result(input_structure <> nil , ' with ' , ''),
                   get_result(input_structure <> nil , input_structure , '')]);
    end;
    //OSSL_TRACE_END(DECODER);
    process_data := OPENSSL_zalloc(sizeof(process_data^));
    process_data.keymgmts := sk_EVP_KEYMGMT_new_null();
    names := sk_OPENSSL_CSTRING_new_null();
    if (process_data = nil)
         or ( (propquery <> nil) and  (get_propq = nil) )
         or (process_data.keymgmts = nil)
         or (names = nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    process_data._object := PPointer( pkey);
    process_data.libctx := libctx;
    process_data.selection := ctx.selection;
    { First, find all keymgmts to form goals }
    EVP_KEYMGMT_do_all_provided(libctx, collect_keymgmt, process_data.keymgmts);
    { Then, we collect all the keymgmt names }
    _end := sk_EVP_KEYMGMT_num(process_data.keymgmts);
    for i := 0 to _end-1 do
    begin
        keymgmt := sk_EVP_KEYMGMT_value(process_data.keymgmts, i);
        {
         * If the key type is given by the caller, we only use the matching
         * KEYMGMTs, otherwise we use them all.
         * We have to special case SM2 here because of its abuse of the EC OID.
         * The EC OID can be used to identify an EC key or an SM2 key - so if
         * we have seen that OID we try both key types
         }
        if (keytype = nil) or
           (EVP_KEYMGMT_is_a(keymgmt, keytype))  or
           ( (isecoid > 0)  and  (EVP_KEYMGMT_is_a(keymgmt, 'SM2'))) then
        begin
            if 0>= EVP_KEYMGMT_names_do_all(keymgmt, collect_name, names) then
            begin
                ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
        end;
    end;
    if Boolean(0) then
    begin
        _end := sk_OPENSSL_CSTRING_num(names);
        BIO_printf(trc_out,
                   '    Found %d keytypes (possibly with duplicates)',
                   [_end]);
        for i := 0 to _end-1 do
            BIO_printf(trc_out, '%s%s',
                      [get_result(i = 0 , ': ' , ', '),
                       sk_OPENSSL_CSTRING_value(names, i)]);
        BIO_printf(trc_out, #10,[]);
    end;
    //OSSL_TRACE_END(DECODER);
    {
     * Finally, find all decoders that have any keymgmt of the collected
     * keymgmt names
     }
    begin
        collect_decoder_data := default(collect_decoder_data_st);
        collect_decoder_data.names := names;
        collect_decoder_data.ctx := ctx;
        OSSL_DECODER_do_all_provided(libctx, collect_decoder, @collect_decoder_data);
        sk_OPENSSL_CSTRING_free(names);
        names := nil;
        if collect_decoder_data.error_occurred > 0 then
           goto _err ;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) Got %d decoders producing keys\n',
                       [Pointer( ctx), collect_decoder_data.total]);
        end;
       // OSSL_TRACE_END(DECODER);
    end;
    if OSSL_DECODER_CTX_get_num_decoders(ctx) <> 0  then
    begin
        if (0 >= OSSL_DECODER_CTX_set_construct(ctx, decoder_construct_pkey))    or
           (0 >= OSSL_DECODER_CTX_set_construct_data(ctx, process_data))   or
           (0 >= OSSL_DECODER_CTX_set_cleanup(ctx, decoder_clean_pkey_construct_arg))  then
            goto _err ;
        process_data := nil; { Avoid it being freed }
    end;
    ok := 1;

 _err:
    decoder_clean_pkey_construct_arg(process_data);
    sk_OPENSSL_CSTRING_free(names);
    Result := ok;
end;


function OSSL_DECODER_CTX_new_for_pkey(pkey : PPEVP_PKEY;const input_type,
                                       input_structure, keytype : PUTF8Char;
                                       selection : integer; libctx : POSSL_LIB_CTX;
                                       const propquery : PUTF8Char):POSSL_DECODER_CTX;
var
  ctx : POSSL_DECODER_CTX;
  trc_out: PBIO;
begin
    ctx := nil;
    ctx := OSSL_DECODER_CTX_new();
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if Boolean(0) then
    begin
        BIO_printf(trc_out,
                   '(ctx %p) Looking for %s decoders with selection %d\n',
                   [Pointer( ctx), keytype, selection]);
        BIO_printf(trc_out, '    input type: %s, input structure: %s\n',
                   [input_type, input_structure]);
    end;
    //OSSL_TRACE_END(DECODER);
    if (OSSL_DECODER_CTX_set_input_type(ctx, input_type) > 0)
         and  (OSSL_DECODER_CTX_set_input_structure(ctx, input_structure)>0)
         and  (OSSL_DECODER_CTX_set_selection(ctx, selection)>0)
         and  (ossl_decoder_ctx_setup_for_pkey(ctx, pkey, keytype, libctx, propquery)>0)
         and  (OSSL_DECODER_CTX_add_extra(ctx, libctx, propquery)>0) then
    begin
        if Boolean(0) then
        begin
            BIO_printf(trc_out, '(ctx %p) Got %d decoders\n',
                       [Pointer( ctx), OSSL_DECODER_CTX_get_num_decoders(ctx)]);
        end;
       // OSSL_TRACE_END(DECODER);
        Exit(ctx);
    end;
    OSSL_DECODER_CTX_free(ctx);
    Result := nil;
end;


end.
