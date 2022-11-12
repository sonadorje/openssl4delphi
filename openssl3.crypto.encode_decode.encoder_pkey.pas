unit openssl3.crypto.encode_decode.encoder_pkey;

interface
uses OpenSSL.Api;

type
  collected_encoder_st = record
      names            : Pstack_st_OPENSSL_CSTRING;
      output_structure,
      output_type      : PUTF8Char;
      keymgmt_prov     : POSSL_PROVIDER;
      ctx              : POSSL_ENCODER_CTX;
      flag_find_same_provider: uint32;
      error_occurred   : integer;
  end;
  Pcollected_encoder_st = ^collected_encoder_st;


  collected_names_st = record
      names          : Pstack_st_OPENSSL_CSTRING;
      error_occurred : uint32;
  end;
  Pcollected_names_st = ^collected_names_st;

  construct_data_st = record
    pk              : PEVP_PKEY;
    selection       : integer;
    encoder_inst    : POSSL_ENCODER_INSTANCE;
    obj,constructed_obj : Pointer;
  end;
  Pconstruct_data_st = ^construct_data_st;

  function OSSL_ENCODER_CTX_set_cipher(ctx : POSSL_ENCODER_CTX;const cipher_name, propquery : PUTF8Char):integer;
  function OSSL_ENCODER_CTX_set_passphrase(ctx : POSSL_ENCODER_CTX;const kstr : PByte; klen : size_t):integer;
  function OSSL_ENCODER_CTX_set_passphrase_ui(ctx : POSSL_ENCODER_CTX;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
  function OSSL_ENCODER_CTX_set_pem_password_cb( ctx : POSSL_ENCODER_CTX; cb : Tpem_password_cb; cbarg : Pointer):integer;
  function OSSL_ENCODER_CTX_set_passphrase_cb( ctx : POSSL_ENCODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  procedure collect_encoder( encoder : POSSL_ENCODER; arg : Pointer);
  procedure collect_name(const name : PUTF8Char; arg : Pointer);
  function encoder_import_cb(const params : POSSL_PARAM; arg : Pointer):integer;
  function encoder_construct_pkey( encoder_inst : POSSL_ENCODER_INSTANCE; arg : Pointer):Pointer;
  procedure encoder_destruct_pkey( arg : Pointer);
  function ossl_encoder_ctx_setup_for_pkey(ctx : POSSL_ENCODER_CTX;const pkey : PEVP_PKEY; selection : integer;const propquery : PUTF8Char):integer;
  function OSSL_ENCODER_CTX_new_for_pkey(const pkey : PEVP_PKEY; selection : integer;const output_type, output_struct, propquery : PUTF8Char):POSSL_ENCODER_CTX;
  function OSSL_ENCODER_CTX_new:POSSL_ENCODER_CTX;
  function OSSL_DECODER_CTX_set_passphrase_cb( ctx : POSSL_DECODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


implementation
uses openssl3.crypto.params, openssl3.crypto.encode_decode.encoder_meth,
     openssl3.crypto.passphrase, openssl3.crypto.safestack,
     openssl3.crypto.encode_decode.encoder_lib,
     openssl3.crypto.bio.bio_print, openssl3.crypto.evp.evp_pkey,
     OpenSSL3.common, OpenSSL3.Err, openssl3.crypto.evp,
     openssl3.crypto.provider_core, openssl3.crypto.mem,
     openssl3.crypto.provider, openssl3.crypto.evp.keymgmt_meth;

function OSSL_DECODER_CTX_set_passphrase_cb( ctx : POSSL_DECODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    Result := ossl_pw_set_ossl_passphrase_cb(@ctx.pwdata, cb, cbarg);
end;

function OSSL_ENCODER_CTX_new:POSSL_ENCODER_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(Result^));
    if Result = nil then
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);

end;

function OSSL_ENCODER_CTX_set_cipher(ctx : POSSL_ENCODER_CTX;const cipher_name, propquery : PUTF8Char):integer;
var
  params :array of TOSSL_PARAM;
begin
    params := [ OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END ];
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_CIPHER, Pointer( cipher_name), 0);
    params[1] := OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, Pointer( propquery), 0);
    Result := OSSL_ENCODER_CTX_set_params(ctx, @params);
end;


function OSSL_ENCODER_CTX_set_passphrase(ctx : POSSL_ENCODER_CTX;const kstr : PByte; klen : size_t):integer;
begin
    Result := ossl_pw_set_passphrase(@ctx.pwdata, kstr, klen);
end;


function OSSL_ENCODER_CTX_set_passphrase_ui(ctx : POSSL_ENCODER_CTX;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
begin
    Result := ossl_pw_set_ui_method(@ctx.pwdata, ui_method, ui_data);
end;


function OSSL_ENCODER_CTX_set_pem_password_cb( ctx : POSSL_ENCODER_CTX; cb : Tpem_password_cb; cbarg : Pointer):integer;
begin
    Result := ossl_pw_set_pem_password_cb(@ctx.pwdata, cb, cbarg);
end;


function OSSL_ENCODER_CTX_set_passphrase_cb( ctx : POSSL_ENCODER_CTX; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    Result := ossl_pw_set_ossl_passphrase_cb(@ctx.pwdata, cb, cbarg);
end;


procedure collect_encoder( encoder : POSSL_ENCODER; arg : Pointer);
var
  data : Pcollected_encoder_st;
  i, end_i : size_t;
  name : PUTF8Char;
  prov : POSSL_PROVIDER;
  provctx : Pointer;
begin
    data := arg;
    if data.error_occurred > 0 then
      Exit;
    data.error_occurred := 1;     { Assume the worst }
    if data.names = nil then
       Exit;
    end_i := sk_OPENSSL_CSTRING_num(data.names);
    for i := 0 to end_i-1 do
    begin
         name := sk_OPENSSL_CSTRING_value(data.names, i);
         prov := OSSL_ENCODER_get0_provider(encoder);
         provctx := OSSL_PROVIDER_get0_provider_ctx(prov);
        {
         * collect_encoder() is called in two passes, one where the encoders
         * from the same provider as the keymgmt are looked up, and one where
         * the other encoders are looked up.  |data.flag_find_same_provider|
         * tells us which pass we're in.
         }
        if int(data.keymgmt_prov = prov) <> data.flag_find_same_provider then
            continue;
        if (0>= OSSL_ENCODER_is_a(encoder, name)) or
           ( (Assigned(encoder.does_selection)) and
             (0>= encoder.does_selection(provctx, data.ctx.selection)) )
             or ( (data.keymgmt_prov <> prov )
                 and  (not Assigned(encoder.import_object)) ) then
            continue;
        { Only add each encoder implementation once }
        if OSSL_ENCODER_CTX_add_encoder(data.ctx, encoder)>0 then
            break;
    end;
    data.error_occurred := 0;         { All is good now }
end;


procedure collect_name(const name : PUTF8Char; arg : Pointer);
var
  data : Pcollected_names_st;
begin
    data := arg;
    if data.error_occurred > 0 then
       Exit;
    data.error_occurred := 1;         { Assume the worst }
    if sk_OPENSSL_CSTRING_push(data.names, name) <= 0  then
       Exit;
    data.error_occurred := 0;         { All is good now }
end;


function encoder_import_cb(const params : POSSL_PARAM; arg : Pointer):integer;
var
    construct_data : Pconstruct_data_st;
    encoder_inst   : POSSL_ENCODER_INSTANCE;
    encoder        : POSSL_ENCODER;
    encoderctx     : Pointer;
begin
    construct_data := arg;
    encoder_inst := construct_data.encoder_inst;
    encoder := OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
    encoderctx := OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);
    construct_data.constructed_obj := encoder.import_object(encoderctx, construct_data.selection, params);
    Result := int(construct_data.constructed_obj <> nil);
end;


function encoder_construct_pkey( encoder_inst : POSSL_ENCODER_INSTANCE; arg : Pointer):Pointer;
var
  data : Pconstruct_data_st;
  encoder : POSSL_ENCODER;
  pk : PEVP_PKEY;
  k_prov, e_prov : POSSL_PROVIDER;
begin
    data := arg;
    if data.obj = nil then
    begin
        encoder := OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
         pk := data.pk;
         k_prov := EVP_KEYMGMT_get0_provider(pk.keymgmt);
         e_prov := OSSL_ENCODER_get0_provider(encoder);
        if k_prov <> e_prov then
        begin
            data.encoder_inst := encoder_inst;
            if 0>= evp_keymgmt_export(pk.keymgmt, pk.keydata, data.selection,
                                    @encoder_import_cb, data) then
                Exit(nil);
            data.obj := data.constructed_obj;
        end
        else
        begin
            data.obj := pk.keydata;
        end;
    end;
    Result := data.obj;
end;


procedure encoder_destruct_pkey( arg : Pointer);
var
  data : Pconstruct_data_st;
  encoder : POSSL_ENCODER;
begin
    data := arg;
    if data.encoder_inst <> nil then
    begin
        encoder := OSSL_ENCODER_INSTANCE_get_encoder(data.encoder_inst);
        encoder.free_object(data.constructed_obj);
    end;
    data.constructed_obj := nil;
end;


function ossl_encoder_ctx_setup_for_pkey(ctx : POSSL_ENCODER_CTX;const pkey : PEVP_PKEY; selection : integer;const propquery : PUTF8Char):integer;
var
    data         : Pconstruct_data_st;
    prov         : POSSL_PROVIDER;
    libctx       : POSSL_LIB_CTX;
    ok           : integer;
    encoder_data : collected_encoder_st;
    keymgmt_data : collected_names_st;
    label _err;
begin
    data := nil;
    prov := nil;
    libctx := nil;
    ok := 0;
    if (not ossl_assert(ctx <> nil))  or  (not ossl_assert(pkey <> nil)) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if evp_pkey_is_provided(pkey) then
    begin
        prov := EVP_KEYMGMT_get0_provider(pkey.keymgmt);
        libctx := ossl_provider_libctx(prov);
    end;
    if pkey.keymgmt <> nil then
    begin
        data := OPENSSL_zalloc(sizeof(data^));
        if (data = nil) then
        begin
            ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        {
         * Select the first encoder implementations in two steps.
         * First, collect the keymgmt names, then the encoders that match.
         }
        keymgmt_data.names := sk_OPENSSL_CSTRING_new_null();
        keymgmt_data.error_occurred := 0;
        EVP_KEYMGMT_names_do_all(pkey.keymgmt, collect_name, @keymgmt_data);
        if keymgmt_data.error_occurred>0 then
        begin
            sk_OPENSSL_CSTRING_free(keymgmt_data.names);
            goto _err ;
        end;
        encoder_data.names := keymgmt_data.names;
        encoder_data.output_type := ctx.output_type;
        encoder_data.output_structure := ctx.output_structure;
        encoder_data.error_occurred := 0;
        encoder_data.keymgmt_prov := prov;
        encoder_data.ctx := ctx;
        {
         * Place the encoders with the a different provider as the keymgmt
         * last (the chain is processed in reverse order)
         }
        encoder_data.flag_find_same_provider := 0;
        OSSL_ENCODER_do_all_provided(libctx, collect_encoder, @encoder_data);
        {
         * Place the encoders with the same provider as the keymgmt first
         * (the chain is processed in reverse order)
         }
        encoder_data.flag_find_same_provider := 1;
        OSSL_ENCODER_do_all_provided(libctx, collect_encoder, @encoder_data);
        sk_OPENSSL_CSTRING_free(keymgmt_data.names);
        if encoder_data.error_occurred>0 then
        begin
            ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    if (data <> nil)  and  (OSSL_ENCODER_CTX_get_num_encoders(ctx) <> 0) then
    begin
        if (0>= OSSL_ENCODER_CTX_set_construct(ctx, encoder_construct_pkey))
             or  (0>= OSSL_ENCODER_CTX_set_construct_data(ctx, data))
             or  (0>= OSSL_ENCODER_CTX_set_cleanup(ctx, encoder_destruct_pkey))then
            goto _err ;
        data.pk := pkey;
        data.selection := selection;
        data := nil;             { Avoid it being freed }
    end;
    ok := 1;

 _err:
    if data <> nil then
    begin
        OSSL_ENCODER_CTX_set_construct_data(ctx, nil);
        OPENSSL_free(data);
    end;
    Result := ok;
end;


function OSSL_ENCODER_CTX_new_for_pkey(const pkey : PEVP_PKEY; selection : integer;const output_type, output_struct, propquery : PUTF8Char):POSSL_ENCODER_CTX;
var
    ctx             : POSSL_ENCODER_CTX;
    libctx          : POSSL_LIB_CTX;
    prov            : POSSL_PROVIDER;
    params          : array of TOSSL_PARAM;
    save_parameters : integer;
    trc_out: PBIO;
begin
    ctx := nil;
    libctx := nil;
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if not evp_pkey_is_assigned(pkey) then
    begin
        ERR_raise_data(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT,
                       ' The passed EVP_PKEY must be assigned a key' );
        Exit(nil);
    end;
    ctx := OSSL_ENCODER_CTX_new();
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if evp_pkey_is_provided(pkey) then
    begin
        prov := EVP_KEYMGMT_get0_provider(pkey.keymgmt);
        libctx := ossl_provider_libctx(prov);
    end;
    if Boolean(0) then
    begin
        BIO_printf(trc_out,
                   ' (ctx %p) Looking for %s encoders with selection %d\n' ,
                   [Pointer( ctx), EVP_PKEY_get0_type_name(pkey), selection]);
        BIO_printf(trc_out, '     output type: %s, output structure: %s\n' ,
                   [output_type, output_struct]);
    end;

    if (OSSL_ENCODER_CTX_set_output_type(ctx, output_type) > 0)  and
       ( (output_struct = nil) or  (OSSL_ENCODER_CTX_set_output_structure(ctx, output_struct) >0 ) )
         and  (OSSL_ENCODER_CTX_set_selection(ctx, selection) > 0)
         and  (ossl_encoder_ctx_setup_for_pkey(ctx, pkey, selection, propquery) > 0)
         and  (OSSL_ENCODER_CTX_add_extra(ctx, libctx, propquery) > 0) then
    begin
        params := [OSSL_PARAM_END, OSSL_PARAM_END];

        save_parameters := pkey.save_parameters;
        params[0] := OSSL_PARAM_construct_int(OSSL_ENCODER_PARAM_SAVE_PARAMETERS,
                                             @save_parameters);
        { ignoring error as this is only auxiliary parameter }
        OSSL_ENCODER_CTX_set_params(ctx, @params[0]);
        if Boolean(0) then
        begin
            BIO_printf(trc_out, ' (ctx %p) Got %d encoders\n' ,
                       [Pointer( ctx), OSSL_ENCODER_CTX_get_num_encoders(ctx)]);
        end;

        Exit(ctx);
    end;
    OSSL_ENCODER_CTX_free(ctx);
    Result := nil;
end;


end.
