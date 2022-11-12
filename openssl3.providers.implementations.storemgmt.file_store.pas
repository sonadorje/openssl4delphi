unit openssl3.providers.implementations.storemgmt.file_store;

interface
uses OpenSSL.Api, SysUtils,
     {$IFDEF  MSWINDOWS} libc.win {$ENDIF}, Character;

type

  file_load_data_st = record
      object_cb    : POSSL_CALLBACK;
      object_cbarg : Pointer;
  end;
  Pfile_load_data_st = ^file_load_data_st;

  Tpath_data = record
      path           : PUTF8Char;
      check_absolute : uint32;
  end;

  type_st = (
    IS_FILE = 0,
    IS_DIR = 1);


  file_st = record
    &file: PBIO;
    decoderctx: POSSL_DECODER_CTX;
    input_type: PUTF8Char;
    propq: PUTF8Char;
  end;


  dir_st = record
    ctx: POPENSSL_DIR_CTX;
    end_reached: Integer;
    search_name: array [0..8] of UTF8Char;
    last_entry: PUTF8Char;
    last_errno: Integer;
  end;


  file_ctx_st = record
      provctx: Pointer;
      uri: PUTF8Char;
      &type: type_st;
      _: record
      case Integer of
        0: (&file: file_st);
        1: (dir: dir_st);
      end;
      expected_type: Integer;
  end;
  Pfile_ctx_st = ^file_ctx_st;

 function file_open(provctx : Pointer;const uri : PUTF8Char):Pointer;
 function file_attach( provctx : Pointer; cin : POSSL_CORE_BIO):Pointer;
  function file_settable_ctx_params( provctx : Pointer):POSSL_PARAM;
 function file_set_ctx_params(loaderctx : Pointer;const params : POSSL_PARAM):integer;
  function file_load( loaderctx : Pointer; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
 function file_eof( loaderctx : Pointer):integer;
function file_close( loaderctx : Pointer):integer;
function file_load_file( ctx : Pfile_ctx_st; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;


const ossl_file_store_functions: array[0..7] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_STORE_OPEN; method:(code:@file_open; data:nil)),
    (function_id:  OSSL_FUNC_STORE_ATTACH; method:(code:@file_attach; data:nil)),
    (function_id:  OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS; method:(code:@file_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_STORE_SET_CTX_PARAMS; method:(code:@file_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_STORE_LOAD; method:(code:@file_load; data:nil)),
    (function_id:  OSSL_FUNC_STORE_EOF; method:(code:@file_eof; data:nil)),
    (function_id:  OSSL_FUNC_STORE_CLOSE; method:(code:@file_close; data:nil)),
    (function_id:  0; method:(code:nil; data:nil)));

function file_close_dir( ctx : Pfile_ctx_st):integer;
procedure free_file_ctx( ctx : Pfile_ctx_st);
function file_close_stream( ctx : Pfile_ctx_st):integer;
function file_setup_decoders( ctx : Pfile_ctx_st):integer;
function file_load_construct(decoder_inst : POSSL_DECODER_INSTANCE;const params : POSSL_PARAM; construct_data : Pointer):integer;
procedure file_load_cleanup( construct_data : Pointer);
function file_load_dir_entry( ctx : Pfile_ctx_st; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
function file_name_check(ctx : Pfile_ctx_st;const name : PUTF8Char):integer;
function file_name_to_uri(ctx : Pfile_ctx_st;const name : PUTF8Char):PUTF8Char;
 function file_open_stream(source : PBIO;const uri : PUTF8Char; provctx : Pointer):Pfile_ctx_st;
function new_file_ctx(_type : integer;const uri : PUTF8Char; provctx : Pointer):Pfile_ctx_st;
function file_open_dir(const path, uri : PUTF8Char; provctx : Pointer):Pointer;


var
  known_settable_ctx_params : array of TOSSL_PARAM;

implementation
uses openssl3.providers.fips.fipsprov, directory_win, openssl3.crypto.mem,
     openssl3.crypto.bio.bio_lib,      OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.Err,                     openssl3.crypto.encode_decode.decoder_lib,
     OpenSSL3.openssl.params,          OpenSSL3.common,
     openssl3.crypto.o_str,            openssl3.crypto.params,
     OpenSSL3.crypto.x509.x_name,      openssl3.crypto.bio.bio_print,
     OpenSSL3.crypto.x509.x509_cmp,    openssl3.crypto.bio.bio_prov,
     openssl3.crypto.conf.conf_def,    openssl3.crypto.bio.bss_file,
     openssl3.crypto.encode_decode.encoder_pkey,
     openssl3.providers.implementations.storemgmt.file_store_any2obj,
     openssl3.crypto.encode_decode.decoder_meth;




function file_open_dir(const path, uri : PUTF8Char; provctx : Pointer):Pointer;
var
  ctx : Pfile_ctx_st;
  label _err;
begin
    ctx := new_file_ctx(Int(IS_DIR), uri, provctx);
    if ctx = nil then  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx._.dir.last_entry := OPENSSL_DIR_read(@ctx._.dir.ctx, path);
    ctx._.dir.last_errno := _errno;
    if ctx._.dir.last_entry = nil then
    begin
        if ctx._.dir.last_errno <> 0 then  begin
            ERR_raise_data(ERR_LIB_SYS, ctx._.dir.last_errno,
                          Format('Calling OPENSSL_DIR_read(''%s'')', [path]));
            goto _err;
        end;
        ctx._.dir.end_reached := 1;
    end;
    Exit(ctx);
 _err:
    file_close(ctx);
    Result := nil;
end;



function new_file_ctx(_type : integer;const uri : PUTF8Char; provctx : Pointer):Pfile_ctx_st;
var
  ctx : Pfile_ctx_st;
begin
    ctx := nil;
    ctx := OPENSSL_zalloc(sizeof(ctx^));
    OPENSSL_strdup(ctx.uri ,uri);
    if (ctx  <> nil) and ( (uri = nil)  or  (ctx.uri <> nil)) then
    begin
        ctx.&type := type_st(_type);
        ctx.provctx := provctx;
        Exit(ctx);
    end;
    free_file_ctx(ctx);
    Result := nil;
end;

function file_open_stream(source : PBIO;const uri : PUTF8Char; provctx : Pointer):Pfile_ctx_st;
var
  ctx : Pfile_ctx_st;
  label _err;
begin
    ctx := new_file_ctx(Int(IS_FILE), uri, provctx);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ctx._.&file.&file := source;
    Exit(ctx);
 _err:
    free_file_ctx(ctx);
    Result := nil;
end;




function file_name_to_uri(ctx : Pfile_ctx_st;const name : PUTF8Char):PUTF8Char;
var
  data,
  pathsep           : PUTF8Char;
  calculated_length : long;
begin
    data := nil;
    assert(name <> nil);
    begin
         pathsep := get_result(ossl_ends_with_dirsep(ctx.uri)>0 , '' , '/');
        calculated_length := Length(ctx.uri) + Length(pathsep) + Length(name) + 1 { \0 } ;
        data := OPENSSL_zalloc(calculated_length);
        if data = nil then begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        OPENSSL_strlcat(data, ctx.uri, calculated_length);
        OPENSSL_strlcat(data, pathsep, calculated_length);
        OPENSSL_strlcat(data, name, calculated_length);
    end;
    Result := data;
end;

function file_name_check(ctx : Pfile_ctx_st;const name : PUTF8Char):integer;
var
  p : PUTF8Char;
  len : size_t;
begin
    p := nil;
    len := Length(ctx._.dir.search_name);
    { If there are no search criteria, all names are accepted }
    if ctx._.dir.search_name[0] = #0 then Exit(1);
    { If the expected type isn't supported, no name is accepted }
    if (ctx.expected_type <> 0)
         and  (ctx.expected_type <> OSSL_STORE_INFO_CERT)
         and  (ctx.expected_type <> OSSL_STORE_INFO_CRL) then
         Exit(0);
    {
     * First, check the basename
     }
    if (strncasecmp(name, ctx._.dir.search_name, len) <> 0)  or  (name[len] <> '.') then
        Exit(0);
    p := @name[len + 1];
    {
     * Then, if the expected type is a CRL, check that the extension starts
     * with 'r'
     }
    if p^ = 'r' then
    begin
        Inc(p);
        if (ctx.expected_type <> 0)
             and  (ctx.expected_type <> OSSL_STORE_INFO_CRL) then
             Exit(0);
    end
    else if (ctx.expected_type = OSSL_STORE_INFO_CRL) then
    begin
        Exit(0);
    end;
    {
     * Last, check that the rest of the extension is a decimal number, at
     * least one digit long.
     }
    if not is_digit(p^) then
        Exit(0);
    while is_digit( p^) do
        Inc(p);
{$IFDEF __VMS}
    {
     * One extra step here, check for a possible generation number.
     }
    if *p = ';' then for (PostInc(p); *p <> #0; PostInc(p))
            if 0>=ossl_isdigit( *p then )
                break;
{$ENDIF}
    {
     * If we've reached the end of the string at this point, we've successfully
     * found a fitting file name.
     }
    Result := Int(p^ = #0);
end;


function file_load_dir_entry( ctx : Pfile_ctx_st; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
    object_type : integer;
    _object     : array of TOSSL_PARAM;
    newname     : PUTF8Char;
    ok          : integer;
begin
    { Prepare as much as possible in advance }
    object_type := OSSL_OBJECT_NAME;
    _object := [
        _OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, PInteger(@object_type)),
        _OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA, nil, 0),
        OSSL_PARAM_END
    ];

    newname := nil;
    { Loop until we get an error or until we have a suitable name }
    repeat
        if ctx._.dir.last_entry = nil then begin
            if 0>=ctx._.dir.end_reached then  begin
                assert(ctx._.dir.last_errno <> 0);
                ERR_raise(ERR_LIB_SYS, ctx._.dir.last_errno);
            end;
            { file_eof will tell if EOF was reached }
            Exit(0);
        end;
        { flag acceptable names }
        if (ctx._.dir.last_entry[0] <> '.')
             and  (file_name_check(ctx, ctx._.dir.last_entry) > 0) then
        begin
            { If we can't allocate the new name, we fail }
            newname := file_name_to_uri(ctx, ctx._.dir.last_entry) ;
            if newname = nil then
                Exit(0);
        end;
        {
         * On the first call (with a nil context), OPENSSL_DIR_read
         * cares about the second argument.  On the following calls, it
         * only cares that it isn't nil.  Therefore, we can safely give
         * it our URI here.
         }
        ctx._.dir.last_entry := OPENSSL_DIR_read(@ctx._.dir.ctx, ctx.uri);
        ctx._.dir.last_errno := _errno;
        if (ctx._.dir.last_entry = nil)  and  (ctx._.dir.last_errno = 0) then
           ctx._.dir.end_reached := 1;
    until not (newname = nil);

    _object[1].data := newname;
    _object[1].data_size := Length(newname);
    ok := object_cb(@_object, object_cbarg);
    OPENSSL_free(newname);
    Result := ok;
end;

procedure file_load_cleanup( construct_data : Pointer);
begin
    { Nothing to do }
end;


function file_load_construct(decoder_inst : POSSL_DECODER_INSTANCE;const params : POSSL_PARAM; construct_data : Pointer):integer;
var
  data : Pfile_load_data_st;
begin
    data := construct_data;
    {
     * At some point, we may find it justifiable to recognise PKCS#12 and
     * handle it specially here, making |file_load| return pass its
     * contents one piece at ta time, like |e_loader_attic.c| does.
     *
     * However, that currently means parsing them out, which converts the
     * DER encoded PKCS#12 into a bunch of EVP_PKEYs and X509s, just to
     * have to re-encode them into DER to create an object abstraction for
     * each of them.
     * It's much simpler (less churn) to pass on the object abstraction we
     * get to the load_result callback and leave it to that one to do the
     * work.  If that's libcrypto code, we know that it has much better
     * possibilities to handle the EVP_PKEYs and X509s without the extra
     * churn.
     }
    Result := data.object_cb(params, data.object_cbarg);
end;



function file_setup_decoders( ctx : Pfile_ctx_st):integer;
var
    libctx      : POSSL_LIB_CTX;
    to_algo     : POSSL_ALGORITHM;
    ok          : integer;
    to_obj      : POSSL_DECODER;
    to_obj_inst : POSSL_DECODER_INSTANCE;
    label _err;
begin
    libctx := ossl_prov_ctx_get0_libctx(ctx.provctx);
    to_algo := nil;
    ok := 0;
    { Setup for this session, so only if not already done }
    if ctx._.&file.decoderctx = nil then
    begin
        ctx._.&file.decoderctx := OSSL_DECODER_CTX_new();
        if (ctx._.&file.decoderctx = nil) then  begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        { Make sure the input type is set }
        if 0>=OSSL_DECODER_CTX_set_input_type(ctx._.&file.decoderctx,
                                             ctx._.&file.input_type) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto _err;
        end;
        {
         * Where applicable, set the outermost structure name.
         * The goal is to avoid the STORE object types that are
         * potentially password protected but aren't interesting
         * for this load.
         }
        case ctx.expected_type of
        OSSL_STORE_INFO_CERT:
        begin
            if 0>=OSSL_DECODER_CTX_set_input_structure(ctx._.&file.decoderctx,
                                                      'Certificate') then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto _err;
            end;
        end;
        OSSL_STORE_INFO_CRL:
        begin
            if 0>=OSSL_DECODER_CTX_set_input_structure(ctx._.&file.decoderctx,
                                                      'CertificateList') then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto _err;
            end;
        end;
        else
            begin
               //break;
            end;
        end;
        to_algo := @ossl_any_to_obj_algorithm;
        while to_algo.algorithm_names <> nil do
        begin
            to_obj := nil;
            to_obj_inst := nil;
            {
             * Create the internal last resort decoder implementation
             * together with a 'decoder instance'.
             * The decoder doesn't need any identification or to be
             * attached to any provider, since it's only used locally.
             }
            to_obj := ossl_decoder_from_algorithm(0, to_algo, nil);
            if to_obj <> nil then
               to_obj_inst := ossl_decoder_instance_new(to_obj, ctx.provctx);
            OSSL_DECODER_free(to_obj);
            if to_obj_inst = nil then goto _err;
            if 0>=ossl_decoder_ctx_add_decoder_inst(ctx._.&file.decoderctx,
                                                   to_obj_inst) then
            begin
                ossl_decoder_instance_free(to_obj_inst);
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto _err;
            end;
            Inc(to_algo);
        end;
        { Add on the usual extra decoders }
        if 0>=OSSL_DECODER_CTX_add_extra(ctx._.&file.decoderctx,
                                        libctx, ctx._.&file.propq) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto _err;
        end;
        {
         * Then install our constructor hooks, which just passes decoded
         * data to the load callback
         }
        if (0>=OSSL_DECODER_CTX_set_construct(ctx._.&file.decoderctx, file_load_construct))  or
           (0>=OSSL_DECODER_CTX_set_cleanup(ctx._.&file.decoderctx, file_load_cleanup)) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto _err;
        end;
    end;
    ok := 1;
 _err:
    Result := ok;
end;




function file_load_file( ctx : Pfile_ctx_st; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  data : file_load_data_st;
  ret, err : integer;
begin
    { Setup the decoders (one time shot per session }
    if 0>=file_setup_decoders(ctx) then
        Exit(0);
    { Setup for this object }
    data.object_cb := object_cb;
    data.object_cbarg := object_cbarg;
    OSSL_DECODER_CTX_set_construct_data(ctx._.&file.decoderctx, @data);
    OSSL_DECODER_CTX_set_passphrase_cb(ctx._.&file.decoderctx, pw_cb, pw_cbarg);
    { Launch }
    ERR_set_mark;
    ret := OSSL_DECODER_from_bio(ctx._.&file.decoderctx, ctx._.&file.&file);
    err := ERR_peek_last_error;
    if (BIO_eof(ctx._.&file.&file) > 0)  and  (err  <> 0)
         and  (ERR_GET_LIB(err) = ERR_LIB_OSSL_DECODER)
         and  (ERR_GET_REASON(err) = ERR_R_UNSUPPORTED)  then
        ERR_pop_to_mark
    else
        ERR_clear_last_mark;
    Result := ret;
end;



function file_close_stream( ctx : Pfile_ctx_st):integer;
begin
    {
     * This frees either the provider BIO filter (for file_attach) OR
     * the allocated file BIO (for file_open).
     }
    BIO_free(ctx._.&file.&file);
    ctx._.&file.&file := nil;
    free_file_ctx(ctx);
    Result := 1;
end;




procedure free_file_ctx( ctx : Pfile_ctx_st);
begin
    if ctx = nil then exit;
    OPENSSL_free(ctx.uri);
    if ctx.&type <> IS_DIR then begin
        OSSL_DECODER_CTX_free(ctx._.&file.decoderctx);
        OPENSSL_free(ctx._.&file.propq);
        OPENSSL_free(ctx._.&file.input_type);
    end;
    OPENSSL_free(ctx);
end;

function file_close_dir( ctx : Pfile_ctx_st):integer;
begin
    if ctx._.dir.ctx <> nil then
       OPENSSL_DIR_end(@ctx._.dir.ctx);
    free_file_ctx(ctx);
    Result := 1;
end;


function file_close( loaderctx : Pointer):integer;
var
  ctx : Pfile_ctx_st;
begin
    ctx := loaderctx;
    case ctx.&type of
    IS_DIR:
        Exit(file_close_dir(ctx));
    IS_FILE:
        Exit(file_close_stream(ctx));
    end;
    { ctx.type has an unexpected value }
    assert(Boolean(0));
    Result := 1;
end;



function file_eof( loaderctx : Pointer):integer;
var
  ctx : Pfile_ctx_st;
begin
    ctx := loaderctx;
    case ctx.&type of
    IS_DIR:
        Exit(ctx._.dir.end_reached);
    IS_FILE:
        {
         * BIO_pending checks any filter BIO.
         * BIO_eof checks the source BIO.
         }
        Exit(Int( (0>= BIO_pending(ctx._.&file.&file))  and
                  (BIO_eof(ctx._.&file.&file) > 0)) );
    end;
    { ctx.type has an unexpected value }
    assert(Boolean(0));
    Result := 1;
end;



function file_load( loaderctx : Pointer; object_cb : POSSL_CALLBACK; object_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx : Pfile_ctx_st;
begin
    ctx := loaderctx;
    case ctx.&type of
    IS_FILE:
        Exit(file_load_file(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg));
    IS_DIR:
        Exit(file_load_dir_entry(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg));
    else
        begin
          //break;
        end;
    end;
    { ctx.type has an unexpected value }
    assert(Boolean(0));
    Result := 0;
end;



function file_set_ctx_params(loaderctx : Pointer;const params : POSSL_PARAM):integer;
var
    ctx       : Pfile_ctx_st;
    p         : POSSL_PARAM;
    der       : PByte;
    der_len   : size_t;
    x509_name : PX509_NAME;
    hash      : Cardinal;
    ok        : integer;
begin
    ctx := loaderctx;
    if params = nil then Exit(1);
    if ctx.&type <> IS_DIR then
    begin
        { these parameters are ignored for directories }
        p := OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
        if p <> nil then begin
            OPENSSL_free(ctx._.&file.propq);
            ctx._.&file.propq := nil;
            if 0>=OSSL_PARAM_get_utf8_string(p, @ctx._.&file.propq, 0) then
                Exit(0);
        end;
        p := OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_INPUT_TYPE);
        if p <> nil then begin
            OPENSSL_free(ctx._.&file.input_type);
            ctx._.&file.input_type := nil;
            if 0>=OSSL_PARAM_get_utf8_string(p, @ctx._.&file.input_type, 0) then
                Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p <> nil)  and  (0>=OSSL_PARAM_get_int(p, @ctx.expected_type)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
    if p <> nil then
    begin
        der := nil;
        der_len := 0;
        if ctx.&type <> IS_DIR then begin
            ERR_raise(ERR_LIB_PROV,
                      PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES);
            Exit(0);
        end;
        x509_name := d2i_X509_NAME(nil, @der, der_len);
        if (0>=OSSL_PARAM_get_octet_string_ptr(p, PPointer(@der), @der_len))
             or  (x509_name = nil) then
            Exit(0);
        hash := X509_NAME_hash_ex(x509_name,
                                 ossl_prov_ctx_get0_libctx(ctx.provctx), nil,
                                 @ok);
        BIO_snprintf(ctx._.dir.search_name, sizeof(ctx._.dir.search_name),
                     '%08lx', [hash]);
        X509_NAME_free(x509_name);
        if ok = 0 then Exit(0);
    end;
    Result := 1;
end;

function file_settable_ctx_params( provctx : Pointer):POSSL_PARAM;
begin
   Result := @known_settable_ctx_params[0];
end;




function file_attach( provctx : Pointer; cin : POSSL_CORE_BIO):Pointer;
var
  ctx : Pfile_ctx_st;
  new_bio : PBIO;
begin
    new_bio := ossl_bio_new_from_core_bio(provctx, cin);
    if new_bio = nil then Exit(nil);
    ctx := file_open_stream(new_bio, nil, provctx);
    if ctx = nil then BIO_free(new_bio);
    Result := ctx;
end;

function file_open(provctx : Pointer;const uri : PUTF8Char):Pointer;
var
    ctx         : Pfile_ctx_st;
    st          : Tstat;
    path_data_n, i : size_t;
    path,
    p, q           : PUTF8Char;
    bio         : PBIO;
    c           : byte;
    path_data: array[0..1] of Tpath_data;
begin
    ctx := nil;
    path_data_n := 0;
    p := uri;
    ERR_set_mark;
    {
     * First step, just take the URI as is.
     }
    path_data[path_data_n].check_absolute := 0;
    path_data[PostInc(path_data_n)].path := uri;
    {
     * Second step, if the URI appears to start with the 'file' scheme,
     * extract the path and make that the second path to check.
     * There's a special case if the URI also contains an authority, then
     * the full URI shouldn't be used as a path anywhere.
     }
    if CHECK_AND_SKIP_CASE_PREFIX(p, 'file:') > 0 then
    begin
        q := p;
        if CHECK_AND_SKIP_CASE_PREFIX(q, '//') > 0 then
        begin
            Dec(path_data_n);           { Invalidate using the full URI }
            if (CHECK_AND_SKIP_CASE_PREFIX(q, 'localhost/') > 0)  or
               (CHECK_AND_SKIP_CASE_PREFIX(q, '/') > 0 )  then
            begin
                p := q - 1;
            end
            else
            begin
                ERR_clear_last_mark;
                ERR_raise(ERR_LIB_PROV, PROV_R_URI_AUTHORITY_UNSUPPORTED);
                Exit(nil);
            end;
        end;
        path_data[path_data_n].check_absolute := 1;
{$IFDEF _WIN32}
        { Windows 'file:' URIs with a drive letter start with a '/' }
        if p[0] = '/'  and  p[2] = ':'  and  p[3] = '/' then begin
            c := tolower(p[1]);
            if c >= 'a'  and  c <= 'z' then begin
                PostInc(p);
                { We know it's absolute, so no need to check }
                path_data[path_data_n].check_absolute := 0;
            end;
        end;
{$ENDIF}
        path_data[PostInc(path_data_n)].path := p;
    end;
    i := 0; path := nil;
    while (path = nil)  and  (i < path_data_n) do
    begin
        {
         * If the scheme 'file' was an explicit part of the URI, the path must
         * be absolute.  So says RFC 8089
         }
        if (path_data[i].check_absolute > 0)  and  (path_data[i].path[0] <> '/') then
        begin
            ERR_clear_last_mark;
            ERR_raise_data(ERR_LIB_PROV, PROV_R_PATH_MUST_BE_ABSOLUTE,
                          Format ('Given path=%s', [path_data[i].path]));
            Exit(nil);
        end;
        if stat(PAnsiChar(path_data[i].path), @st) < 0  then
        begin
            ERR_raise_data(ERR_LIB_SYS, _errno,
                         Format('calling stat(%s)',
                           [path_data[i].path]));
        end
        else
            path := path_data[i].path;

        Inc(i);
    end;
    if path = nil then begin
        ERR_clear_last_mark;
        Exit(nil);
    end;
    { Successfully found a working path, clear possible collected errors }
    ERR_pop_to_mark;
    if S_ISDIR(st.st_mode) then
        ctx := file_open_dir(path, uri, provctx)
    else
    begin
       bio := BIO_new_file(path, 'rb');
       ctx := file_open_stream(bio, uri, provctx);
       if (bio = nil) or  (ctx = nil) then
          BIO_free_all(bio);
    end;
    Result := ctx;
end;

initialization
   known_settable_ctx_params := [
    _OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, nil, 0),
    _OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, nil),
    _OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, nil, 0),
    OSSL_PARAM_END ];
end.
