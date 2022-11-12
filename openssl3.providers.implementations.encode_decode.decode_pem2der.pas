unit openssl3.providers.implementations.encode_decode.decode_pem2der;

interface
uses OpenSSL.Api;

type
  pem2der_ctx_st = record
    provctx : PPROV_CTX;
  end;
  Ppem2der_ctx_st = ^pem2der_ctx_st;


  pem2der_pass_data_st = record
    cb : TOSSL_PASSPHRASE_CALLBACK;
    cbarg : Pointer;
  end;
  Ppem2der_pass_data_st = ^pem2der_pass_data_st;

function read_pem( provctx : PPROV_CTX; cin : POSSL_CORE_BIO; pem_name, pem_header : PPUTF8Char; data : PPByte; len : Plong):integer;
function pem2der_newctx( provctx : Pointer):Pointer;
procedure pem2der_freectx( vctx : Pointer);
function pem2der_pass_helper( buf : PUTF8Char; num, w : integer; data : Pointer):integer;
function pem2der_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;

const ossl_pem_to_der_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_DECODER_NEWCTX; method:(code:@pem2der_newctx; data:nil)),
    (function_id:  OSSL_FUNC_DECODER_FREECTX; method:(code:@pem2der_freectx; data:nil)),
    (function_id:  OSSL_FUNC_DECODER_DECODE; method:(code:@pem2der_decode; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) ));


implementation
uses  openssl3.crypto.bio.bio_prov, openssl3.crypto.pem.pem_lib,
      openssl3.crypto.params,
      openssl3.crypto.bio.bio_lib,  openssl3.crypto.mem;

type
pem_name_map_st = record
    pem_name       : PUTF8Char;
    object_type    : integer;
  data_type,
  data_structure : PUTF8Char;
end;

function get_pem_name_map_st(
  pem_name       : PUTF8Char;
  object_type    : integer;
  data_type,
  data_structure : PUTF8Char): pem_name_map_st;
begin
   Result.pem_name       := pem_name;
   Result.object_type    := object_type;
   Result.data_type      := data_type;
   Result.data_structure := data_structure;
end;

function read_pem( provctx : PPROV_CTX; cin : POSSL_CORE_BIO; pem_name, pem_header : PPUTF8Char; data : PPByte; len : Plong):integer;
var
  _in : PBIO;
  ok : integer;
begin
    _in := ossl_bio_new_from_core_bio(provctx, cin);
    if _in = nil then Exit(0);
    ok := int(PEM_read_bio(_in, pem_name, pem_header, data, len) > 0);
    BIO_free(_in);
    Result := ok;
end;


function pem2der_newctx( provctx : Pointer):Pointer;
var
  ctx : Ppem2der_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then ctx.provctx := provctx;
    Result := ctx;
end;


procedure pem2der_freectx( vctx : Pointer);
var
  ctx : Ppem2der_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(Pointer(ctx));
end;


function pem2der_pass_helper( buf : PUTF8Char; num, w : integer; data : Pointer):integer;
var
    pass_data : Ppem2der_pass_data_st;
    plen      : size_t;
begin
    pass_data := data;
    if (pass_data = nil)
         or  (not Assigned(pass_data.cb))
         or  (0>=pass_data.cb(buf, num, @plen, nil, pass_data.cbarg)) then
        Exit(-1);
    Result := int(plen);
end;


function pem2der_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer;
                         data_cb : POSSL_CALLBACK; data_cbarg : Pointer;
                         pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  pem_name_map   : array of pem_name_map_st;
  ctx            : Ppem2der_ctx_st;
  pem_name ,pem_header      : PUTF8Char;
  i              : size_t;
  der            : PByte;
  der_len        : long;
  ok,  objtype   : integer;
  cipher         : TEVP_CIPHER_INFO;
  pass_data      : pem2der_pass_data_st;
  params         : array[0..4] of TOSSL_PARAM;
  P: POSSL_PARAM;
  data_type,
  data_structure : PUTF8Char;
  label _end;
begin
    {
     * PEM names we recognise.  Other PEM names should be recognised by
     * other decoder implementations.
     }
   for i := 0 to 4 do
      params[i] := default(TOSSL_PARAM);

   pem_name_map := [
        { PKCS#8 and SubjectPublicKeyInfo }
        get_pem_name_map_st(  PEM_STRING_PKCS8, OSSL_OBJECT_PKEY, nil, 'EncryptedPrivateKeyInfo' ),
        get_pem_name_map_st(  PEM_STRING_PKCS8INF, OSSL_OBJECT_PKEY, nil, 'PrivateKeyInfo' ),
        get_pem_name_map_st(  PEM_STRING_PUBLIC, OSSL_OBJECT_PKEY, nil, 'SubjectPublicKeyInfo' ),
        { Our set of type specific PEM types }
        get_pem_name_map_st(  PEM_STRING_DHPARAMS, OSSL_OBJECT_PKEY, 'DH', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_DHXPARAMS, OSSL_OBJECT_PKEY, 'X9.42 DH', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_DSA, OSSL_OBJECT_PKEY, 'DSA', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_DSA_PUBLIC, OSSL_OBJECT_PKEY, 'DSA', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_DSAPARAMS, OSSL_OBJECT_PKEY, 'DSA', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_ECPRIVATEKEY, OSSL_OBJECT_PKEY, 'EC', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_ECPARAMETERS, OSSL_OBJECT_PKEY, 'EC', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_RSA, OSSL_OBJECT_PKEY, 'RSA', 'type-specific' ),
        get_pem_name_map_st(  PEM_STRING_RSA_PUBLIC, OSSL_OBJECT_PKEY, 'RSA', 'type-specific' ),
        {
         * A few others that there is at least have an object type for, even
         * though there is no provider interface to handle such objects, yet.
         * However, this is beneficial for the OSSL_STORE result handler.
         }
        get_pem_name_map_st(  PEM_STRING_X509, OSSL_OBJECT_CERT, nil, 'Certificate' ),
        get_pem_name_map_st(  PEM_STRING_X509_TRUSTED, OSSL_OBJECT_CERT, nil, 'Certificate' ),
        get_pem_name_map_st(  PEM_STRING_X509_OLD, OSSL_OBJECT_CERT, nil, 'Certificate' ),
        get_pem_name_map_st(  PEM_STRING_X509_CRL, OSSL_OBJECT_CRL, nil, 'CertificateList' )
    ];

    ctx := vctx;
    pem_name := nil; pem_header := nil;
    der := nil;
    der_len := 0;
    ok := 0;
    objtype := OSSL_OBJECT_UNKNOWN;
    ok := Int(read_pem(ctx.provctx, cin, @pem_name, @pem_header, @der, @der_len) > 0);
    { We return 'empty handed'.  This is not an error. }
    if 0>=ok then Exit(1);
    {
     * 10 is the number of UTF8Characters in 'Proc-Type:', which
     * PEM_get_EVP_CIPHER_INFO requires to be present.
     * If the PEM header has less characters than that, it's
     * not worth spending cycles on it.
     }
    if Length(pem_header) > 10  then
    begin
        ok := 0;                  { Assume that we fail }
        pass_data.cb := pw_cb;
        pass_data.cbarg := pw_cbarg;
        if (0>=PEM_get_EVP_CIPHER_INFO(pem_header, @cipher))  or
           (0>=PEM_do_header(@cipher, der, @der_len,
                              pem2der_pass_helper, @pass_data))  then
            goto _end;
    end;
    {
     * Indicated that we successfully decoded something, or not at all.
     * Ending up 'empty handed' is not an error.
     }
    ok := 1;
    { Have a look to see if we recognise anything }
    for i := 0 to Length(pem_name_map)-1 do
        if strcmp(pem_name, pem_name_map[i].pem_name) = 0  then
            break;
    if i < Length(pem_name_map) then
    begin
        p := @params[0];
        { We expect these to be read only so casting away the const is ok }
        data_type := PUTF8Char( pem_name_map[i].data_type);
        data_structure := PUTF8Char( pem_name_map[i].data_structure);
        objtype := pem_name_map[i].object_type;
        if data_type <> nil then
           PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 data_type, 0);
        { We expect this to be read only so casting away the const is ok }
        if data_structure <> nil then
           PostInc(p)^ :=  OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, data_structure, 0);

        PostInc(p)^ :=  OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, der_len);
        PostInc(p)^ :=  OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @objtype);
        p^ := OSSL_PARAM_construct_end;
        ok := data_cb(@params, data_cbarg);
    end;

 _end:
    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der);
    Result := ok;
end;

end.
