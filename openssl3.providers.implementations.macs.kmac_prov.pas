unit openssl3.providers.implementations.macs.kmac_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

const
  KMAC_MAX_OUTPUT_LEN = ($FFFFFF div 8);

  procedure kmac_free( vmacctx : Pointer);
  function kmac_new( provctx : Pointer):Pkmac_data_st;
  function kmac_fetch_new(provctx : Pointer;const params : POSSL_PARAM):Pointer;
  function kmac128_new( provctx : Pointer):Pointer;
  function kmac256_new( provctx : Pointer):Pointer;
  function kmac_dup( vsrc : Pointer):Pointer;
  function kmac_setkey(kctx : Pkmac_data_st;const key : PByte; keylen : size_t):integer;
  function kmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function kmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function kmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function kmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function kmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
  function kmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function kmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
  function get_encode_size(var bits : size_t):uint32;
  function right_encode( &out : PByte; out_max_len : size_t; out_len : Psize_t;var bits : size_t):integer;
  function encode_string(_out : PByte; out_max_len : size_t; out_len : Psize_t;const _in : PByte; in_len : size_t):integer;
  function bytepad(_out : PByte; out_len : Psize_t;const in1 : PByte; in1_len : size_t;const in2 : PByte; in2_len, w : size_t):integer;
  function kmac_bytepad_encode_key(_out : PByte; out_max_len : size_t; out_len : Psize_t;const _in : PByte; in_len, w : size_t):integer;

   const  ossl_kmac256_functions: array[0..10] of TOSSL_DISPATCH = (
  (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@kmac256_new; data:nil)),
  (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@kmac_dup; data:nil)),
  (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@kmac_free; data:nil)),
  (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@kmac_init; data:nil)),
  (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@kmac_update; data:nil)),
  (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@kmac_final; data:nil)),
  (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
    method:(code:@kmac_gettable_ctx_params; data:nil)),
  (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@kmac_get_ctx_params; data:nil)),
  (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
    method:(code:@kmac_settable_ctx_params; data:nil)),
  (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@kmac_set_ctx_params; data:nil)),
  (function_id:  0; method:(code:nil; data:nil) )
);
  const  ossl_kmac128_functions: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@kmac128_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@kmac_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@kmac_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@kmac_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@kmac_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@kmac_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
      method:(code:@kmac_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@kmac_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@kmac_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@kmac_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     openssl3.crypto.evp.digest,  openssl3.crypto.evp,
     OpenSSL.ssl.s3_cbc, openssl3.crypto.hmac.hmac, OpenSSL3.common,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;

const // 1d arrays
  kmac_string : array[0..5] of Byte = (
    $01, $20, $4B, $4D, $41, $43 );

var
  known_gettable_ctx_params: array[0..2] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..6] of TOSSL_PARAM ;


var // 1d arrays

  kmac128_params,
  kmac256_params : array[0..1] of TOSSL_PARAM;

function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;

procedure kmac_free( vmacctx : Pointer);
var
  kctx : Pkmac_data_st;
begin
    kctx := vmacctx;
    if kctx <> nil then
    begin
        EVP_MD_CTX_free(kctx.ctx);
        ossl_prov_digest_reset(@kctx.digest);
        OPENSSL_cleanse(@kctx.key, kctx.key_len);
        OPENSSL_cleanse(@kctx.custom, kctx.custom_len);
        OPENSSL_free(Pointer(kctx));
    end;
end;


function kmac_new( provctx : Pointer):Pkmac_data_st;
var
  kctx : Pkmac_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    kctx := OPENSSL_zalloc(sizeof( kctx^)) ;
    kctx.ctx := EVP_MD_CTX_new();
    if (kctx = nil) or  (kctx.ctx = nil) then
    begin
        kmac_free(kctx);
        Exit(nil);
    end;
    kctx.provctx := provctx;
    Result := kctx;
end;


function kmac_fetch_new(provctx : Pointer;const params : POSSL_PARAM):Pointer;
var
  kctx : Pkmac_data_st;
begin
    kctx := kmac_new(provctx);
    if kctx = nil then Exit(0);
    if 0>= ossl_prov_digest_load_from_params(@kctx.digest, params,
                                      PROV_LIBCTX_OF(provctx))  then
    begin
        kmac_free(kctx);
        Exit(0);
    end;
    kctx.out_len := EVP_MD_get_size(ossl_prov_digest_md(@kctx.digest));
    Result := kctx;
end;


function kmac128_new( provctx : Pointer):Pointer;
begin
    Result := kmac_fetch_new(provctx, @kmac128_params);
end;


function kmac256_new( provctx : Pointer):Pointer;
begin
   Result := kmac_fetch_new(provctx, @kmac256_params);
end;


function kmac_dup( vsrc : Pointer):Pointer;
var
  src, dst : Pkmac_data_st;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := kmac_new(src.provctx);
    if dst = nil then Exit(nil);
    if (0>= EVP_MD_CTX_copy(dst.ctx, src.ctx))  or
       (0>= ossl_prov_digest_copy(@dst.digest, @src.digest))  then
    begin
        kmac_free(dst);
        Exit(nil);
    end;
    dst.out_len := src.out_len;
    dst.key_len := src.key_len;
    dst.custom_len := src.custom_len;
    dst.xof_mode := src.xof_mode;
    memcpy(@dst.key, @src.key, src.key_len);
    memcpy(@dst.custom, @src.custom, dst.custom_len);
    Result := dst;
end;


function kmac_setkey(kctx : Pkmac_data_st;const key : PByte; keylen : size_t):integer;
var
  digest : PEVP_MD;

  w : integer;
begin
    digest := ossl_prov_digest_md(@kctx.digest);
    w := EVP_MD_get_block_size(digest);
    if (keylen < KMAC_MIN_KEY)  or  (keylen > KMAC_MAX_KEY) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    if w < 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        Exit(0);
    end;
    if 0>= kmac_bytepad_encode_key(@kctx.key, sizeof(kctx.key), @kctx.key_len,
                                 key, keylen, size_t( w))then
        Exit(0);
    Result := 1;
end;


function kmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
    kctx      : Pkmac_data_st;
    ctx       : PEVP_MD_CTX;
    _out      : PByte;
    out_len,
    block_len : size_t;
    res,
    t         : integer;
    cparams   : array[0..1] of TOSSL_PARAM;
begin
    kctx := vmacctx;
    ctx := kctx.ctx;
    if (not ossl_prov_is_running)  or  (0>= kmac_set_ctx_params(kctx, params)) then
        Exit(0);
    if key <> nil then
    begin
        if 0>= kmac_setkey(kctx, key, keylen) then
            Exit(0);
    end
    else
    if (kctx.key_len = 0) then
    begin
        { Check key has been set }
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if 0>= EVP_DigestInit_ex(kctx.ctx, ossl_prov_digest_md(@kctx.digest) ,
                           nil)  then
        Exit(0);
    t := EVP_MD_get_block_size(ossl_prov_digest_md(@kctx.digest));
    if t < 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        Exit(0);
    end;
    block_len := t;
    { Set default custom string if it is not already set }
    if kctx.custom_len = 0 then
    begin
        cparams[0] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, nil, 0);
        cparams[0] := OSSL_PARAM_END;

        kmac_set_ctx_params(kctx, @cparams);
    end;
    if 0>= bytepad(nil, @out_len, @kmac_string, sizeof(kmac_string) ,
                 @kctx.custom, kctx.custom_len, block_len)  then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    _out := OPENSSL_malloc(out_len);
    if _out = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    res := int( (bytepad(_out, nil, @kmac_string, sizeof(kmac_string),
                  @kctx.custom, kctx.custom_len, block_len)>0)
           and  (EVP_DigestUpdate(ctx, _out, out_len)>0)
           and  (EVP_DigestUpdate(ctx, @kctx.key, kctx.key_len)>0) );
    OPENSSL_free(Pointer(_out));
    Result := res;
end;


function kmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  kctx : Pkmac_data_st;
begin
    kctx := vmacctx;
    Result := EVP_DigestUpdate(kctx.ctx, data, datalen);
end;


function kmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  kctx           : Pkmac_data_st;
  ctx            : PEVP_MD_CTX;
  lbits,
  len            : size_t;
  encoded_outlen : array[0..(KMAC_MAX_ENCODED_HEADER_LEN)-1] of Byte;
  ok             : Boolean;
begin
    kctx := vmacctx;
    ctx := kctx.ctx;
    if not ossl_prov_is_running then
        Exit(0);
    { KMAC XOF mode sets the encoded length to 0 }
    lbits := get_result(kctx.xof_mode >0, 0 , (kctx.out_len * 8));
    ok := (right_encode(@encoded_outlen, sizeof(encoded_outlen), @len, lbits)>0)
         and  (EVP_DigestUpdate(ctx, @encoded_outlen, len) >0)
         and  (EVP_DigestFinalXOF(ctx, &out, kctx.out_len) >0);
    outl^ := kctx.out_len;
    Result := Int(ok);
end;


function kmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function kmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
var
  kctx : Pkmac_data_st;
  p : POSSL_PARAM;
  sz : integer;
begin
    kctx := vmacctx;
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE );
    if (p <> nil)
             and  (0>= OSSL_PARAM_set_size_t(p, kctx.out_len)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE );
    if p <> nil then
    begin
        sz := EVP_MD_block_size(ossl_prov_digest_md(@kctx.digest));
        if 0>= OSSL_PARAM_set_int(p, sz) then
            Exit(0);
    end;
    Result := 1;
end;


function kmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function kmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  kctx : Pkmac_data_st;
  p : POSSL_PARAM;
  sz : size_t;
begin
    kctx := vmacctx;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_XOF );
    if (P  <> nil )
         and  (0>= OSSL_PARAM_get_int(p, @kctx.xof_mode)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
    if p <> nil then
    begin
        sz := 0;
        if 0>= OSSL_PARAM_get_size_t(p, @sz) then
            Exit(0);
        if sz > KMAC_MAX_OUTPUT_LEN then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
            Exit(0);
        end;
        kctx.out_len := sz;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if (p  <> nil )
             and  (0>= kmac_setkey(kctx, p.data, p.data_size)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM);
    if (p<> nil) then
    begin
        if p.data_size > KMAC_MAX_CUSTOM then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
            Exit(0);
        end;
        if 0>= encode_string(@kctx.custom, sizeof(kctx.custom) , @kctx.custom_len,
                           p.data, p.data_size)  then
            Exit(0);
    end;
    Result := 1;
end;


function get_encode_size(var bits : size_t):uint32;
var
  cnt,sz : uint32;
begin
    cnt := 0; sz := sizeof(size_t) ;
    while (bits>0)  and  (cnt < sz) do
    begin
        Inc(cnt);
        bits := bits shr 8;
    end;
    { If bits is zero 1 byte is required }
    if cnt = 0 then
       cnt := 1;
    Result := cnt;
end;


function right_encode( &out : PByte; out_max_len : size_t; out_len : Psize_t;var bits : size_t):integer;
var
  len : uint32;

  i : integer;
begin
    len := get_encode_size(bits);
    if len >= out_max_len then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        Exit(0);
    end;
    { MSB's are at the start of the bytes array }
    i := len - 1;
    while i >= 0 do
    begin
        &out[i] := Byte(bits and $FF);
        bits := bits shr  8;
        Dec(i);
    end;
    { Tack the length onto the end }
    &out[len] := Byte( len);
    { The Returned length includes the tacked on byte }
    out_len^ := len + 1;
    Result := 1;
end;


function encode_string(_out : PByte; out_max_len : size_t; out_len : Psize_t;const _in : PByte; in_len : size_t):integer;
var
  i, bits, len, sz : size_t;
begin
    if _in = nil then
    begin
        out_len^ := 0;
    end
    else
    begin
        bits := 8 * in_len;
        len := get_encode_size(bits);
        sz := 1 + len + in_len;
        if sz > out_max_len then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            Exit(0);
        end;
        _out[0] := Byte( len);
        for i := len downto 1 do
        begin
            _out[i] := (bits and $FF);
            bits := bits shr 8;
        end;
        memcpy(_out + len + 1, _in, in_len);
        out_len^ := sz;
    end;
    Result := 1;
end;


function bytepad(_out : PByte; out_len : Psize_t;const in1 : PByte; in1_len : size_t;const in2 : PByte; in2_len, w : size_t):integer;
var
  len : integer;

  p : PByte;

  sz : integer;
begin
    p := _out;
    sz := w;
    if _out = nil then
    begin
        if out_len = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            Exit(0);
        end;
        sz := 2 + in1_len + get_result(in2 <> nil , in2_len , 0);
        out_len^ := (sz + w - 1) div w * w;
        Exit(1);
    end;
    if not ossl_assert(w <= 255) then
        Exit(0);
    { Left encoded w }
    p^ := 1;
    Inc (p);
    p^ := Byte( w);
    Inc (p);
    {  or  in1 }
    memcpy(p, in1, in1_len);
    p  := p + in1_len;
    { [  or  in2 ] }
    if (in2 <> nil)  and  (in2_len > 0) then
    begin
        memcpy(p, in2, in2_len);
        p  := p + in2_len;
    end;
    { Figure out the pad size (divisible by w) }
    len := p - _out;
    sz := (len + w - 1) div w * w;
    { zero pad the end of the buffer }
    if sz <> len then
       memset(p, 0, sz - len);
    if out_len <> nil then
       out_len^ := sz;
    Result := 1;
end;


function kmac_bytepad_encode_key(_out : PByte; out_max_len : size_t; out_len : Psize_t;const _in : PByte; in_len, w : size_t):integer;
var
  tmp : array[0..(KMAC_MAX_KEY + KMAC_MAX_ENCODED_HEADER_LEN)-1] of Byte;

  tmp_len : size_t;
begin
    if 0>= encode_string(@tmp, sizeof(tmp), @tmp_len, _in, in_len)  then
        Exit(0);
    if 0>= bytepad(nil, out_len, @tmp, tmp_len, nil, 0, w ) then
        Exit(0);
    if not ossl_assert( out_len^ <= out_max_len )then
        Exit(0);
    Result := bytepad(_out, nil, @tmp, tmp_len, nil, 0, w);
end;




initialization

    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, Nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, nil);
    known_gettable_ctx_params[2] := OSSL_PARAM_END;

    known_settable_ctx_params[0] := _OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, nil);
    known_settable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, nil, 0);
    known_settable_ctx_params[4] := OSSL_PARAM_END ;

    kmac128_params[0] := _OSSL_PARAM_utf8_string('digest', PUTF8Char(OSSL_DIGEST_NAME_KECCAK_KMAC128), sizeof(OSSL_DIGEST_NAME_KECCAK_KMAC128));
    kmac128_params[1] := OSSL_PARAM_END;
    kmac256_params[0] := _OSSL_PARAM_utf8_string('digest', PUTF8Char(OSSL_DIGEST_NAME_KECCAK_KMAC256), sizeof(OSSL_DIGEST_NAME_KECCAK_KMAC256));
    kmac256_params[1] := OSSL_PARAM_END;

end.
