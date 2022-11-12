unit OpenSSL3.providers.implementations.kdfs.krb5kdf;

interface
uses OpenSSL.Api;

function krb5kdf_new( provctx : Pointer):Pointer;
procedure krb5kdf_free( vctx : Pointer);
procedure krb5kdf_reset( vctx : Pointer);
function krb5kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function krb5kdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function krb5kdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function krb5kdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function krb5kdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function krb5kdf_set_membuf(var dst : PByte; dst_len : Psize_t;const p : POSSL_PARAM):integer;
function KRB5KDF(const cipher : PEVP_CIPHER; engine : PENGINE;const key : PByte; key_len : size_t;const constant : PByte; constant_len : size_t; okey : PByte; okey_len : size_t):integer;
function cipher_init(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; engine : PENGINE;const key : PByte; key_len : size_t):integer;
procedure n_fold(block : PByte; blocksize : uint32;const constant : PByte; constant_len : size_t);
function fixup_des3_key( key : PByte):integer;

const ossl_kdf_krb5kdf_functions: array[0..8] of TOSSL_DISPATCH  = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@krb5kdf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@krb5kdf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@krb5kdf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@krb5kdf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;
      method:(code:@krb5kdf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS;
      method:(code:@krb5kdf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
      method:(code:@krb5kdf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS;
      method:(code:@krb5kdf_get_ctx_params ;data:nil)),
    ( function_id: 0;  method:(code:nil ;data:nil))
);


var // 1d arrays
  known_settable_ctx_params : array[0..4] of TOSSL_PARAM;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;


implementation
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,
     openssl3.crypto.des.set_key, openssl3.crypto.cpuid,
     openssl3.crypto.evp.evp_enc,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib;



function fixup_des3_key( key : PByte):integer;
var
  cblock : PByte;

  i, j : integer;
begin
    i := 2;
    while ( i >= 0) do
    begin
        cblock := @key[i * 8];
        memmove(cblock, @key[i * 7], 7);
        cblock[7] := 0;
        for j := 0 to 6 do
            cblock[7]  := cblock[7]  or ((cblock[j] and 1)  shl  (j + 1));
        DES_set_odd_parity(PDES_cblock (cblock));
        Dec(i);
    end;
    { fail if keys are such that triple des degrades to single des }
    if (CRYPTO_memcmp(@key[0], @key[8], 8 ) = 0 ) or
       (CRYPTO_memcmp(@key[8], @key[16], 8) = 0)then
    begin
        Exit(0);
    end;
    Result := 1;
end;

procedure n_fold(block : PByte; blocksize : uint32;const constant : PByte; constant_len : size_t);
var
  tmp,
  gcd,
  remainder,
  lcm,
  carry     : uint32;
  b,
  l         : integer;
  rotbits,
  rshift,
  rbyte     : uint32;
begin
    if constant_len = blocksize then
    begin
        memcpy(block, constant, constant_len);
        exit;
    end;
    { Least Common Multiple of lengths: LCM(a,b)}
    gcd := blocksize;
    remainder := constant_len;
    { Calculate Great Common Divisor first GCD(a,b) }
    while remainder <> 0 do  begin
        tmp := gcd mod remainder;
        gcd := remainder;
        remainder := tmp;
    end;
    { resulting a is the GCD, LCM(a,b) = |a*b|/GCD(a,b) }
    lcm := blocksize * constant_len div gcd;
    { now spread out the bits }
    memset(block, 0, blocksize);
    { last to first to be able to bring carry forward }
    carry := 0;
    l := lcm - 1;
    while( l >= 0) do
    begin
        { destination byte in block is l % N }
        b := l mod blocksize;
        { Our virtual s buffer is R = L/K long (K = constant_len) }
        { So we rotate backwards from R-1 to 0 (none) rotations }
        rotbits := 13 * (l div constant_len);
        { find the byte on s where rotbits falls onto }
        rbyte := l - (rotbits div 8);
        { calculate how much shift on that byte }
        rshift := rotbits and $07;
        { rbyte % constant_len gives us the unrotated byte in the
         * constant buffer, get also the previous byte then
         * appropriately shift them to get the rotated byte we need }
        tmp := (constant[(rbyte-1) mod constant_len]  shl  (8 - rshift)
               or constant[rbyte mod constant_len]  shr  rshift)
              and $ff;
        { add with carry to any value placed by previous passes }
        tmp  := tmp + (carry + block[b]);
        block[b] := tmp and $ff;
        { save any carry that may be left }
        carry := tmp  shr  8;
        Dec(l);
    end;
    { if any carry is left at the end, add it through the number }
    b := blocksize - 1;
    while ( b >= 0)  and  (carry <> 0) do
    begin
        carry  := carry + (block[b]);
        block[b] := carry and $ff;
        carry := carry shr 8;
        Dec(b);
    end;
end;




function cipher_init(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; engine : PENGINE;const key : PByte; key_len : size_t):integer;
var
  klen, ret : integer;
  label _out;
begin
    ret := EVP_EncryptInit_ex(ctx, cipher, engine, key, nil);
    if 0>= ret then goto _out ;
    { set the key len for the odd variable key len cipher }
    klen := EVP_CIPHER_CTX_get_key_length(ctx);
    if key_len <> size_t(klen) then
    begin
        ret := EVP_CIPHER_CTX_set_key_length(ctx, key_len);
        if 0>= ret then goto _out ;
    end;
    { we never want padding, either the length requested is a multiple of
     * the cipher block size or we are passed a cipher that can cope with
     * partial blocks via techniques like cipher text stealing }
    ret := EVP_CIPHER_CTX_set_padding(ctx, 0);
    if 0>= ret then goto _out ;
_out:
    Result := ret;
end;


function KRB5KDF(const cipher : PEVP_CIPHER; engine : PENGINE;const key : PByte; key_len : size_t;const constant : PByte; constant_len : size_t; okey : PByte; okey_len : size_t):integer;
var
    ctx           : PEVP_CIPHER_CTX;

    block         : array[0..(EVP_MAX_BLOCK_LENGTH * 2)-1] of Byte;

  plainblock,
  cipherblock   : PByte;

  blocksize,
  cipherlen,
  osize         : size_t;

  des3_no_fixup,
  ret,
  olen          : integer;
  label _out;
begin
    ctx := nil;
{$IFNDEF OPENSSL_NO_DES}
    des3_no_fixup := 0;
{$ENDIF}
    if key_len <> okey_len then
    begin
{$IFNDEF OPENSSL_NO_DES}
        { special case for 3des, where the caller may be requesting
         * the random raw key, instead of the fixed up key  }
        if (EVP_CIPHER_get_nid(cipher) = NID_des_ede3_cbc)  and
            (key_len = 24)  and  (okey_len = 21) then
        begin
           des3_no_fixup := 1;
        end
        else
        begin
{$ENDIF}
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_OUTPUT_BUFFER_SIZE);
            Exit(0);
{$IFNDEF OPENSSL_NO_DES}
        end;
{$ENDIF}
    end;
    ctx := EVP_CIPHER_CTX_new();
    if ctx = nil then Exit(0);
    ret := cipher_init(ctx, cipher, engine, key, key_len);
    if  0>= ret then
       goto _out ;
    { Initialize input block }
    blocksize := EVP_CIPHER_CTX_get_block_size(ctx);
    if constant_len > blocksize then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONSTANT_LENGTH);
        ret := 0;
        goto _out ;
    end;
    n_fold(@block, blocksize, constant, constant_len);
    plainblock := @block;
    cipherblock := PByte(@block) + EVP_MAX_BLOCK_LENGTH;
    osize := 0;
    while ( osize < okey_len) do
    begin
        ret := EVP_EncryptUpdate(ctx, cipherblock, @olen,
                                plainblock, blocksize);
        if 0>= ret then goto _out ;
        cipherlen := olen;
        ret := EVP_EncryptFinal_ex(ctx, cipherblock, @olen);
        if 0>= ret then goto _out ;
        if olen <> 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            ret := 0;
            goto _out ;
        end;
        { write cipherblock out }
        if cipherlen > okey_len - osize then
           cipherlen := okey_len - osize;
        memcpy(okey + osize, cipherblock, cipherlen);
        if okey_len > osize + cipherlen then
        begin
            { we need to reinitialize cipher context per spec }
            ret := EVP_CIPHER_CTX_reset(ctx);
            if 0>= ret then goto _out ;
            ret := cipher_init(ctx, cipher, engine, key, key_len);
            if 0>= ret then goto _out ;
            { also swap block offsets so last ciphertext becomes new
             * plaintext }
            plainblock := cipherblock;
            if cipherblock = @block then
            begin
                cipherblock  := cipherblock + EVP_MAX_BLOCK_LENGTH;
            end
            else
            begin
                cipherblock := @block;
            end;
        end;
        osize := osize+cipherlen;
    end;
{$IFNDEF OPENSSL_NO_DES}
    if ( EVP_CIPHER_get_nid(cipher) = NID_des_ede3_cbc ) and
      ( 0>= des3_no_fixup) then
    begin
        ret := fixup_des3_key(okey);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            goto _out ;
        end;
    end;
{$ENDIF}
    ret := 1;
_out:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(@block, EVP_MAX_BLOCK_LENGTH * 2);
    Result := ret;
end;




function krb5kdf_set_membuf(var dst : PByte; dst_len : Psize_t;const p : POSSL_PARAM):integer;
begin
    OPENSSL_clear_free(Pointer(dst), dst_len^);
    dst := nil;
    dst_len^ := 0;
    Result := OSSL_PARAM_get_octet_string(p,  Pointer( dst), 0, dst_len);
end;

function krb5kdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PKRB5KDF_CTX;

  cipher : PEVP_CIPHER;

  len : size_t;

  p : POSSL_PARAM;
begin
    ctx := (PKRB5KDF_CTX  (vctx));
    cipher := ossl_prov_cipher_cipher(@ctx.cipher);
    if Assigned(cipher) then
       len := EVP_CIPHER_get_key_length(cipher)
    else
        len := EVP_MAX_KEY_LENGTH;
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, len));
    Result := -2;
end;



function krb5kdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[0] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;



function krb5kdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  ctx : PKRB5KDF_CTX;
  provctx : POSSL_LIB_CTX;
begin
    ctx := vctx;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if 0>= ossl_prov_cipher_load_from_params(@ctx.cipher, params, provctx)  then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY );
    if p <> nil then
        if (0>= krb5kdf_set_membuf(ctx.key, @ctx.key_len, p)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CONSTANT );
    if (p <> nil)  then
        if 0>= krb5kdf_set_membuf(ctx.constant, @ctx.constant_len, p) then
            Exit(0);
    Result := 1;
end;


function krb5kdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_CONSTANT, nil, 0);
    known_settable_ctx_params[4] := OSSL_PARAM_END ;

    Result := @known_settable_ctx_params;
end;



function krb5kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKRB5KDF_CTX;

  cipher : PEVP_CIPHER;

  engine : PENGINE;
begin
    ctx := (PKRB5KDF_CTX  (vctx));
    if (not ossl_prov_is_running) or
       ( 0>= krb5kdf_set_ctx_params(ctx, params))then
        Exit(0);
    cipher := ossl_prov_cipher_cipher(@ctx.cipher);
    if cipher = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        Exit(0);
    end;
    if ctx.key = nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        Exit(0);
    end;
    if ctx.constant = nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONSTANT);
        Exit(0);
    end;
    engine := ossl_prov_cipher_engine(@ctx.cipher);
    Exit(KRB5KDF(cipher, engine, ctx.key, ctx.key_len,
                   ctx.constant, ctx.constant_len,
                   key, keylen));
end;



procedure krb5kdf_reset( vctx : Pointer);
var
  ctx : PKRB5KDF_CTX;

  provctx : Pointer;
begin
    ctx := (PKRB5KDF_CTX  (vctx));
    provctx := ctx.provctx;
    ossl_prov_cipher_reset(@ctx.cipher);
    OPENSSL_clear_free(Pointer(ctx.key), ctx.key_len);
    OPENSSL_clear_free(Pointer(ctx.constant), ctx.constant_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
end;



procedure krb5kdf_free( vctx : Pointer);
var
  ctx : PKRB5KDF_CTX;
begin
    ctx := (PKRB5KDF_CTX  (vctx));
    if ctx <> nil then
    begin
        krb5kdf_reset(ctx);
        OPENSSL_free(ctx);
    end;
end;

function krb5kdf_new( provctx : Pointer):Pointer;
var
  ctx : PKRB5KDF_CTX;
begin
    if not ossl_prov_is_running()  then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^ ));
    if ctx =  nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.provctx := provctx;
    Result := ctx;
end;


end.
