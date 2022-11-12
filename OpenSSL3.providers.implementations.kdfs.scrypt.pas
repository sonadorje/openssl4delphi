unit OpenSSL3.providers.implementations.kdfs.scrypt;

interface
uses OpenSSL.Api;

function kdf_scrypt_new( provctx : Pointer):Pointer;
procedure kdf_scrypt_free( vctx : Pointer);
procedure kdf_scrypt_reset( vctx : Pointer);
  procedure kdf_scrypt_init( ctx : PKDF_SCRYPT);
  function scrypt_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
  function set_digest( ctx : PKDF_SCRYPT):integer;
  function set_property_query(ctx : PKDF_SCRYPT;const propq : PUTF8Char):integer;
  function kdf_scrypt_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function is_power_of_two( value : uint64):Boolean;
  function kdf_scrypt_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function kdf_scrypt_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
  function kdf_scrypt_gettable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
  function kdf_scrypt_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function scrypt_alg(var pass : PUTF8Char; passlen : size_t;var salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t; sha256 : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  procedure scryptROMix( B : PByte; r, N : uint64; X, T, V : Puint32_t);
  procedure scryptBlockMix( B_, B : Puint32_t; r : uint64);
  procedure salsa208_word_specification( inout : Puint32);

const
    SCRYPT_PR_MAX  = ((1 shl 30) - 1);
    LOG2_UINT64_MAX   =      (sizeof(uint64_t) * 8 - 1);

    ossl_kdf_scrypt_functions: array[0..8] of TOSSL_DISPATCH  = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@kdf_scrypt_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@kdf_scrypt_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@kdf_scrypt_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@kdf_scrypt_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;
      method:(code:@kdf_scrypt_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kdf_scrypt_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
      method:(code:@kdf_scrypt_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@kdf_scrypt_get_ctx_params ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);
var// 1d arrays
  known_settable_ctx_params : array[0..17] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;

implementation

uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib,
     openssl3.crypto.evp.digest, openssl3.crypto.o_str,
     openssl3.crypto.evp.p5_crpt2;

function  R(a,b: UInt32): UInt32;
begin
   Result := (((a) shl (b)) or ((a) shr (32 - (b))))
end;

procedure salsa208_word_specification( inout : Puint32);
var
  i : integer;

  x : array[0..15] of uint32;
begin
{$POINTERMATH ON}
    memcpy(@x, inout, sizeof(x));
    i := 8;
    while ( i > 0) do
    begin
        x[4]  := x[4] xor (R(x[0] + x[12], 7));
        x[8]  := x[8] xor (R(x[4] + x[0], 9));
        x[12]  := x[12] xor (R(x[8] + x[4], 13));
        x[0]  := x[0] xor (R(x[12] + x[8], 18));
        x[9]  := x[9] xor (R(x[5] + x[1], 7));
        x[13]  := x[13] xor (R(x[9] + x[5], 9));
        x[1]  := x[1] xor (R(x[13] + x[9], 13));
        x[5]  := x[5] xor (R(x[1] + x[13], 18));
        x[14]  := x[14] xor (R(x[10] + x[6], 7));
        x[2]  := x[2] xor (R(x[14] + x[10], 9));
        x[6]  := x[6] xor (R(x[2] + x[14], 13));
        x[10]  := x[10] xor (R(x[6] + x[2], 18));
        x[3]  := x[3] xor (R(x[15] + x[11], 7));
        x[7]  := x[7] xor (R(x[3] + x[15], 9));
        x[11]  := x[11] xor (R(x[7] + x[3], 13));
        x[15]  := x[15] xor (R(x[11] + x[7], 18));
        x[1]  := x[1] xor (R(x[0] + x[3], 7));
        x[2]  := x[2] xor (R(x[1] + x[0], 9));
        x[3]  := x[3] xor (R(x[2] + x[1], 13));
        x[0]  := x[0] xor (R(x[3] + x[2], 18));
        x[6]  := x[6] xor (R(x[5] + x[4], 7));
        x[7]  := x[7] xor (R(x[6] + x[5], 9));
        x[4]  := x[4] xor (R(x[7] + x[6], 13));
        x[5]  := x[5] xor (R(x[4] + x[7], 18));
        x[11]  := x[11] xor (R(x[10] + x[9], 7));
        x[8]  := x[8] xor (R(x[11] + x[10], 9));
        x[9]  := x[9] xor (R(x[8] + x[11], 13));
        x[10]  := x[10] xor (R(x[9] + x[8], 18));
        x[12]  := x[12] xor (R(x[15] + x[14], 7));
        x[13]  := x[13] xor (R(x[12] + x[15], 9));
        x[14]  := x[14] xor (R(x[13] + x[12], 13));
        x[15]  := x[15] xor (R(x[14] + x[13], 18));
        i := i - 2;
    end;
    for i := 0 to 16 - 1 do
        inout[i]  := inout[i] + (x[i]);
    OPENSSL_cleanse(@x, sizeof(x));
{$POINTERMATH OFF}
end;



procedure scryptBlockMix( B_, B : Puint32_t; r : uint64);
var
  i : uint64;
  j : Integer;
  X : array[0..15] of uint32;

  pB : Puint32_t;
begin
    Inc(B , (r * 2 - 1) * 16);
    memcpy(@X, B, sizeof(X));
    pB := B;
    i := 0;
    while i<= r * 2-1 do
    begin
        for j := 0 to 15 do
        begin
            X[j]  := X[j] xor ( pB^);
            Inc(pB);
        end;
        salsa208_word_specification(@X);
        Inc(B_ , (i div 2 + (i and 1) * r) * 16);
        memcpy(B_, @X, sizeof(X));
        Inc(i);
    end;
    OPENSSL_cleanse(@X, sizeof(X));
end;


procedure scryptROMix( B : PByte; r, N : uint64; X, T, V : Puint32_t);
var
  pB : PByte;
  pV, p0 : Puint32_t;
  i, k : uint64;
  j, xtmp : uint32;
begin
{$POINTERMATH ON}
    { Convert from little endian input }
    pV := V; i := 0; pB := B;
    while ( i < 32 * r )do
    begin
        pV^ := pb^;Inc(pB);
        pV^  := pV^  or ( pB^  shl  8); Inc(pB);
        pV^  := pV^  or ( pB^  shl  16); Inc(pB);
        pV^  := pV^  or (uint32_t(pB^)  shl  24); Inc(pB);
        Inc(i);
        Inc(pV);
    end;
    i := 1;
    while ( i < N) do
    begin
        scryptBlockMix(pV, pV - 32 * r, r);
        Inc(i);
        pV := pV + 32 * r;
    end;
    scryptBlockMix(X, V + (N - 1) * 32 * r, r);
    i := 0 ;
    while i<= N-1 do
    begin
        j := X[16 * (2 * r - 1)] mod N;
        pV := V + 32 * r * j;
        k := 0;
        while k<= 32 * r-1 do
        begin
            T[k] := X[k]  xor pV^;
            Inc(pV);
            Inc(k);
        end;
        scryptBlockMix(X, T, r);
        Inc(i);
    end;
    { Convert output to little endian }
    i := 0; pB := B;
    while i <=32 * r-1 do
    begin
        xtmp := X[i];
        pB^ := (xtmp and $ff); Inc(pB);
        pB^ := ((xtmp  shr  8) and $ff);Inc(pB);
        pB^ := ((xtmp  shr  16) and $ff);Inc(pB);
        pB^ := ((xtmp  shr  24) and $ff); Inc(pB);
        Inc(i);
    end;
{$POINTERMATH OFF}
end;






function scrypt_alg(var pass : PUTF8Char; passlen : size_t;var salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t; sha256 : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  rv : integer;
  B : PByte;
  X, V, T : Puint32_t;
  i, Blen, Vlen : uint64;
  label _err;
begin
    rv := 0;
    { Sanity check parameters }
    { initial check, r,p must be non zero, N >= 2 and a power of 2 }
    if (r = 0)  or  (p = 0)  or  (N < 2)  or  (N and (N - 1 )>0) then
        Exit(0);
    { Check p * r < SCRYPT_PR_MAX avoiding overflow }
    if p > SCRYPT_PR_MAX div r then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
        Exit(0);
    end;
    {
     * Need to check N: if 2^(128 * r / 8) overflows limit this is
     * automatically satisfied since N <= UINT64_MAX.
     }
    if 16 * r <= LOG2_UINT64_MAX then
    begin
        if N >= ((uint64_t(1))  shl  (16 * r)) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
            Exit(0);
        end;
    end;
    { Memory checks: check total allocated buffer size fits in Puint64_t  /
    {
     * B size in section 5 step 1.S
     * Note: we know p * 128 * r < UINT64_MAX because we already checked
     * p * r < SCRYPT_PR_MAX
     }
    Blen := p * 128 * r;
    {
     * Yet we pass it as integer to PKCS5_PBKDF2_HMAC... [This would
     * have to be revised when/if PKCS5_PBKDF2_HMAC accepts size_t.]
     }
    if Blen > INT_MAX then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
        Exit(0);
    end;
    {
     * Check 32 * r * (N + 2) * sizeof(uint32_t) fits in uint64_t
     * This is combined size V, X and T (section 4)
     }
    i := UINT64_MAX div (32 * sizeof(uint32_t));
    if N + 2 > i div r then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
        Exit(0);
    end;
    Vlen := 32 * r * (N + 2) * sizeof(uint32_t);
    { check total allocated size fits in Puint64_t  /
    if Blen > UINT64_MAX - Vlen then {
        ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
        Exit(0);
    }
    { Check that the maximum memory doesn't exceed a size_t limits }
    if maxmem > SIZE_MAX then maxmem := SIZE_MAX;
    if Blen + Vlen > maxmem then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED);
        Exit(0);
    end;
    { If no key return to indicate parameters are OK }
    if key = nil then Exit(1);
    B := OPENSSL_malloc(size_t(Blen + Vlen));
    if B = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    X := Puint32_t(B + Blen);
    Inc(X , 32 * r);
    T := X;//X + 32 * r;
    Inc(T , 32 * r);
    V := T;//T + 32 * r;
    if ossl_pkcs5_pbkdf2_hmac_ex(pass, passlen, salt, saltlen, 1, sha256,
                                  int(Blen), B, libctx, propq) = 0 then
        goto _err ;
    i := 0;
    while i <= p-1 do
    begin
        scryptROMix(B + 128 * r * i, r, N, X, T, V);
        Inc(i);
    end;

    if ossl_pkcs5_pbkdf2_hmac_ex(pass, passlen, B, int( Blen), 1, sha256,
                                  keylen, key, libctx, propq) = 0 then
        goto _err ;
    rv := 1;
 _err:
    if rv = 0 then
       ERR_raise(ERR_LIB_EVP, EVP_R_PBKDF2_ERROR);
    OPENSSL_clear_free(Pointer(B), size_t(Blen + Vlen));
    Result := rv;
end;

function kdf_scrypt_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, SIZE_MAX));
    Result := -2;
end;



function kdf_scrypt_gettable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[0] := OSSL_PARAM_END ;
    Result := @known_gettable_ctx_params;
end;



function kdf_scrypt_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_N, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_uint32(OSSL_KDF_PARAM_SCRYPT_R, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_uint32(OSSL_KDF_PARAM_SCRYPT_P, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[0] := OSSL_PARAM_END ;

    Result := @known_settable_ctx_params;
end;





procedure kdf_scrypt_reset( vctx : Pointer);
var
  ctx : PKDF_SCRYPT;
begin
    ctx := (PKDF_SCRYPT  (vctx));
    OPENSSL_free(ctx.salt);
    OPENSSL_clear_free(Pointer(ctx.pass), ctx.pass_len);
    kdf_scrypt_init(ctx);
end;


procedure kdf_scrypt_init( ctx : PKDF_SCRYPT);
begin
    { Default values are the most conservative recommendation given in the
     * original paper of C. Percival. Derivation uses roughly 1 GiB of memory
     * for this parameter choice (approx. 128 * r * N * p bytes).
     }
    ctx.N := 1  shl  20;
    ctx.r := 8;
    ctx.p := 1;
    ctx.maxmem_bytes := 1025 * 1024 * 1024;
end;


function scrypt_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
begin
    OPENSSL_clear_free(Pointer(buffer), buflen^);
    buffer := nil;
    buflen^ := 0;
    if p.data_size = 0 then
    begin
        buffer := OPENSSL_malloc(1);
        if buffer = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end
    else
    if (p.data <> nil) then
    begin
        if  0>= OSSL_PARAM_get_octet_string(p, Pointer(buffer), 0, buflen) then
            Exit(0);
    end;
    Result := 1;
end;


function set_digest( ctx : PKDF_SCRYPT):integer;
begin
    EVP_MD_free(ctx.sha256);
    ctx.sha256 := EVP_MD_fetch(ctx.libctx, 'sha256', ctx.propq);
    if ctx.sha256 = nil then
    begin
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOAD_SHA256);
        Exit(0);
    end;
    Result := 1;
end;


function set_property_query(ctx : PKDF_SCRYPT;const propq : PUTF8Char):integer;
begin
    OPENSSL_free(ctx.propq);
    ctx.propq := nil;
    if propq <> nil then
    begin
        OPENSSL_strdup(ctx.propq, propq);
        if ctx.propq = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    Result := 1;
end;


function kdf_scrypt_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_SCRYPT;
begin
    ctx := (PKDF_SCRYPT  (vctx));
    if (not ossl_prov_is_running)  or
       (0>= kdf_scrypt_set_ctx_params(ctx, params)) then
        Exit(0);
    if ctx.pass = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        Exit(0);
    end;
    if ctx.salt = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        Exit(0);
    end;
    if (ctx.sha256 = nil)  and  (0>= set_digest(ctx) )then
        Exit(0);
    Exit(scrypt_alg(PUTF8Char (ctx.pass), ctx.pass_len, ctx.salt,
                      ctx.salt_len, ctx.N, ctx.r, ctx.p,
                      ctx.maxmem_bytes, key, keylen, ctx.sha256,
                      ctx.libctx, ctx.propq));
end;


function is_power_of_two( value : uint64):Boolean;
begin
    Result := (value <> 0)  and  ((value and (value - 1)) = 0);
end;


function kdf_scrypt_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
    p         : POSSL_PARAM;

    ctx       : PKDF_SCRYPT;

    u64_value : uint64;
begin
    ctx := vctx;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD );
    if p <> nil then
        if (0>= scrypt_set_membuf(ctx.pass, @ctx.pass_len, p))then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT );
    if p <> nil then
        if (0>= scrypt_set_membuf(ctx.salt, @ctx.salt_len, p)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SCRYPT_N );
    if p <> nil then
    begin
        if (0>= OSSL_PARAM_get_uint64(p, @u64_value) )
             or  (u64_value <= 1)
             or  (not is_power_of_two(u64_value))then
            Exit(0);
        ctx.N := u64_value;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SCRYPT_R );
    if (p  <> nil) then
    begin
        if (0>= OSSL_PARAM_get_uint64(p, @u64_value) )  or  (u64_value < 1) then
            Exit(0);
        ctx.r := u64_value;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SCRYPT_P) ;
    if (p <> nil) then
    begin
        if (0>= OSSL_PARAM_get_uint64(p, @u64_value) ) or  (u64_value < 1) then
            Exit(0);
        ctx.p := u64_value;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SCRYPT_MAXMEM );
    if (p <> nil)   then
    begin
        if (0>= OSSL_PARAM_get_uint64(p, @u64_value))  or  (u64_value < 1) then
            Exit(0);
        ctx.maxmem_bytes := u64_value;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if p <> nil then
    begin
        if (p.data_type <> OSSL_PARAM_UTF8_STRING )
             or  (0>= set_property_query(ctx, p.data))
             or  (0>= set_digest(ctx)) then
            Exit(0);
    end;
    Result := 1;
end;




procedure kdf_scrypt_free( vctx : Pointer);
var
  ctx : PKDF_SCRYPT;
begin
    ctx := (PKDF_SCRYPT  (vctx));
    if ctx <> nil then
    begin
        OPENSSL_free(ctx.propq);
        EVP_MD_free(ctx.sha256);
        kdf_scrypt_reset(ctx);
        OPENSSL_free(ctx);
    end;
end;



function kdf_scrypt_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_SCRYPT;
begin
    if not ossl_prov_is_running()   then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.libctx := PROV_LIBCTX_OF(provctx);
    kdf_scrypt_init(ctx);
    Result := ctx;
end;
end.
