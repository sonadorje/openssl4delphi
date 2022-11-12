unit OpenSSL3.providers.implementations.rands.drbg_hash;

interface
uses  OpenSSL.Api, DateUtils, SysUtils,
    OpenSSL3.providers.implementations.rands.drbg;

type
  Tdnew_func = function(ctx: PPROV_DRBG): Integer;
  Tinstantiate_func = function(drbg: PPROV_DRBG; const entropy: PByte; entropylen: size_t; const nonce: PByte; noncelen: size_t; const pers: PByte; perslen: size_t): Integer;
  Tuninstantiate_func = function(ctx: PPROV_DRBG): Integer;
  Treseed_func = function(drbg: PPROV_DRBG; const ent: PByte; ent_len: size_t; const adin: PByte; adin_len: size_t): Integer;
  Tgenerate_func = function(p1: PPROV_DRBG; &out: PByte; outlen: size_t; const adin: PByte; adin_len: size_t): Integer;

 function drbg_hash_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
 procedure drbg_hash_free( vdrbg : Pointer);
 function drbg_hash_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
 function drbg_hash_uninstantiate_wrapper( vdrbg : Pointer):integer;
 function drbg_hash_generate_wrapper(vdrbg : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
 function drbg_hash_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
 function drbg_hash_settable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
 function drbg_hash_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
 function drbg_hash_gettable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
 function drbg_hash_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
 function drbg_hash_verify_zeroization( vdrbg : Pointer):integer;
 function drbg_hash_uninstantiate( drbg : PPROV_DRBG):integer;

const
    MAX_BLOCKLEN_USING_SMALL_SEEDLEN = (256 div 8);
    (* 888 bits from SP800-90Ar1 10.1 table 2 *)
    HASH_PRNG_MAX_SEEDLEN  =  (888 div 8);
    (* 440 bits from SP800-90Ar1 10.1 table 2 *)
    HASH_PRNG_SMALL_SEEDLEN  = (440 div 8);
    INBYTE_IGNORE: Byte = Byte($FF);

    ossl_drbg_hash_functions: array[0..16] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_RAND_NEWCTX; method:(code:@drbg_hash_new_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_FREECTX; method:(code:@drbg_hash_free ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_INSTANTIATE;
      method:(code:@drbg_hash_instantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNINSTANTIATE;
      method:(code:@drbg_hash_uninstantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GENERATE; method:(code:@drbg_hash_generate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_RESEED; method:(code:@drbg_hash_reseed_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_ENABLE_LOCKING; method:(code:@ossl_drbg_enable_locking ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_LOCK; method:(code:@ossl_drbg_lock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNLOCK; method:(code:@ossl_drbg_unlock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS;
      method:(code:@drbg_hash_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS; method:(code:@drbg_hash_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS;
      method:(code:@drbg_hash_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS; method:(code:@drbg_hash_get_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION;
      method:(code:@drbg_hash_verify_zeroization ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_SEED; method:(code:@ossl_drbg_get_seed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_CLEAR_SEED; method:(code:@ossl_drbg_clear_seed ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);

function drbg_hash_new( ctx : PPROV_DRBG):integer;
function drbg_hash_instantiate(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const nonce : PByte; nonce_len : size_t;const pstr : PByte; pstr_len : size_t):integer;
function hash_df(drbg : PPROV_DRBG; _out : PByte;const inbyte : Byte; &in : PByte; inlen : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
function hash_df1(drbg : PPROV_DRBG; &out : PByte;const in_byte : Byte; in1 : PByte; in1len : size_t):integer;
function drbg_hash_reseed(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
function drbg_hash_generate(drbg : PPROV_DRBG; &out : PByte; outlen : size_t;const adin : PByte; adin_len : size_t):integer;
function add_hash_to_v(drbg : PPROV_DRBG; inbyte : Byte;const adin : PByte; adinlen : size_t):integer;
function add_bytes( drbg : PPROV_DRBG; dst, _in : PByte; inlen : size_t):integer;
function hash_gen( drbg : PPROV_DRBG; &out : PByte; outlen : size_t):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem_sec, openssl3.providers.fips.self_test,
     openssl3.crypto.mem, openssl3.providers.common.provider_ctx,
     openssl3.crypto.context, openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params, openssl3.crypto.params,
     OpenSSL3.threads_none, OpenSSL3.openssl.core_dispatch,
     OpenSSL3.providers.common.provider_util,  openssl3.crypto.evp.evp_enc,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.digest;


var // 1d arrays
  known_settable_ctx_params : array[0..4] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..14] of TOSSL_PARAM;


function hash_gen( drbg : PPROV_DRBG; &out : PByte; outlen : size_t):integer;
var
  hash : PPROV_DRBG_HASH;

  one : Byte;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    one := 1;
    if outlen = 0 then Exit(1);
    memcpy(@hash.vtmp, @hash.V, drbg.seedlen);
    while True do
    begin
        if  (0>= EVP_DigestInit_ex(hash.ctx, ossl_prov_digest_md(@hash.digest) , nil) )
           or  (0>= EVP_DigestUpdate(hash.ctx, @hash.vtmp, drbg.seedlen)) then
            Exit(0);
        if outlen < hash.blocklen then
        begin
            if 0>= EVP_DigestFinal(hash.ctx, @hash.vtmp, nil) then
                Exit(0);
            memcpy(&out, @hash.vtmp, outlen);
            Exit(1);
        end
        else
        begin
            if  0>= EVP_DigestFinal(hash.ctx, &out, nil) then
                Exit(0);
            outlen  := outlen - hash.blocklen;
            if outlen = 0 then break;
            out  := out + hash.blocklen;
        end;
        add_bytes(drbg, @hash.vtmp, @one, 1);
    end;
    Result := 1;
end;




function add_bytes( drbg : PPROV_DRBG; dst, _in : PByte; inlen : size_t):integer;
var
  i : size_t;
  d, add : PByte;
  carry : Byte;
begin
    carry := 0;
    assert( (drbg.seedlen >= 1)  and  (inlen >= 1)  and  (inlen <= drbg.seedlen));
    d := @dst[drbg.seedlen - 1];
    add := @_in[inlen - 1];
    i := inlen;
    while ( i > 0) do
    begin
        result := d^ + add^ + carry;
        carry := Byte  (result  shr  8);
        d^ := Byte  (result and $ff);
        Dec(i); Dec(d); Dec(add);
    end;
    if carry <> 0 then
    begin
        { Add the carry to the top of the dst if inlen is not the same size }
        i := drbg.seedlen - inlen;
        while ( i > 0) do
        begin
            d^  := d^ + 1;
            if d^ <> 0 then { exit if carry doesnt propagate to the next byte }
                break;
            Dec(i); Dec(d);
        end;
    end;
    Result := 1;
end;



function add_hash_to_v(drbg : PPROV_DRBG; inbyte : Byte;const adin : PByte; adinlen : size_t):integer;
var
  hash : PPROV_DRBG_HASH;

  ctx : PEVP_MD_CTX;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    ctx := hash.ctx;
    Result := Int( (EVP_DigestInit_ex(ctx, ossl_prov_digest_md(@hash.digest), nil)>0)
            and    (EVP_DigestUpdate(ctx, @inbyte, 1)>0)
            and    (EVP_DigestUpdate(ctx, @hash.V, drbg.seedlen) >0)
            and    ( (adin = nil)  or  (EVP_DigestUpdate(ctx, adin, adinlen)>0) )
            and  (EVP_DigestFinal(ctx, @hash.vtmp, nil)>0)
            and  (add_bytes(drbg, @hash.V, @hash.vtmp, hash.blocklen)>0) );
end;

function drbg_hash_generate(drbg : PPROV_DRBG; &out : PByte; outlen : size_t;const adin : PByte; adin_len : size_t):integer;
var
    hash           : PPROV_DRBG_HASH;

    counter        : array[0..3] of Byte;

    reseed_counter : integer;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    reseed_counter := drbg.generate_counter;
    counter[0] := Byte  ((reseed_counter  shr  24) and $ff);
    counter[1] := Byte  ((reseed_counter  shr  16) and $ff);
    counter[2] := Byte  ((reseed_counter  shr  8) and $ff);
    counter[3] := Byte  (reseed_counter and $ff);
    Result := Int( (hash.ctx <> nil)
            and  ( (adin = nil)
           { (Step 2) if adin <> nil then V = V + Hash($02 or V or adin) }
                or  (adin_len = 0)
                or  (add_hash_to_v(drbg, $02, adin, adin_len) >0) )
           { (Step 3) Hashgen(outlen, V) }
            and  (hash_gen(drbg, out, outlen)>0)
           { (Step 4/5) H = V = (V + Hash($03 or V) mod (2^seedlen_bits) }
            and  (add_hash_to_v(drbg, $03, nil, 0)>0)
           { (Step 5) V = (V + H + C + reseed_counter) mod (2^seedlen_bits) }
           { V = (V + C) mod (2^seedlen_bits) }
            and  (add_bytes(drbg, @hash.V, @hash.C, drbg.seedlen)>0)
           { V = (V + reseed_counter) mod (2^seedlen_bits) }
            and  (add_bytes(drbg, @hash.V, @counter, 4)>0) );
end;




function drbg_hash_reseed(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
var
  hash : PPROV_DRBG_HASH;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    { (Step 1-2) V = Hash_df($01  or  V  or  entropy_input  or  additional_input) }
    { V about to be updated so use C as output instead }
    if  0>= hash_df(drbg, @hash.C, $01, @hash.V, drbg.seedlen, ent, ent_len,
                 adin, adin_len)  then
        Exit(0);
    memcpy(@hash.V, @hash.C, drbg.seedlen);
    { (Step 4) C = Hash_df($00 or V, seedlen) }
    Result := hash_df1(drbg, @hash.C, $00, @hash.V, drbg.seedlen);
end;




function hash_df1(drbg : PPROV_DRBG; &out : PByte;const in_byte : Byte; in1 : PByte; in1len : size_t):integer;
begin
    Result := hash_df(drbg, out, in_byte, in1, in1len, nil, 0, nil, 0);
end;




function hash_df(drbg : PPROV_DRBG; _out : PByte;const inbyte : Byte; &in : PByte; inlen : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
var
    hash              : PPROV_DRBG_HASH;
    ctx               : PEVP_MD_CTX;
    vtmp              : PByte;
    tmp               : array[0..(1 + 4 + 1)-1] of Byte;
    tmp_sz            : integer;
    outlen,
    num_bits_returned : size_t;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    ctx := hash.ctx;
    vtmp := @hash.vtmp;
    { tmp = counter  or  num_bits_returned  or  [inbyte] }
    tmp_sz := 0;
    outlen := drbg.seedlen;
    num_bits_returned := outlen * 8;
    {
     * No need to check outlen size here, as the standard only ever needs
     * seedlen bytes which is always less than the maximum permitted.
     }
    { (Step 3) counter = 1 (tmp[0] is the 8 bit counter) }
    tmp[PostInc(tmp_sz)] := 1;
    { tmp[1..4] is the fixed 32 bit no_of_bits_to_return }
    tmp[PostInc(tmp_sz)] := Byte((num_bits_returned  shr  24) and $ff);
    tmp[PostInc(tmp_sz)] := Byte ((num_bits_returned  shr  16) and $ff);
    tmp[PostInc(tmp_sz)] := Byte ((num_bits_returned  shr  8) and $ff);
    tmp[PostInc(tmp_sz)] := Byte (num_bits_returned and $ff);
    { Tack the additional input byte onto the end of tmp if it exists }
    if inbyte <> INBYTE_IGNORE then
       tmp[PostInc(tmp_sz)] := inbyte;
    { (Step 4) }
    while True do
    begin
        {
         * (Step 4.1) out = out  or  Hash(tmp  or  in  or  [in2]  or  [in3])
         *            (where tmp = counter  or  num_bits_returned  or  [inbyte])
         }
        if  not ( (EVP_DigestInit_ex(ctx, ossl_prov_digest_md(@hash.digest), nil)>0)
                 and  (EVP_DigestUpdate(ctx, @tmp, tmp_sz)>0)
                 and  (EVP_DigestUpdate(ctx, &in, inlen)>0)
                 and  ( (in2 = nil)  or  (EVP_DigestUpdate(ctx, in2, in2len)>0) )
                 and  ( (in3 = nil)  or  (EVP_DigestUpdate(ctx, in3, in3len)>0) ) )  then
            Exit(0);
        if outlen < hash.blocklen then
        begin
            if  0>= EVP_DigestFinal(ctx, vtmp, nil) then
                Exit(0);
            memcpy(_out, vtmp, outlen);
            OPENSSL_cleanse(vtmp, hash.blocklen);
            break;
        end
        else
        if ( 0>= EVP_DigestFinal(ctx, _out, nil)) then
        begin
            Exit(0);
        end;
        outlen  := outlen - hash.blocklen;
        if outlen = 0 then break;
        { (Step 4.2) PostInc(counter) }
        Inc(tmp[0]);
        _out  := _out + hash.blocklen;
    end;
    Result := 1;
end;



function drbg_hash_instantiate(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const nonce : PByte; nonce_len : size_t;const pstr : PByte; pstr_len : size_t):integer;
var
  hash : PPROV_DRBG_HASH;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    EVP_MD_CTX_free(hash.ctx);
    hash.ctx := EVP_MD_CTX_new();
    { (Step 1-3) V = Hash_df(entropy or nonce or pers, seedlen) }
    Result := Int( (hash.ctx <> nil) and
                   (hash_df(drbg, @hash.V, INBYTE_IGNORE,
                      ent, ent_len, nonce, nonce_len, pstr, pstr_len)>0)
           { (Step 4) C = Hash_df($00 or V, seedlen) }
              and  (hash_df1(drbg, @hash.C, $00, @hash.V, drbg.seedlen)>0));
end;




function drbg_hash_new( ctx : PPROV_DRBG):integer;
var
  hash : PPROV_DRBG_HASH;
begin
    hash := OPENSSL_secure_zalloc(sizeof( hash^));
    if hash = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ctx.data := hash;
    ctx.seedlen := HASH_PRNG_MAX_SEEDLEN;
    ctx.max_entropylen := DRBG_MAX_LENGTH;
    ctx.max_noncelen := DRBG_MAX_LENGTH;
    ctx.max_perslen := DRBG_MAX_LENGTH;
    ctx.max_adinlen := DRBG_MAX_LENGTH;
    { Maximum number of bits per request = 2^19  = 2^16 bytes }
    ctx.max_request := 1  shl  16;
    Result := 1;
end;

function drbg_hash_uninstantiate( drbg : PPROV_DRBG):integer;
var
  hash : PPROV_DRBG_HASH;
begin
    hash := PPROV_DRBG_HASH ( drbg.data);
    OPENSSL_cleanse(@hash.V, sizeof(hash.V));
    OPENSSL_cleanse(@hash.C, sizeof(hash.C));
    OPENSSL_cleanse(@hash.vtmp, sizeof(hash.vtmp));
    Result := ossl_prov_drbg_uninstantiate(drbg);
end;

function PROV_DRBG_VERYIFY_ZEROIZATION( v : PByte):integer;
var
  i : size_t;
begin
    for i := 0 to SizeOf(v)-1 do
        if v[i] <> 0 then Exit(0);
end;




function drbg_hash_verify_zeroization( vdrbg : Pointer):integer;
var
  drbg : PPROV_DRBG;
  hash : PPROV_DRBG_HASH;
begin
    drbg := PPROV_DRBG ( vdrbg);
    hash := PPROV_DRBG_HASH ( drbg.data);
    PROV_DRBG_VERYIFY_ZEROIZATION(@hash.V);
    PROV_DRBG_VERYIFY_ZEROIZATION(@hash.C);
    PROV_DRBG_VERYIFY_ZEROIZATION(@hash.vtmp);
    Result := 1;
end;

function drbg_hash_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;

  hash : PPROV_DRBG_HASH;
  md: PEVP_MD;
  p : POSSL_PARAM;
begin
    drbg := PPROV_DRBG ( vdrbg);
    hash := PPROV_DRBG_HASH ( drbg.data);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_DIGEST);
    if p <> nil then
    begin
        md := ossl_prov_digest_md(@hash.digest);
        if (md = nil)  or
           (0>= OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(md )) ) then
            Exit(0);
    end;
    Result := ossl_drbg_get_ctx_params(drbg, params);
end;


function drbg_hash_gettable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, nil, 0);
    known_gettable_ctx_params[1] := _OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nil);
    known_gettable_ctx_params[2] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_gettable_ctx_params[3] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil);
    known_gettable_ctx_params[4] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, nil);
    known_gettable_ctx_params[5] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, nil);
    known_gettable_ctx_params[6] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, nil);
    known_gettable_ctx_params[7] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, nil);
    known_gettable_ctx_params[8] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, nil);
    known_gettable_ctx_params[9] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, nil);
    known_gettable_ctx_params[10] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, nil);
    known_gettable_ctx_params[11] := _OSSL_PARAM_time_t(OSSL_DRBG_PARAM_RESEED_TIME, nil);
    known_gettable_ctx_params[12] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, nil);
    known_gettable_ctx_params[13] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_gettable_ctx_params[14] := OSSL_PARAM_END ;

    Result := @known_gettable_ctx_params;
end;




function drbg_hash_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_DRBG;

  hash : PPROV_DRBG_HASH;
  md: PEVP_MD;
  libctx : POSSL_LIB_CTX;
begin
    ctx := PPROV_DRBG ( vctx);
    hash := PPROV_DRBG_HASH ( ctx.data);
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if 0>= ossl_prov_digest_load_from_params(@hash.digest, params, libctx )then
        Exit(0);
    md := ossl_prov_digest_md(@hash.digest);
    if md <> nil then
    begin
        if (EVP_MD_get_flags(md) and EVP_MD_FLAG_XOF) <> 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED);
            Exit(0);
        end;
        { These are taken from SP 800-90 10.1 Table 2 }
        hash.blocklen := EVP_MD_get_size(md);
        { See SP800-57 Part1 Rev4 5.6.1 Table 3 }
        ctx.strength := 64 * (hash.blocklen  shr  3);
        if ctx.strength > 256 then ctx.strength := 256;
        if hash.blocklen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN then
           ctx.seedlen := HASH_PRNG_MAX_SEEDLEN
        else
            ctx.seedlen := HASH_PRNG_SMALL_SEEDLEN;
        ctx.min_entropylen := ctx.strength div 8;
        ctx.min_noncelen := ctx.min_entropylen div 2;
    end;
    Result := ossl_drbg_set_ctx_params(ctx, params);
end;


function drbg_hash_settable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,nil);
    known_settable_ctx_params[3] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_settable_ctx_params[4] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;




function drbg_hash_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    Exit(ossl_prov_drbg_reseed(drbg, prediction_resistance, ent, ent_len,
                                 adin, adin_len));
end;




function drbg_hash_generate_wrapper(vdrbg : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    Exit(ossl_prov_drbg_generate(drbg, _out, outlen, strength,
                                   prediction_resistance, adin, adin_len) );
end;


function drbg_hash_uninstantiate_wrapper( vdrbg : Pointer):integer;
begin
    Result := drbg_hash_uninstantiate(PPROV_DRBG ( vdrbg));
end;

function drbg_hash_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG(vdrbg);
    if (not ossl_prov_is_running)  or
       (0>= drbg_hash_set_ctx_params(drbg, params))then
        Exit(0);
    Exit(ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance,
                                      pstr, pstr_len));
end;




procedure drbg_hash_free( vdrbg : Pointer);
var
  drbg : PPROV_DRBG;

  hash : PPROV_DRBG_HASH;
begin
    drbg := PPROV_DRBG  (vdrbg);
    hash := PPROV_DRBG_HASH(drbg.data);
    if (drbg <> nil)  and  (hash <> nil)  then
    begin
        EVP_MD_CTX_free(hash.ctx);
        ossl_prov_digest_reset(@hash.digest);
        OPENSSL_secure_clear_free(hash, sizeof( hash^));
    end;
    ossl_rand_drbg_free(drbg);
end;




function drbg_hash_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
begin
    Exit(ossl_rand_drbg_new(provctx, parent, parent_dispatch, @drbg_hash_new,
                              @drbg_hash_instantiate, @drbg_hash_uninstantiate,
                              @drbg_hash_reseed, @drbg_hash_generate));
end;






end.
