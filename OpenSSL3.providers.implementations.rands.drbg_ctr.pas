unit OpenSSL3.providers.implementations.rands.drbg_ctr;

interface
uses
   OpenSSL.Api, OpenSSL3.providers.implementations.rands.drbg;

function drbg_ctr_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
procedure drbg_ctr_free( vdrbg : Pointer);
function drbg_ctr_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
function drbg_ctr_uninstantiate_wrapper( vdrbg : Pointer):integer;
function drbg_ctr_generate_wrapper(vdrbg : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
function drbg_ctr_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
function drbg_ctr_settable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
function drbg_ctr_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function drbg_ctr_gettable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
function drbg_ctr_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
function drbg_ctr_verify_zeroization( vdrbg : Pointer):integer;
function drbg_ctr_init( drbg : PPROV_DRBG):integer;
function drbg_ctr_init_lengths( drbg : PPROV_DRBG):integer;
function drbg_ctr_uninstantiate( drbg : PPROV_DRBG):integer;
function drbg_ctr_new( drbg : PPROV_DRBG):integer;
function drbg_ctr_instantiate(drbg : PPROV_DRBG;const entropy : PByte; entropylen : size_t;const nonce : PByte; noncelen : size_t;const pers : PByte; perslen : size_t):int;
procedure inc_128( ctr : PPROV_DRBG_CTR);
function ctr_update(drbg : PPROV_DRBG;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const nonce : PByte; noncelen : size_t):integer;
function ctr_df(ctr : PPROV_DRBG_CTR;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
function ctr_BCC_update(ctr : PPROV_DRBG_CTR; _in : PByte; inlen : size_t):integer;
function ctr_BCC_blocks(ctr : PPROV_DRBG_CTR;const _in : PByte):integer;
function ctr_BCC_block(ctr : PPROV_DRBG_CTR; _out : PByte;const _in : PByte; len : integer):integer;
function ctr_BCC_init( ctr : PPROV_DRBG_CTR):integer;

const
    ossl_drbg_ctr_functions: array[0..16] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_RAND_NEWCTX; method:(code:@drbg_ctr_new_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_FREECTX; method:(code:@drbg_ctr_free ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_INSTANTIATE;  method:(code:@drbg_ctr_instantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNINSTANTIATE; method:(code:@drbg_ctr_uninstantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GENERATE; method:(code:@drbg_ctr_generate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_RESEED; method:(code:@drbg_ctr_reseed_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_ENABLE_LOCKING; method:(code:@ossl_drbg_enable_locking ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_LOCK; method:(code:@ossl_drbg_lock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNLOCK; method:(code:@ossl_drbg_unlock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS; method:(code:@drbg_ctr_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS; method:(code:@drbg_ctr_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS; method:(code:@drbg_ctr_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS; method:(code:@drbg_ctr_get_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION; method:(code:@drbg_ctr_verify_zeroization ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_SEED; method:(code:@ossl_drbg_get_seed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_CLEAR_SEED; method:(code:@ossl_drbg_clear_seed ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);

function ctr_BCC_final( ctr : PPROV_DRBG_CTR):integer;
procedure ctr_XOR(ctr : PPROV_DRBG_CTR;const _in : PByte; inlen : size_t);
function drbg_ctr_reseed(drbg : PPROV_DRBG;const entropy : PByte; entropylen : size_t;const adin : PByte; adinlen : size_t):int;
function drbg_ctr_generate(drbg : PPROV_DRBG; _out : PByte; outlen : size_t; adin : PByte; adinlen : size_t):integer;
procedure ctr96_inc( counter : PByte);
procedure PUTU32( p : PByte; v : uint32);


var// 1d arrays
  known_settable_ctx_params : array[0..5] of TOSSL_PARAM ;
 // 1d arrays
  known_gettable_ctx_params : array[0..15] of TOSSL_PARAM ;

implementation

uses openssl3.crypto.params,                   openssl3.crypto.evp.evp_lib,
     OpenSSL3.openssl.params,                  OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.o_str,      openssl3.crypto.evp.evp_enc,
     openssl3.crypto.mem,                      openssl3.providers.prov_running,
     openssl3.crypto.mem_sec;


procedure PUTU32( p : PByte; v : uint32);
begin
   p[0] := uint8((v) shr 24);
   p[1] := uint8((v) shr 16);
   p[2] := uint8((v) shr 8);
   p[3] := uint8(v)
end;

procedure ctr96_inc( counter : PByte);
var
  n, c : uint32;
begin
    n := 12; c := 1;
    repeat
        Dec(n);
        c  := c + (counter[n]);
        counter[n] := uint8(c);
        c  := c shr 8;
    until not Boolean(n);
end;

function drbg_ctr_generate(drbg : PPROV_DRBG; _out : PByte; outlen : size_t;
                           adin : PByte; adinlen : size_t):integer;
var
  ctr : PPROV_DRBG_CTR;
  ctr32, blocks : uint32;
  outl, buflen : integer;
begin
    ctr := PPROV_DRBG_CTR(drbg.data);
    if (adin <> nil)  and  (adinlen <> 0) then
    begin
        inc_128(ctr);
        if 0>= ctr_update(drbg, adin, adinlen, nil, 0, nil, 0  ) then
            Exit(0);
        { This means we reuse derived value }
        if ctr.use_df >0 then
        begin
            adin := nil;
            adinlen := 1;
        end;
    end
    else
    begin
        adinlen := 0;
    end;
    inc_128(ctr);
    if outlen = 0 then begin
        inc_128(ctr);
        if 0>= ctr_update(drbg, adin, adinlen, nil, 0, nil, 0 ) then
            Exit(0);
        Exit(1);
    end;
    memset(_out, 0, outlen);
    repeat
        if 0>= EVP_CipherInit_ex(ctr.ctx_ctr,
                               nil, nil, nil, @ctr.V, -1 ) then
            Exit(0);
        {-
         * outlen has type size_t while EVP_CipherUpdate takes an
         * int argument and thus cannot be guaranteed to process more
         * than 2^31-1 bytes at a time. We process such huge generate
         * requests in 2^30 byte chunks, which is the greatest multiple
         * of AES block size lower than or equal to 2^31-1.
         }
        if outlen > (uint32(1)  shl  30) then
           buflen :=  (uint32(1)  shl  30)
        else
           buflen := outlen;
        blocks := (buflen + 15) div 16;
        ctr32 := GETU32(PByte(@ctr.V) + 12) + blocks;
        if ctr32 < blocks then
        begin
            { 32-bit counter overflow into V. }
            if ctr32 <> 0 then
            begin
                blocks  := blocks - ctr32;
                buflen := blocks * 16;
                ctr32 := 0;
            end;
            ctr96_inc(@ctr.V);
        end;
        PUTU32(PByte(@ctr.V) + 12, ctr32);
        if (0>= EVP_CipherUpdate(ctr.ctx_ctr, _out, @outl, _out, buflen) ) or
           (outl <> buflen) then
            Exit(0);
        _out  := _out + buflen;
        outlen  := outlen - buflen;
    until not Boolean(outlen);
    if 0>= ctr_update(drbg, adin, adinlen, nil, 0, nil, 0 ) then
        Exit(0);
    Result := 1;
end;

function drbg_ctr_reseed(drbg : PPROV_DRBG;const entropy : PByte;
                         entropylen : size_t;const adin : PByte;
                         adinlen : size_t):int;
var
  ctr : PPROV_DRBG_CTR;
begin
    ctr := PPROV_DRBG_CTR ( drbg.data);
    if entropy = nil then Exit(0);
    inc_128(ctr);
    if  0>= ctr_update(drbg, entropy, entropylen, adin, adinlen, nil, 0 )then
        Exit(0);
    Result := 1;
end;

procedure ctr_XOR(ctr : PPROV_DRBG_CTR;const _in : PByte; inlen : size_t);
var
  i, n : size_t;
begin
    if (_in = nil)  or  (inlen = 0) then exit;
    {
     * Any zero padding will have no effect on the result as we
     * are XORing. So just process however much input we have.
     }
    n := get_result(inlen < ctr.keylen , inlen , ctr.keylen);
    for i := 0 to n-1 do
        ctr.K[i]  := ctr.K[i] xor (_in[i]);
    if inlen <= ctr.keylen then exit;
    n := inlen - ctr.keylen;
    if n > 16 then
    begin
        { Should never happen }
        n := 16;
    end;
    for i := 0 to n-1 do
        ctr.V[i]  := ctr.V[i] xor (_in[i + ctr.keylen]);
end;

function ctr_BCC_final( ctr : PPROV_DRBG_CTR):integer;
begin
    if ctr.bltmp_pos > 0 then
    begin
        memset(PByte(@ctr.bltmp) + ctr.bltmp_pos, 0, 16 - ctr.bltmp_pos);
        if  0>= ctr_BCC_blocks(ctr, @ctr.bltmp) then
            Exit(0);
    end;
    Result := 1;
end;

function ctr_BCC_init( ctr : PPROV_DRBG_CTR):integer;
var
    bltmp      : array[0..47] of Byte;
    num_of_blk : Byte;
begin
    FillChar(bltmp, 48, 0);
    memset(@ctr.KX, 0, 48);
    num_of_blk := get_result(ctr.keylen = 16 , 2 , 3);
    bltmp[(AES_BLOCK_SIZE * 1) + 3] := 1;
    bltmp[(AES_BLOCK_SIZE * 2) + 3] := 2;
    Result := ctr_BCC_block(ctr, @ctr.KX, @bltmp, num_of_blk * AES_BLOCK_SIZE);
end;

function ctr_BCC_block(ctr : PPROV_DRBG_CTR; _out : PByte;const _in : PByte; len : integer):integer;
var
  i, outlen : integer;
begin
    outlen := AES_BLOCK_SIZE;
    for i := 0 to len-1 do
        _out[i]  := _out[i] xor (_in[i]);
    if  (0>= EVP_CipherUpdate(ctr.ctx_df, _out, @outlen, _out, len))  or
        (outlen <> len) then
        Exit(0);
    Result := 1;
end;


function ctr_BCC_blocks(ctr : PPROV_DRBG_CTR;const _in : PByte):integer;
var
    in_tmp     : array[0..47] of Byte;
    num_of_blk : Byte;
begin
    num_of_blk := 2;
    memcpy(@in_tmp, _in, 16);
    memcpy(PByte(@in_tmp) + 16, _in, 16);
    if ctr.keylen <> 16 then
    begin
        memcpy(PByte(@in_tmp) + 32, _in, 16);
        num_of_blk := 3;
    end;
    Result := ctr_BCC_block(ctr, @ctr.KX, @in_tmp, AES_BLOCK_SIZE * num_of_blk);
end;

function ctr_BCC_update(ctr : PPROV_DRBG_CTR; _in : PByte; inlen : size_t):integer;
var
  left : size_t;
begin
    if (_in = nil)  or  (inlen = 0) then Exit(1);
    { If we have partial block handle it first }
    if ctr.bltmp_pos >0 then
    begin
        left := 16 - ctr.bltmp_pos;
        { If we now have a complete block process it }
        if inlen >= left then
        begin
            memcpy(PByte(@ctr.bltmp) + ctr.bltmp_pos, _in, left);
            if  0>= ctr_BCC_blocks(ctr, @ctr.bltmp)  then
                Exit(0);
            ctr.bltmp_pos := 0;
            inlen  := inlen - left;
            _in  := _in + left;
        end;
    end;
    { Process zero or more complete blocks }
    while inlen >= 16 do
    begin
        if  0>= ctr_BCC_blocks(ctr, _in) then
            Exit(0);
        _in := _in + 16;
        inlen := inlen - 16;
    end;
    { Copy any remaining partial block to the temporary buffer }
    if inlen > 0 then
    begin
        memcpy(PByte(@ctr.bltmp) + ctr.bltmp_pos, _in, inlen);
        ctr.bltmp_pos  := ctr.bltmp_pos + inlen;
    end;
    Result := 1;
end;

var
  c80:Byte  = $80;
function ctr_df(ctr : PPROV_DRBG_CTR;const in1 : PByte; in1len : size_t;
                const in2 : PByte; in2len : size_t;const in3 : PByte;
                in3len : size_t):integer;
var
  inlen : size_t;
  p : PByte;
  outlen : integer;
begin
    p := @ctr.bltmp;
    outlen := AES_BLOCK_SIZE;
    if 0>= ctr_BCC_init(ctr)  then
        Exit(0);
    if in1 = nil then in1len := 0;
    if in2 = nil then in2len := 0;
    if in3 = nil then in3len := 0;
    inlen := in1len + in2len + in3len;
    { Initialise L or N in temporary block }
    p^ :=  ((inlen  shr  24) and $ff); Inc(p);
    p^ :=  ((inlen  shr  16) and $ff); Inc(p);
    p^ :=  ((inlen  shr  8) and $ff); Inc(p);
    p^ :=  (inlen and $ff); Inc(p);
    { NB keylen is at most 32 bytes }
    p^ :=  0; Inc(p);
    p^ :=  0; Inc(p);
    p^ :=  0; Inc(p);
    p^ := Byte ((ctr.keylen + 16) and $ff);
    ctr.bltmp_pos := 8;
    if (0>= ctr_BCC_update(ctr, in1, in1len))  or
       (0>= ctr_BCC_update(ctr, in2, in2len))  or
       (0>= ctr_BCC_update(ctr, in3, in3len))  or
       (0>= ctr_BCC_update(ctr, @c80, 1)) or
       (0>= ctr_BCC_final(ctr)) then
        Exit(0);
    { Set up key K }
    if 0>= EVP_CipherInit_ex(ctr.ctx_ecb, nil, nil, @ctr.KX, nil, -1)  then
        Exit(0);
    { X follows key K }
    if (0>= EVP_CipherUpdate(ctr.ctx_ecb, @ctr.KX, @outlen, PByte(@ctr.KX) + ctr.keylen,
                          AES_BLOCK_SIZE)) or  (outlen <> AES_BLOCK_SIZE)  then
        Exit(0);
    if (0>= EVP_CipherUpdate(ctr.ctx_ecb, PByte(@ctr.KX) + 16, @outlen, @ctr.KX,
                          AES_BLOCK_SIZE))  or  (outlen <> AES_BLOCK_SIZE)  then
        Exit(0);
    if ctr.keylen <> 16 then
       if (0>= EVP_CipherUpdate(ctr.ctx_ecb, PByte(@ctr.KX) + 32, @outlen,
                              PByte(@ctr.KX) + 16, AES_BLOCK_SIZE))
             or  (outlen <> AES_BLOCK_SIZE) then
            Exit(0);
    Result := 1;
end;

function ctr_update(drbg : PPROV_DRBG;const in1 : PByte; in1len : size_t;
                    const in2 : PByte; in2len : size_t;const nonce : PByte;
                    noncelen : size_t):integer;
var
  ctr : PPROV_DRBG_CTR;
  outlen : integer;
  V_tmp, _out: array[0..47] of Byte;
  len : Byte;
begin
    FillChar(V_tmp, SizeOf(V_tmp), 0);
    FillChar(_out, SizeOf(_out), 0);
    ctr := PPROV_DRBG_CTR ( drbg.data);
    outlen := AES_BLOCK_SIZE;

    { correct key is already set up. }
    memcpy(@V_tmp, @ctr.V, 16);
    inc_128(ctr);
    memcpy(PByte(@V_tmp) + 16, @ctr.V, 16);
    if ctr.keylen = 16 then
    begin
        len := 32;
    end
    else
    begin
        inc_128(ctr);
        memcpy(PByte(@V_tmp) + 32, @ctr.V, 16);
        len := 48;
    end;
    if  (0>= EVP_CipherUpdate(ctr.ctx_ecb, @_out, @outlen, @V_tmp, len)) or
        (outlen <> len) then
        Exit(0);
    memcpy(@ctr.K, @_out, ctr.keylen);
    memcpy(@ctr.V, PByte(@_out) + ctr.keylen, 16);
    if ctr.use_df>0 then
    begin
        { If no input reuse existing derived value }
        if (in1 <> nil)  or  (nonce <> nil)  or  (in2 <> nil) then
            if (0>= ctr_df(ctr, in1, in1len, nonce, noncelen, in2, in2len)) then
                Exit(0);
        { If this a reuse input in1len <> 0 }
        if in1len>0 then
           ctr_XOR(ctr, @ctr.KX, drbg.seedlen);
    end
    else
    begin
        ctr_XOR(ctr, in1, in1len);
        ctr_XOR(ctr, in2, in2len);
    end;
    if  (0>= EVP_CipherInit_ex(ctr.ctx_ecb, nil, nil, @ctr.K, nil, -1)) or
        (0>= EVP_CipherInit_ex(ctr.ctx_ctr, nil, nil, @ctr.K, nil, -1))  then
        Exit(0);
    Result := 1;
end;

procedure inc_128( ctr : PPROV_DRBG_CTR);
var
  p : PByte;
  n ,c: uint32;
begin
    p := @ctr.V[0];
    n := 16; c := 1;
    repeat
        Dec(n);
        c  := c + (p[n]);
        p[n] := Byte(c);
        c  := c shr 8;
    until (n = 0);
end;

function drbg_ctr_instantiate(drbg : PPROV_DRBG;const entropy : PByte;
                              entropylen : size_t;const nonce : PByte;
                              noncelen : size_t;const pers : PByte;
                              perslen : size_t):int;
var
  ctr : PPROV_DRBG_CTR;
begin
    ctr := PPROV_DRBG_CTR ( drbg.data);
    if entropy = nil then Exit(0);
    memset(@ctr.K, 0, sizeof(ctr.K));
    memset(@ctr.V, 0, sizeof(ctr.V));
    if  0>= EVP_CipherInit_ex(ctr.ctx_ecb, nil, nil, @ctr.K, nil, -1  )then
        Exit(0);
    inc_128(ctr);
    if  0>= ctr_update(drbg, entropy, entropylen, pers, perslen, nonce, noncelen) then
        Exit(0);
    Result := 1;
end;

function drbg_ctr_new( drbg : PPROV_DRBG):integer;
var
  ctr : PPROV_DRBG_CTR;
begin
    ctr := OPENSSL_secure_zalloc(sizeof( ctr^));
    if ctr = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ctr.use_df := 1;
    drbg.data := ctr;
    Result := drbg_ctr_init_lengths(drbg);
end;

function drbg_ctr_uninstantiate( drbg : PPROV_DRBG):integer;
var
  ctr : PPROV_DRBG_CTR;
begin
    ctr := PPROV_DRBG_CTR ( drbg.data);
    OPENSSL_cleanse(@ctr.K, sizeof(ctr.K));
    OPENSSL_cleanse(@ctr.V, sizeof(ctr.V));
    OPENSSL_cleanse(@ctr.bltmp, sizeof(ctr.bltmp));
    OPENSSL_cleanse(@ctr.KX, sizeof(ctr.KX));
    ctr.bltmp_pos := 0;
    Result := ossl_prov_drbg_uninstantiate(drbg);
end;

function drbg_ctr_init_lengths( drbg : PPROV_DRBG):integer;
var
  ctr : PPROV_DRBG_CTR;
  res : integer;
  len : size_t;
begin
    ctr := PPROV_DRBG_CTR  (drbg.data);
    res := 1;
    { Maximum number of bits per request = 2^19  = 2^16 bytes }
    drbg.max_request := 1  shl  16;
    if ctr.use_df>0 then
    begin
        drbg.min_entropylen := 0;
        drbg.max_entropylen := DRBG_MAX_LENGTH;
        drbg.min_noncelen := 0;
        drbg.max_noncelen := DRBG_MAX_LENGTH;
        drbg.max_perslen := DRBG_MAX_LENGTH;
        drbg.max_adinlen := DRBG_MAX_LENGTH;
        if ctr.keylen > 0 then
        begin
            drbg.min_entropylen := ctr.keylen;
            drbg.min_noncelen := drbg.min_entropylen div 2;
        end;
    end
    else
    begin
        if ctr.keylen > 0 then
           len := drbg.seedlen
        else
           len := DRBG_MAX_LENGTH;
        drbg.min_entropylen := len;
        drbg.max_entropylen := len;
        { Nonce not used }
        drbg.min_noncelen := 0;
        drbg.max_noncelen := 0;
        drbg.max_perslen := len;
        drbg.max_adinlen := len;
    end;
    Result := res;
end;

function drbg_ctr_init( drbg : PPROV_DRBG):integer;
var
  ctr : PPROV_DRBG_CTR;
  keylen : size_t;
const // 1d arrays
  df_key : array[0..31] of Byte = (
    $00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $0a, $0b, $0c, $0d,
    $0e, $0f, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $1a, $1b,
    $1c, $1d, $1e, $1f );
label _err;
begin
    ctr := PPROV_DRBG_CTR  (drbg.data);
    if ctr.cipher_ctr = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        Exit(0);
    end;
    keylen := EVP_CIPHER_get_key_length(ctr.cipher_ctr);
    ctr.keylen := keylen;
    if ctr.ctx_ecb = nil then
       ctr.ctx_ecb := EVP_CIPHER_CTX_new();
    if ctr.ctx_ctr = nil then
       ctr.ctx_ctr := EVP_CIPHER_CTX_new();
    if (ctr.ctx_ecb = nil)  or  (ctr.ctx_ctr = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if  (0>= EVP_CipherInit_ex(ctr.ctx_ecb,
                           ctr.cipher_ecb, nil, nil, nil, 1))  or
        (0>= EVP_CipherInit_ex(ctr.ctx_ctr,
                              ctr.cipher_ctr, nil, nil, nil, 1)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_INITIALISE_CIPHERS);
        goto _err ;
    end;
    drbg.strength := keylen * 8;
    drbg.seedlen := keylen + 16;
    if ctr.use_df >0 then
    begin
        { df initialisation }

        if ctr.ctx_df = nil then
           ctr.ctx_df := EVP_CIPHER_CTX_new();
        if ctr.ctx_df = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        { Set key schedule for df_key }
        if  0>= EVP_CipherInit_ex(ctr.ctx_df,
                               ctr.cipher_ecb, nil, @df_key, nil, 1 )then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_DERIVATION_FUNCTION_INIT_FAILED);
            goto _err ;
        end;
    end;
    Exit(drbg_ctr_init_lengths(drbg));
_err:
    EVP_CIPHER_CTX_free(ctr.ctx_ecb);
    EVP_CIPHER_CTX_free(ctr.ctx_ctr);
    ctr.ctx_ecb := nil;
    ctr.ctx_ctr := nil;
    Exit(0);
end;

function drbg_ctr_verify_zeroization( vdrbg : Pointer):integer;
var
  drbg : PPROV_DRBG;
  ctr : PPROV_DRBG_CTR;
begin
    drbg := PPROV_DRBG ( vdrbg);
    ctr := PPROV_DRBG_CTR  (drbg.data);
    PROV_DRBG_VERYIFY_ZEROIZATION(@ctr.K);
    PROV_DRBG_VERYIFY_ZEROIZATION(@ctr.V);
    PROV_DRBG_VERYIFY_ZEROIZATION(@ctr.bltmp);
    PROV_DRBG_VERYIFY_ZEROIZATION(@ctr.KX);
    if ctr.bltmp_pos <> 0 then Exit(0);
    Result := 1;
end;


function drbg_ctr_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;
  ctr : PPROV_DRBG_CTR;
  p : POSSL_PARAM;
begin
    drbg := PPROV_DRBG ( vdrbg);
    ctr := PPROV_DRBG_CTR(drbg.data);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_USE_DF);
    if (p <> nil)  and   (0>= OSSL_PARAM_set_int(p, ctr.use_df) )  then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_CIPHER);
    if p <> nil then
    begin
        if (ctr.cipher_ctr = nil) or
           (0>= OSSL_PARAM_set_utf8_string(p, EVP_CIPHER_get0_name(ctr.cipher_ctr))) then
            Exit(0);
    end;
    Result := ossl_drbg_get_ctx_params(drbg, params);
end;

function drbg_ctr_gettable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, nil, 0);
    known_gettable_ctx_params[1] := _OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, nil);
    known_gettable_ctx_params[2] := _OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nil);
    known_gettable_ctx_params[3] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_gettable_ctx_params[4] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil);
    known_gettable_ctx_params[5] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, nil);
    known_gettable_ctx_params[6] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, nil);
    known_gettable_ctx_params[7] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, nil);
    known_gettable_ctx_params[8] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, nil);
    known_gettable_ctx_params[9] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, nil);
    known_gettable_ctx_params[10] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, nil);
    known_gettable_ctx_params[11] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, nil);
    known_gettable_ctx_params[12] := _OSSL_PARAM_time_t(OSSL_DRBG_PARAM_RESEED_TIME, nil);
    known_gettable_ctx_params[13] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, nil);
    known_gettable_ctx_params[14] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_gettable_ctx_params[15] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;

function drbg_ctr_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx         : PPROV_DRBG;
  p           : POSSL_PARAM;
  ctr         : PPROV_DRBG_CTR;
  libctx      : POSSL_LIB_CTX;
  ecb,
  propquery   : PUTF8Char;
  i,
  cipher_init : integer;
  base        : PUTF8Char;
  ctr_str_len,
  ecb_str_len : size_t;
begin
    ctx := PPROV_DRBG ( vctx);
    ctr := PPROV_DRBG_CTR(ctx.data);
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    propquery := nil;
    cipher_init := 0;
    p := OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_USE_DF );
    if (p  <> nil) and  (OSSL_PARAM_get_int(p, @i) > 0) then
    begin
        { FIPS errors out in the drbg_ctr_init() call later }
        ctr.use_df := Int(i <> 0);
        cipher_init := 1;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_PROPERTIES ) ;
    if (p <> nil)then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        propquery := PUTF8Char (p.data);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_CIPHER );
    if p <> nil then
    begin
        base := PUTF8Char (p.data);
        ctr_str_len := Strsize(PUTF8Char('CTR')) - 1;
        ecb_str_len := Strsize(PUTF8Char('ECB')) - 1;
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
                 or  (p.data_size < ctr_str_len) then
           Exit(0);
        if strcasecmp('CTR', base + p.data_size - ctr_str_len)  <> 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_REQUIRE_CTR_MODE_CIPHER);
            Exit(0);
        end;
        OPENSSL_strndup(ecb, base, p.data_size );
        if ecb = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        strcpy(ecb + p.data_size - ecb_str_len , 'ECB');
        EVP_CIPHER_free(ctr.cipher_ecb);
        EVP_CIPHER_free(ctr.cipher_ctr);
        ctr.cipher_ctr := EVP_CIPHER_fetch(libctx, base, propquery);
        ctr.cipher_ecb := EVP_CIPHER_fetch(libctx, ecb, propquery);
        OPENSSL_free(ecb);
        if (ctr.cipher_ctr = nil)  or  (ctr.cipher_ecb = nil) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_FIND_CIPHERS);
            Exit(0);
        end;
        cipher_init := 1;
    end;
    if (cipher_init > 0) and   (0>= drbg_ctr_init(ctx))  then
        Exit(0);
    Result := ossl_drbg_set_ctx_params(ctx, params);
end;



function drbg_ctr_settable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, nil);
    known_settable_ctx_params[3] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, nil);
    known_settable_ctx_params[4] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_settable_ctx_params[5] := OSSL_PARAM_END ;

    Result := @known_settable_ctx_params;
end;

function drbg_ctr_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;
                                 const ent : PByte; ent_len : size_t;
                                 const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG (vdrbg);
    Exit(ossl_prov_drbg_reseed(drbg, prediction_resistance, ent, ent_len,
                                 adin, adin_len));
end;

function drbg_ctr_generate_wrapper(vdrbg : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG (vdrbg);
    Result := ossl_prov_drbg_generate(drbg, _out, outlen, strength,
                                      prediction_resistance, adin, adin_len);
end;

function drbg_ctr_uninstantiate_wrapper( vdrbg : Pointer):integer;
begin
    Result := drbg_ctr_uninstantiate(PPROV_DRBG ( vdrbg));
end;

function drbg_ctr_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    if  (not ossl_prov_is_running) or
       (0>= drbg_ctr_set_ctx_params(drbg, params)) then
        Exit(0);
    Exit(ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance,
                                      pstr, pstr_len));
end;

procedure drbg_ctr_free( vdrbg : Pointer);
var
  drbg : PPROV_DRBG;
  ctr : PPROV_DRBG_CTR;
begin
    drbg := PPROV_DRBG ( vdrbg);
    ctr := PPROV_DRBG_CTR(drbg.data);
    if (drbg <> nil)  and  (ctr <> nil)    then
    begin
        EVP_CIPHER_CTX_free(ctr.ctx_ecb);
        EVP_CIPHER_CTX_free(ctr.ctx_ctr);
        EVP_CIPHER_CTX_free(ctr.ctx_df);
        EVP_CIPHER_free(ctr.cipher_ecb);
        EVP_CIPHER_free(ctr.cipher_ctr);
        OPENSSL_secure_clear_free(ctr, sizeof( ctr^));
    end;
    ossl_rand_drbg_free(drbg);
end;

function drbg_ctr_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
begin
    Result := ossl_rand_drbg_new(provctx, parent, parent_dispatch, @drbg_ctr_new,
                                  @drbg_ctr_instantiate, @drbg_ctr_uninstantiate,
                                  @drbg_ctr_reseed, @drbg_ctr_generate);
end;


end.
