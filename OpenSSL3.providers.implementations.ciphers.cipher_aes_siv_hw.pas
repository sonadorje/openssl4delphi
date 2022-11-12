unit OpenSSL3.providers.implementations.ciphers.cipher_aes_siv_hw;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

function aes_siv_initkey(vctx : Pointer;const key : PByte; keylen : size_t):integer;
  function aes_siv_dupctx( in_vctx, out_vctx : Pointer):integer;
  function aes_siv_settag(vctx : Pointer;const tag : PByte; tagl : size_t):integer;
  procedure aes_siv_setspeed( vctx : Pointer; speed : integer);
  procedure aes_siv_cleanup( vctx : Pointer);
  function aes_siv_cipher(vctx : Pointer; _out : PByte;const _in : PByte; len : size_t):integer;
  function ossl_prov_cipher_hw_aes_siv( keybits : size_t):PPROV_CIPHER_HW_AES_SIV;
  function siv128_do_encrypt(ctx : PEVP_CIPHER_CTX; _out : PByte;const _in : PByte; len : size_t; icv : PSIV_BLOCK):integer;
  function ossl_siv128_decrypt(ctx : PSIV128_CONTEXT;const _in : PByte; _out : PByte; len : size_t):integer;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     openssl3.crypto.params_from_text,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.siv128,
     openssl3.crypto.aes.aes_core, openssl3.crypto.aes.aes_cbc,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw,
     openssl3.crypto.evp.ctrl_params_translate;

const aes_siv_hw: TPROV_CIPHER_HW_AES_SIV  =
(
    initkey:aes_siv_initkey;
    cipher:aes_siv_cipher;
    setspeed:aes_siv_setspeed;
    settag:aes_siv_settag;
    cleanup:aes_siv_cleanup;
    dupctx:aes_siv_dupctx;
);



function ossl_siv128_decrypt(ctx : PSIV128_CONTEXT;const _in : PByte; _out : PByte; len : size_t):integer;
var
  t, q : TSIV_BLOCK;
  p: PByte;
  i : integer;
begin

    { can only do one crypto operation }
    if ctx.crypto_ok = 0 then Exit(0);
    Dec(ctx.crypto_ok);
    memcpy(@q, @ctx.tag.byte, SIV_LEN);
    q.byte[8] := q.byte[8] and $7f;
    q.byte[12] := q.byte[12] and $7f;
    if (0>= siv128_do_encrypt(ctx.cipher_ctx, _out, _in, len, @q))  or
       (0>= siv128_do_s2v_p(ctx, @t, _out, len)) then
        Exit(0);
    p := @ctx.tag.byte;
    for i := 0 to SIV_LEN-1 do
        t.byte[i]  := t.byte[i] xor (p[i]);
    if (t.word[0]>0) or (t.word[1] <> 0) then
    begin
        OPENSSL_cleanse(_out, len);
        Exit(0);
    end;
    ctx.final_ret := 0;
    Result := len;
end;

function siv128_do_encrypt(ctx : PEVP_CIPHER_CTX; _out : PByte;const _in : PByte; len : size_t; icv : PSIV_BLOCK):integer;
var
  out_len : integer;
begin
    out_len := int (len);

    if 0>= EVP_CipherInit_ex(ctx, nil, nil, nil, @icv.byte, 1) then
        Exit(0);
    Result := EVP_EncryptUpdate(ctx, _out, @out_len, _in, out_len);
end;


function aes_siv_initkey(vctx : Pointer;const key : PByte; keylen : size_t):integer;
var
  ctx : PPROV_AES_SIV_CTX;

  sctx : PSIV128_CONTEXT;

  klen : size_t;

  libctx : POSSL_LIB_CTX;

  propq : PUTF8Char;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    sctx := @ctx.siv;
    klen := keylen div 2;
    libctx := ctx.libctx;
    propq := nil;
    EVP_CIPHER_free(ctx.cbc);
    EVP_CIPHER_free(ctx.ctr);
    ctx.cbc := nil;
    ctx.ctr := nil;
    case klen of
    16:
    begin
        ctx.cbc := EVP_CIPHER_fetch(libctx, 'AES-128-CBC', propq);
        ctx.ctr := EVP_CIPHER_fetch(libctx, 'AES-128-CTR', propq);
    end;
    24:
    begin
        ctx.cbc := EVP_CIPHER_fetch(libctx, 'AES-192-CBC', propq);
        ctx.ctr := EVP_CIPHER_fetch(libctx, 'AES-192-CTR', propq);
    end;
    32:
    begin
        ctx.cbc := EVP_CIPHER_fetch(libctx, 'AES-256-CBC', propq);
        ctx.ctr := EVP_CIPHER_fetch(libctx, 'AES-256-CTR', propq);
    end;
    //else
      //  break;
    end;
    if (ctx.cbc = nil)  or  (ctx.ctr = nil) then Exit(0);
    {
     * klen is the length of the underlying cipher, not the input key,
     * which should be twice as long
     }
    Exit(ossl_siv128_init(sctx, key, klen, ctx.cbc, ctx.ctr, libctx,
                              propq));
end;


function aes_siv_dupctx( in_vctx, out_vctx : Pointer):integer;
var
  _in, _out : PPROV_AES_SIV_CTX;
begin
    _in := PPROV_AES_SIV_CTX ( in_vctx);
    _out := PPROV_AES_SIV_CTX ( out_vctx);
    _out^ := _in^;
    _out.siv.cipher_ctx := nil;
    _out.siv.mac_ctx_init := nil;
    _out.siv.mac := nil;
    if 0>= ossl_siv128_copy_ctx(@_out.siv, @_in.siv) then
        Exit(0);
    if _out.cbc <> nil then EVP_CIPHER_up_ref(_out.cbc);
    if _out.ctr <> nil then EVP_CIPHER_up_ref(_out.ctr);
    Result := 1;
end;


function aes_siv_settag(vctx : Pointer;const tag : PByte; tagl : size_t):integer;
var
  ctx : PPROV_AES_SIV_CTX;
  sctx : PSIV128_CONTEXT;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    sctx := @ctx.siv;
    Result := ossl_siv128_set_tag(sctx, tag, tagl);
end;


procedure aes_siv_setspeed( vctx : Pointer; speed : integer);
var
  ctx : PPROV_AES_SIV_CTX;
  sctx : PSIV128_CONTEXT;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    sctx := @ctx.siv;
    ossl_siv128_speed(sctx, int (speed));
end;


procedure aes_siv_cleanup( vctx : Pointer);
var
  ctx : PPROV_AES_SIV_CTX;
  sctx : PSIV128_CONTEXT;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    sctx := @ctx.siv;
    ossl_siv128_cleanup(sctx);
    EVP_CIPHER_free(ctx.cbc);
    EVP_CIPHER_free(ctx.ctr);
end;


function aes_siv_cipher(vctx : Pointer; _out : PByte;const _in : PByte; len : size_t):integer;
var
  ctx : PPROV_AES_SIV_CTX;

  sctx : PSIV128_CONTEXT;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    sctx := @ctx.siv;
    { EncryptFinal or DecryptFinal }
    if _in = nil then Exit(Int(ossl_siv128_finish(sctx) = 0));
    { Deal with associated data }
    if _out = nil then
       Exit(int(ossl_siv128_aad(sctx, _in, len) = 1));
    if ctx.enc >0 then
       Exit(Int(ossl_siv128_encrypt(sctx, _in, _out, len) > 0));
    Result := Int(ossl_siv128_decrypt(sctx, _in, _out, len) > 0);
end;


function ossl_prov_cipher_hw_aes_siv( keybits : size_t):PPROV_CIPHER_HW_AES_SIV;
begin
    Result := @aes_siv_hw;
end;






end.
