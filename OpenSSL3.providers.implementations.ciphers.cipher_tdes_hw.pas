unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_hw;

interface
uses OpenSSL.Api;

const
  DES_BLOCK_SIZE = 8;

  function ossl_cipher_hw_tdes_ede3_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
  procedure ossl_cipher_hw_tdes_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
  function ossl_cipher_hw_tdes_cbc(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function ossl_cipher_hw_tdes_ecb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
  function ossl_prov_cipher_hw_tdes_ede3_ecb:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede3_cbc:PPROV_CIPHER_HW;

const
    ede3_ecb : TPROV_CIPHER_HW = ( init: ossl_cipher_hw_tdes_ede3_initkey; cipher: ossl_cipher_hw_tdes_ecb; copyctx: ossl_cipher_hw_tdes_copyctx );
    ede3_cbc : TPROV_CIPHER_HW = ( init: ossl_cipher_hw_tdes_ede3_initkey; cipher: ossl_cipher_hw_tdes_cbc; copyctx: ossl_cipher_hw_tdes_copyctx );


implementation
uses openssl3.crypto.des.set_key, openssl3.crypto.des.des_enc,
     openssl3.crypto.des.ecb3_enc;






function ossl_prov_cipher_hw_tdes_ede3_ecb:PPROV_CIPHER_HW;
begin
 Result := @ede3_ecb;
end;


function ossl_prov_cipher_hw_tdes_ede3_cbc:PPROV_CIPHER_HW;
begin
 Result := @ede3_cbc;
end;

function ossl_cipher_hw_tdes_ede3_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
  deskey : PDES_cblock;
begin
    tctx := PPROV_TDES_CTX(ctx);
    deskey := PDES_cblock (key);
    tctx.tstream.cbc := nil;
{$if defined(SPARC_DES_CAPABLE)}
    if SPARC_DES_CAPABLE then begin
        if ctx.mode = EVP_CIPH_CBC_MODE then  begin
            des_t4_key_expand(&deskey[0], &tctx.ks1);
            des_t4_key_expand(&deskey[1], &tctx.ks2);
            des_t4_key_expand(&deskey[2], &tctx.ks3);
            tctx.tstream.cbc := ctx.enc ? des_t4_ede3_cbc_encrypt :
                                           des_t4_ede3_cbc_decrypt;
            Exit(1);
        end;
    end;
{$endif}
    DES_set_key_unchecked(@deskey[0], @tctx.tks.ks[0]);
    DES_set_key_unchecked(@deskey[1], @tctx.tks.ks[1]);
    DES_set_key_unchecked(@deskey[2], @tctx.tks.ks[2]);
    Result := 1;
end;


procedure ossl_cipher_hw_tdes_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_TDES_CTX;
begin
    sctx := PPROV_TDES_CTX(src);
    dctx := PPROV_TDES_CTX(dst);
    dctx^ := sctx^;
    dst.ks := @dctx.tks.ks;
end;


function ossl_cipher_hw_tdes_cbc(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
begin
    tctx := PPROV_TDES_CTX(ctx);
    if Assigned(tctx.tstream.cbc) then begin
        tctx.tstream.cbc(_in, _out, inl, @tctx.tks.ks, @ctx.iv);
        Exit(1);
    end;
    while inl >= MAXCHUNK do
    begin
        DES_ede3_cbc_encrypt(_in, _out, long(MAXCHUNK), @tctx.tks.ks[0], @tctx.tks.ks[1],
                             @tctx.tks.ks[2], PDES_cblock (@ctx.iv), ctx.enc);
        inl  := inl - MAXCHUNK;
        _in  := _in + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then
       DES_ede3_cbc_encrypt(_in, _out, long(inl), @tctx.tks.ks[0], @tctx.tks.ks[1],
                             @tctx.tks.ks[2], PDES_cblock(@ctx.iv), ctx.enc);
    Result := 1;
end;


function ossl_cipher_hw_tdes_ecb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  i : size_t;
  tctx : PPROV_TDES_CTX;
begin
    tctx := PPROV_TDES_CTX(ctx);
    if len < DES_BLOCK_SIZE then Exit(1);
    i := 0; len  := len - (DES_BLOCK_SIZE);
    while i <= len do
    begin
        DES_ecb3_encrypt(Pconst_DES_cblock(_in + i), PDES_cblock(_out + i),
                         @tctx.tks.ks[0], @tctx.tks.ks[1], @tctx.tks.ks[2], ctx.enc);
    end;
    Result := 1;
end;


end.
