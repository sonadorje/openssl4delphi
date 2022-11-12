unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_default_hw;

interface
uses OpenSSL.Api;

  function ossl_cipher_hw_tdes_ede2_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_cipher_hw_tdes_ofb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function ossl_cipher_hw_tdes_cfb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function ossl_cipher_hw_tdes_cfb1(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function ossl_cipher_hw_tdes_cfb8(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;

  function ossl_prov_cipher_hw_tdes_ede3_ofb:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede3_cfb:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede3_cfb1:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede3_cfb8:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede2_ecb:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede2_cbc:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede2_ofb:PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_tdes_ede2_cfb:PPROV_CIPHER_HW;

implementation
uses openssl3.crypto.des.set_key,  openssl3.crypto.des.ofb64ede,
     openssl3.crypto.des.cfb64ede,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes_hw;


const  ede3_ofb: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede3_initkey;cipher: ossl_cipher_hw_tdes_ofb;copyctx: ossl_cipher_hw_tdes_copyctx );

const  ede3_cfb: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede3_initkey;cipher: ossl_cipher_hw_tdes_cfb;copyctx: ossl_cipher_hw_tdes_copyctx );

ede3_cfb1: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede3_initkey;cipher: ossl_cipher_hw_tdes_cfb1;copyctx: ossl_cipher_hw_tdes_copyctx );

ede3_cfb8: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede3_initkey;cipher: ossl_cipher_hw_tdes_cfb8;copyctx: ossl_cipher_hw_tdes_copyctx );

ede2_ecb: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede2_initkey;cipher: ossl_cipher_hw_tdes_ecb;copyctx: ossl_cipher_hw_tdes_copyctx );

ede2_cbc: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede2_initkey;cipher: ossl_cipher_hw_tdes_cbc;copyctx: ossl_cipher_hw_tdes_copyctx );

ede2_ofb: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede2_initkey;cipher: ossl_cipher_hw_tdes_ofb;copyctx: ossl_cipher_hw_tdes_copyctx );

ede2_cfb: TPROV_CIPHER_HW =
( init: ossl_cipher_hw_tdes_ede2_initkey;cipher: ossl_cipher_hw_tdes_cfb;copyctx: ossl_cipher_hw_tdes_copyctx );

function ossl_prov_cipher_hw_tdes_ede3_ofb:PPROV_CIPHER_HW;
begin
 Exit(@ede3_ofb);
end;


function ossl_prov_cipher_hw_tdes_ede3_cfb:PPROV_CIPHER_HW;
begin
 Exit(@ede3_cfb);
end;


function ossl_prov_cipher_hw_tdes_ede3_cfb1:PPROV_CIPHER_HW;
begin
 Exit(@ede3_cfb1);
end;


function ossl_prov_cipher_hw_tdes_ede3_cfb8:PPROV_CIPHER_HW;
begin
 Exit(@ede3_cfb8);
end;


function ossl_prov_cipher_hw_tdes_ede2_ecb:PPROV_CIPHER_HW;
begin
 Exit(@ede2_ecb);
end;


function ossl_prov_cipher_hw_tdes_ede2_cbc:PPROV_CIPHER_HW;
begin
 Exit(@ede2_cbc);
end;


function ossl_prov_cipher_hw_tdes_ede2_ofb:PPROV_CIPHER_HW;
begin
 Exit(@ede2_ofb);
end;


function ossl_prov_cipher_hw_tdes_ede2_cfb:PPROV_CIPHER_HW;
begin
 Exit(@ede2_cfb);
end;

function ossl_cipher_hw_tdes_ede2_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
  deskey : PDES_cblock;
begin
    tctx := PPROV_TDES_CTX(ctx);
    deskey := PDES_cblock (key);
    tctx.tstream.cbc := nil;
{$IF defined(SPARC_DES_CAPABLE)}
    if SPARC_DES_CAPABLE then begin
        if ctx.mode = EVP_CIPH_CBC_MODE then  begin
            des_t4_key_expand(&deskey[0], &tctx.ks1);
            des_t4_key_expand(&deskey[1], &tctx.ks2);
            memcpy(&tctx.ks3, &tctx.ks1, sizeof(tctx.ks1));
            tctx.tstream.cbc := ctx.enc ? des_t4_ede3_cbc_encrypt :
                                           des_t4_ede3_cbc_decrypt;
            Exit(1);
        end;
    end;
{$ENDIF}
    DES_set_key_unchecked(@deskey[0], @tctx.tks.ks[0]);
    DES_set_key_unchecked(@deskey[1], @tctx.tks.ks[1]);
    memcpy(@tctx.tks.ks[2]{ks3}, @tctx.tks.ks[0]{ks1}, sizeof(tctx.tks.ks[0]));
    Result := 1;
end;


function ossl_cipher_hw_tdes_ofb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
  num : integer;
begin
    tctx := PPROV_TDES_CTX(ctx);
    num := ctx.num;
    while inl >= MAXCHUNK do
    begin
        DES_ede3_ofb64_encrypt(_in, _out, long(MAXCHUNK), @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2},
                               @tctx.tks.ks[2]{ks3}, PDES_cblock(@ctx.iv), @num);
        inl  := inl - MAXCHUNK;
        _in  := _in + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then
    begin
        DES_ede3_ofb64_encrypt(_in, _out, long(inl), @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2},
                               @tctx.tks.ks[2]{ks3}, PDES_cblock (@ctx.iv), @num);
    end;
    ctx.num := num;
    Result := 1;
end;


function ossl_cipher_hw_tdes_cfb(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
  num : integer;
begin
    tctx := PPROV_TDES_CTX(ctx);
    num := ctx.num;
    while inl >= MAXCHUNK do
    begin
        DES_ede3_cfb64_encrypt(_in, _out, long(MAXCHUNK),
                               @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2}, @tctx.tks.ks[2]{ks3},
                               PDES_cblock (@ctx.iv), @num, ctx.enc);
        inl  := inl - MAXCHUNK;
        _in  := _in + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then
    begin
        DES_ede3_cfb64_encrypt(_in, _out, long(inl),
                               @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2}, @tctx.tks.ks[2]{ks3},
                               PDES_cblock (@ctx.iv), @num, ctx.enc);
    end;
    ctx.num := num;
    Result := 1;
end;


function ossl_cipher_hw_tdes_cfb1(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
  n : size_t;
  c, d : array[0..0] of Byte;
begin
    tctx := PPROV_TDES_CTX(ctx);
    //Byte  c[1], d[1];
    if ctx.use_bits = 0 then
       inl  := inl  * 8;
    for n := 0 to inl - 1 do
    begin
        c[0] := get_result( (_in[n div 8] and (1 shl (7 - n mod 8))) > 0 , $80 , 0);
        DES_ede3_cfb_encrypt(@c, @d, 1, 1,
                             @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2}, @tctx.tks.ks[2]{ks3},
                             PDES_cblock (@ctx.iv), ctx.enc);
        _out[n div 8] := (_out[n div 8] and not ($80  shr  uint32(n mod 8)))
            or ((d[0] and $80)  shr  uint32(n mod 8));
    end;
    Result := 1;
end;


function ossl_cipher_hw_tdes_cfb8(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  tctx : PPROV_TDES_CTX;
begin
    tctx := PPROV_TDES_CTX(ctx);
    while inl >= MAXCHUNK do
    begin
        DES_ede3_cfb_encrypt(_in, _out, 8, long(MAXCHUNK),
                             @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2}, @tctx.tks.ks[2]{ks3},
                             PDES_cblock (@ctx.iv), ctx.enc);
        inl  := inl - MAXCHUNK;
        _in  := _in + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then DES_ede3_cfb_encrypt(_in, _out, 8, long(inl),
                             @tctx.tks.ks[0]{ks1}, @tctx.tks.ks[1]{ks2}, @tctx.tks.ks[2]{ks3},
                             PDES_cblock (@ctx.iv), ctx.enc);
    Result := 1;
end;


end.
