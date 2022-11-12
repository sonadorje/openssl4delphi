unit openssl3.crypto.evp.e_xcbc_d;

interface
uses OpenSSL.Api;

type
  TDESX_CBC_KEY = record
    ks : TDES_key_schedule;
    inw, outw : TDES_cblock;
  end;
  PDESX_CBC_KEY = ^TDESX_CBC_KEY;

function EVP_desx_cbc:PEVP_CIPHER;

var
  d_xcbc_cipher :TEVP_CIPHER;
function desx_cbc_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function data(ctx: PEVP_CIPHER_CTX): PDESX_CBC_KEY;
function desx_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;

implementation
 uses openssl3.crypto.des.set_key,    openssl3.crypto.evp.evp_lib,
      openssl3.crypto.evp,            openssl3.crypto.des.xcbc_enc;

function data(ctx: PEVP_CIPHER_CTX): PDESX_CBC_KEY;
begin
  Result := PDESX_CBC_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
end;


function desx_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        DES_xcbc_encrypt(_in, _out, long(EVP_MAXCHUNK), @data(ctx).ks,
                         PDES_cblock(@ctx.iv),
                         @data(ctx).inw, @data(ctx).outw,
                         EVP_CIPHER_CTX_is_encrypting(ctx));
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then DES_xcbc_encrypt(_in, _out, long(inl), @data(ctx).ks,
                         PDES_cblock(@ctx.iv),
                         @data(ctx).inw, @data(ctx).outw,
                         EVP_CIPHER_CTX_is_encrypting(ctx));
    Result := 1;
end;



function desx_cbc_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  deskey : PDES_cblock;
begin
    deskey := PDES_cblock(key);
    DES_set_key_unchecked(deskey, @data(ctx).ks);
    memcpy(@data(ctx).inw[0], @key[8], 8);
    memcpy(@data(ctx).outw[0], @key[16], 8);
    Result := 1;
end;



function EVP_desx_cbc:PEVP_CIPHER;
begin
    Result := @d_xcbc_cipher;
end;

initialization
   d_xcbc_cipher := get_EVP_CIPHER(
    NID_desx_cbc,
    8, 24, 8,
    EVP_CIPH_CBC_MODE,
    EVP_ORIG_GLOBAL,
    desx_cbc_init_key,
    desx_cbc_cipher,
    nil,
    sizeof(TDESX_CBC_KEY),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    nil,
    nil);
end.
