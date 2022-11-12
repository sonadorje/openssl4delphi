unit openssl3.crypto.evp.e_rc4;

interface
uses OpenSSL.Api;

type
 TEVP_RC4_KEY = record
    ks: TRC4_KEY ;                 (* working key *)
 end;
 PEVP_RC4_KEY = ^TEVP_RC4_KEY;

 function EVP_rc4:PEVP_CIPHER;

 var
   r4_cipher, r4_40_cipher : TEVP_CIPHER;

function rc4_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function data(ctx: PEVP_CIPHER_CTX): PEVP_RC4_KEY;
function rc4_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function EVP_rc4_40:PEVP_CIPHER;

implementation
uses openssl3.crypto.evp.evp_lib,            openssl3.crypto.rc4.rc4_skey,
     openssl3.crypto.rc4.rc4_enc;




function EVP_rc4_40:PEVP_CIPHER;
begin
    Result := @r4_40_cipher;
end;



function rc4_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    RC4(@data(ctx).ks, inl, _in, _out);
    Result := 1;
end;

function data(ctx: PEVP_CIPHER_CTX): PEVP_RC4_KEY;
begin
  Result := PEVP_RC4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
end;

function rc4_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  keylen : integer;
begin
    keylen := EVP_CIPHER_CTX_get_key_length(ctx);
    if keylen  <= 0 then
        Exit(0);
    RC4_set_key(@data(ctx).ks, keylen, key);
    Result := 1;
end;



function EVP_rc4:PEVP_CIPHER;
begin
    Result := @r4_cipher;
end;

initialization
    r4_cipher := get_EVP_CIPHER (
    NID_rc4,
    1, EVP_RC4_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    EVP_ORIG_GLOBAL,
    rc4_init_key,
    rc4_cipher,
    nil,
    sizeof(TEVP_RC4_KEY),
    nil,
    nil,
    nil,
    nil);

   r4_40_cipher := get_EVP_CIPHER(
    NID_rc4_40,
    1, 5 (* 40 bit *) , 0,
    EVP_CIPH_VARIABLE_LENGTH,
    EVP_ORIG_GLOBAL,
    rc4_init_key,
    rc4_cipher,
    nil,
    sizeof(TEVP_RC4_KEY),
    nil,
    nil,
    nil,
    nil);

end.
