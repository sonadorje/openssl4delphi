unit openssl3.crypto.aes.aes_cbc;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;


procedure AES_cbc_encrypt(const &in : PByte; &out : PByte; len : size_t;const key : Pointer; ivec : PByte;enc : integer);

implementation
uses openssl3.crypto.aes.aes_core, openssl3.crypto.modes.cbc128;

procedure AES_cbc_encrypt(const &in : PByte; &out : PByte; len : size_t;const key : Pointer; ivec : PByte;enc : integer);
begin
    if enc>0 then
       CRYPTO_cbc128_encrypt(&in, &out, len, key, ivec,
                              AES_encrypt)
    else
       CRYPTO_cbc128_decrypt(&in, &out, len, key, ivec,
                              AES_decrypt);
end;





end.
