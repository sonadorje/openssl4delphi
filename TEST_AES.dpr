{ YuOpenSSL authenticated encryption and decryption demo. Pascal adoption of
  https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

  Visit the YuOpenSSL web page for latest information and updates:

    http://www.yunqa.de

  Copyright (c) 2020-2022 Ralf Junker, Yunqa <delphi@yunqa.de>

------------------------------------------------------------------------------ }

program TEST_AES;

{$APPTYPE CONSOLE}
//{$I DICompilers.inc}


uses
  {$IFDEF EurekaLog}
  EMemLeaks,
  EResLeaks,
  EDebugExports,
  EDebugJCL,
  EFixSafeCallException,
  EMapWin32,
  EAppConsole,
  EDialogConsole,
  ExceptionLog7,
  {$ENDIF EurekaLog}
  {$IFDEF FastMM}
  {$I}
  {$ENDIF }
  SysUtils,
  openssl.api,
  openssl3.crypto.evp.evp_lib,
  OpenSSL3.Err,
  OpenSSL3.crypto.err.err_prn,
  openssl3.crypto.evp.evp_enc,
  openssl3.crypto.evp.e_aes,
  libc.error in 'libc\libc.error.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  basic_output in 'test\basic_output.pas',
  openssl3.crypto.evp.p5_crpt2 in 'openssl3.crypto.evp.p5_crpt2.pas',
  openssl3.providers.fips.fipsprov in 'openssl3.providers.fips.fipsprov.pas',
  openssl3.providers.prov_running in 'openssl3.providers.prov_running.pas';

const // 1d arrays
  key : array[0..15] of byte = (
    $14, $9d, $0b, $16, $62, $ab, $87, $1f, $be, $63, $c4, $9b, $5e, $65,
    $5a, $5d );

  pt : array[0..97] of byte = (
    $0d, $00, $00, $00, $00, $18, $41, $0a, $02, $00, $00, $56, $03, $03,
    $ee, $fc, $e7, $f7, $b3, $7b, $a1, $d1, $63, $2e, $96, $67, $78, $25,
    $dd, $f7, $39, $88, $cf, $c7, $98, $25, $df, $56, $6d, $c5, $43, $0b,
    $9a, $04, $5a, $12, $00, $13, $01, $00, $00, $2e, $00, $33, $00, $24,
    $00, $1d, $00, $20, $9d, $3c, $94, $0d, $89, $69, $0b, $84, $d0, $8a,
    $60, $99, $3c, $14, $4e, $ca, $68, $4d, $10, $81, $28, $7c, $83, $4d,
    $53, $11, $bc, $f3, $2b, $b9, $da, $1a, $00, $2b, $00, $02, $03, $04 );

//https://github.com/NanXiao/code-for-my-blog/blob/master/2021/04/aes/main.c
function main:integer;
var
    ret           : integer;
    ct            : array[0..1023] of byte;
    len,
    ct_len        : integer;
    enc_ctx       : PEVP_CIPHER_CTX;
    decrypted     : array[0..1023] of byte;
    decrypted_len : integer;
    dec_ctx       : PEVP_CIPHER_CTX;
    i             : integer;
    p             : PByte;
    label _end;
begin
  ret := 1;
  FillChar(decrypted, SizeOf(decrypted), 0);
  FillChar(ct, SizeOf(ct), 0);
  enc_ctx := EVP_CIPHER_CTX_new;
  if EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ecb, nil, @key, nil) = 0 then
  begin
    goto _END;
  end;
  dec_ctx := EVP_CIPHER_CTX_new;
  if EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_ecb, nil, @key, nil) = 0 then
  begin
    goto _END;
  end;

  for i := 0 to 9 do
  begin
      if EVP_EncryptInit_ex(enc_ctx, nil, nil, nil, nil) = 0  then
      begin
        goto _END;
      end;
      if EVP_EncryptUpdate(enc_ctx, @ct, @ct_len, @pt, sizeof(pt))  = 0 then
      begin
        goto _END;
      end;
      if EVP_EncryptFinal_ex(enc_ctx, PByte(@ct) + ct_len, @len) = 0 then
      begin
        goto _END;
      end;

      ct_len  := ct_len + len;
      if EVP_DecryptInit_ex(dec_ctx, nil, nil, nil, nil)  = 0 then
      begin
        goto _END;
      end;
      if EVP_DecryptUpdate(dec_ctx, @decrypted, @decrypted_len, @ct, ct_len) = 0 then
      begin
        goto _END;
      end;
      p := @decrypted;
      if EVP_DecryptFinal_ex(dec_ctx, P + decrypted_len, @len) = 0 then
      begin
        goto _END;
      end;
      decrypted_len  := decrypted_len + len;
      if (decrypted_len <> sizeof(pt))   or
         (memcmp(PByte(@pt), PByte(@decrypted), sizeof(pt)) <> 0) then
      begin
        goto _END;
      end;
  end;
  ret := 0;
_END:
  if ret <> 0 then begin
    Writeln('Error occurred!');
  end
 else
 begin
    Writeln('Success!\n');
  end;
  EVP_CIPHER_CTX_free(enc_ctx);
  EVP_CIPHER_CTX_free(dec_ctx);
  Result := ret;
end;




begin
  try
    Main;
  except
    on e:Exception do
      WriteLn(e.Message);
  end;
end.


