{ YuOpenSSL authenticated encryption and decryption demo. Pascal adoption of
  https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

  Visit the YuOpenSSL web page for latest information and updates:

    http://www.yunqa.de

  Copyright (c) 2020-2022 Ralf Junker, Yunqa <delphi@yunqa.de>

------------------------------------------------------------------------------ }

program aes_oneshot;

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
  openssl3.crypto.sha.sha1_one,

  libc.error in 'libc\libc.error.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  basic_output in 'test\basic_output.pas',
  openssl3.crypto.evp.p5_crpt2 in 'openssl3.crypto.evp.p5_crpt2.pas',
  openssl3.providers.fips.fipsprov in 'openssl3.providers.fips.fipsprov.pas',
  openssl3.providers.prov_running in 'openssl3.providers.prov_running.pas';

const Char_Size = 1;
function aes_oneshot_encrypt( key : PByte; key_len : integer; salt : PByte; salt_len : integer; data : PByte; data_len : integer; out_len : PInteger):PByte;
var
  nalloc,
  npartial,
  nfinal    : integer;
  encrypted : PByte;
  key_buff,
  iv_buff   : array[0..(SHA256_DIGEST_LENGTH)-1] of Byte;
  ctx       : TEVP_CIPHER_CTX;
begin
   nalloc := 0;
   npartial := 0;
   nfinal := 0;
   encrypted := 0;
   out_len^ := 0;
   FillChar(key_buff, SizeOf(key_buff), 0);
   FillChar(iv_buff, SizeOf(iv_buff), 0);
   SHA256( key, key_len, @key_buff );
   SHA256( salt, salt_len, @iv_buff );
   ctx := default(TEVP_CIPHER_CTX);
   EVP_EncryptInit(@ctx, EVP_aes_256_cbc, @key_buff, @iv_buff);
   nalloc := data_len + EVP_CIPHER_CTX_get_block_size(@ctx);
   encrypted := malloc( nalloc );
   EVP_EncryptUpdate(@ctx, encrypted, @npartial, data, data_len);
   EVP_EncryptFinal_ex(@ctx, encrypted + npartial, @nfinal);
   out_len^ := npartial + nfinal;
   Result := encrypted;
end;


function main():integer;
var
  nbytes : integer;
  key, salt, data : PAnsiChar;
  _key, _salt, _data:TBytes;
  enc : PByte;
  &out : PFILE;
begin
   nbytes := 0;
   key := 'foobar';
   salt := 'wallace';
   data := 'abandon all hope ye who enter here';
   enc := 0;
   _key:=StrToPByte(key);
   _salt:=StrToPByte(salt);
   _data:=StrToPByte(data);
   enc := aes_oneshot_encrypt(PByte(_key), Length(key)*Char_Size,
                              PByte(_salt), Length(salt)*Char_Size,
                              PByte(_data), Length(data)*Char_Size,
                              @nbytes );
   {out := fopen('/tmp/tenc', 'wb');
   fwrite( enc, 1, nbytes, out );
   fclose(out);}
   Result := 0;
end;




begin
  try
    Main;
  except
    on e:Exception do
      WriteLn(e.Message);
  end;
end.


