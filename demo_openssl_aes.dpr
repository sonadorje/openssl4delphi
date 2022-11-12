{ YuOpenSSL authenticated encryption and decryption demo. Pascal adoption of
  https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

  Visit the YuOpenSSL web page for latest information and updates:

    http://www.yunqa.de

  Copyright (c) 2020-2022 Ralf Junker, Yunqa <delphi@yunqa.de>

------------------------------------------------------------------------------ }

program demo_openssl_aes;

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
  SysUtils,
  System.NetEncoding,
  openssl.api,
  openssl3.crypto.evp.evp_lib,
  OpenSSL3.Err,
  OpenSSL3.crypto.err.err_prn,
  openssl3.crypto.evp.evp_enc,
  openssl3.crypto.evp.e_aes,
  openssl3.crypto.sha.sha1_one,
  openssl3.crypto.evp.evp_key,
  openssl3.crypto.bio.bio_lib,
  openssl3.crypto.evp.bio_b64,
  openssl3.crypto.bio.bss_mem,
  openssl3.crypto.evp.legacy_sha,
  libc.error in 'libc\libc.error.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  basic_output in 'test\basic_output.pas';

const Char_Size = 2;
function aes_init( key_data : PByte; key_data_len : integer; salt : PByte; e_ctx, d_ctx : PEVP_CIPHER_CTX):integer;
var
  i, nrounds : integer;
  key, iv : array[0..31] of Byte;
begin
  nrounds := 5;

  {
   * Gen key and IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   }
  FillChar(key, 32, 0);
  FillChar(iv, SizeOf(iv), 0);
  i := EVP_BytesToKey(EVP_aes_256_cbc, EVP_sha1, salt, key_data, key_data_len, nrounds, @key, @iv);
  if i <> 32 then begin
    Writeln(Format('Key size is %d bits - should be 256 bits', [i]));
    Exit(-1);
  end;
  //EVP_CIPHER_CTX_init(e_ctx);
  e_ctx^ := default(TEVP_CIPHER_CTX);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc, nil, @key, @iv);
  //EVP_CIPHER_CTX_init(d_ctx);
  d_ctx^ := default(TEVP_CIPHER_CTX);

  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc, nil, @key, @iv);
  Result := 0;
end;


function aes_encrypt( e : PEVP_CIPHER_CTX; plaintext : PByte;var len : Integer): TBytes;
var
    c_len, f_len      : integer;
    ciphertext : TBytes;
begin
  { max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes }
  c_len := len + AES_BLOCK_SIZE;
  f_len := 0;
  //ciphertext := malloc(c_len);
  SetLength(ciphertext, c_len);
  { allows reusing of 'e' for multiple encryption cycles }
  EVP_EncryptInit_ex(e, nil, nil, nil, nil);
  { update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes }
  EVP_EncryptUpdate(e, Pbyte(ciphertext), @c_len, plaintext, len);
  { update ciphertext with the final remaining bytes }
  EVP_EncryptFinal_ex(e, Pbyte(ciphertext)+c_len, @f_len);
  len := c_len + f_len;
  Result := ciphertext;
end;


function aes_decrypt( e : PEVP_CIPHER_CTX; Aciphertext : PByte;var Alen : Integer):TBytes;
var
    p_len, f_len     : integer;
    vPlaintext : TBytes;
begin
  { plaintext will always be equal to or lesser than length of ciphertext}
  p_len := Alen;
  f_len := 0;
  //plaintext := malloc(p_len);
  SetLength(vPlaintext, p_len);
  EVP_DecryptInit_ex(e, nil, nil, nil, nil);
  EVP_DecryptUpdate(e, PByte(vPlaintext), @p_len, Aciphertext, Alen);
  EVP_DecryptFinal_ex(e, PByte(vPlaintext) + p_len, @f_len);
  Alen := p_len + f_len;
  Result := vPlaintext;
end;

function main({ argc : integer; argv : PPChar}):integer;
var
  input: array of  PChar ;
  en,
  de           : PEVP_CIPHER_CTX;
  salt         : array[0..1] of uint32;
  key_data, P  : PByte;
  key_data_len,
  i            : integer;
  plaintext    : TBytes;
  ciphertext, _salt   : TBytes;
  enc: TBytes;
  olen, len, len_b64,
  enc_len_b64        : integer;
  S: string;
  enc_b64: array of AnsiChar;
begin
  { 'opaque' encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations }
  en := EVP_CIPHER_CTX_new;
  de := EVP_CIPHER_CTX_new;
  { 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte
     integers on the stack as 64 bits of contigous salt material -
     ofcourse this only works if sizeofint( >= 4 }
  //salt[0] := 12345;
  //salt[1] := 54321;
  _salt := BytesOf('encryptionIntVec');
  input := ['The quick brown fox jumps over the lazy dog', '你好，世界！', 'こんにちは世界', 'Привет, мир!',
                   nil];
  { the key_data is read from the argument list }
  key_data := PByte(StrToBytes(ParamStr(1), Typeinfo(UTF8Char)));
  key_data_len := Length(ParamStr(1));
  { gen key and iv. init the cipher ctx object }
  if 0 <> aes_init(key_data, key_data_len, PByte(_salt), en, de) then
  begin
    Writeln('Couldn''t initialize AES cipher');
    Exit(-1);
  end;
  { encrypt and decrypt each input string and compare with the original }
  i := 0;
  while input[i] <> nil do
  begin
    { The enc/dec functions deal with binary data and not C strings. strlen will
       Exit(length of the string without counting the #0 string marker. We always);
       pass in the marker byte to the encrypt/decrypt functions so that after decryption
       we end up with a legal C string }
    len := StrSize(input[i]);

    olen := len;
    ciphertext := aes_encrypt(en, PByte(StrToBytes(input[i], Typeinfo(UTF8Char))), len);
    {*
     * 加密后的长度是16(AES_BLOCK_SIZE)的倍数；
     * 加密内容最好补齐16倍数，采用NoPadding方式，这里是例子简单写
     *}
    len  := ((len div AES_BLOCK_SIZE) + int(0 <> (len mod AES_BLOCK_SIZE))) * AES_BLOCK_SIZE;
    len_b64 := (len + 2) div 3 * 4 + ((len + 2) div 3 * 4 + 63) div 64;
    enc := ciphertext;
    enc_len_b64 := 0;
    SetLength(enc_b64, len_b64);
    base64encode(PByte(enc), len, PAnsiChar(enc_b64), @enc_len_b64, 0);
    plaintext := aes_decrypt(de, pbyte(ciphertext), len);
    S := BytesToStr(plaintext);

    if strncmp(PChar(s), input[i], olen) > 0 then
      writeln(Format('FAIL: enc/dec failed for ''%s''', [input[i]]))
    else
      writeln(Format('OK: enc/dec ok for ''%s''', [Trim(s)]));
    SetLength(ciphertext, 0);
    SetLength(plaintext, 0);
    Inc(i);
  end;
  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);
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


