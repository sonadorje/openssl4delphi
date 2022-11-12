program demo_wiki_aes;

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
  openssl3.crypto.bio.bio_dump,
  openssl3.crypto.evp.legacy_sha,
  System.TypInfo,
  libc.error in 'libc\libc.error.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  basic_output in 'test\basic_output.pas';

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
procedure handleErrors;
begin
    ERR_print_errors_fp(@System.ErrOutput);
    abort();
end;

function encrypt( plaintext : PByte; plaintext_len : integer; key, iv, ciphertext : PByte):integer;
var
  ctx            : PEVP_CIPHER_CTX;
  len,
  ciphertext_len : integer;
begin
    { Create and initialise the context }
    ctx := EVP_CIPHER_CTX_new ;
    if nil = ctx then
        handleErrors;
    {
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     }
    if 1 <> EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc, nil, key, iv ) then
        handleErrors;
    {
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     }
    if 1 <> EVP_EncryptUpdate(ctx, ciphertext, @len, plaintext, plaintext_len) then
        handleErrors;
    ciphertext_len := len;
    {
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     }
    if 1 <> EVP_EncryptFinal_ex(ctx, ciphertext + len, @len) then
        handleErrors;
    ciphertext_len  := ciphertext_len + len;
    { Clean up }
    EVP_CIPHER_CTX_free(ctx);
    Result := ciphertext_len;
end;


function decrypt( ciphertext : PByte; ciphertext_len : integer; key, iv, plaintext : PByte):integer;
var
  ctx           : PEVP_CIPHER_CTX;
  len,
  plaintext_len : integer;
begin
    { Create and initialise the context }
    ctx := EVP_CIPHER_CTX_new ;
    if nil = ctx then
        handleErrors;
    {
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     }
    if 1 <> EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc, nil, key, iv )then
        handleErrors;
    {
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     }
    if 1 <> EVP_DecryptUpdate(ctx, plaintext, @len, ciphertext, ciphertext_len) then
        handleErrors;
    plaintext_len := len;
    {
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     }
    if 1 <> EVP_DecryptFinal_ex(ctx, plaintext + len, @len) then
        handleErrors;
    plaintext_len  := plaintext_len + len;
    { Clean up }
    EVP_CIPHER_CTX_free(ctx);
    Result := plaintext_len;
end;

type
   SSL_string = AnsiString;
   UTF8Char = AnsiChar;

const
   msg: SSL_String = 'The quick brown fox jumps over the lazy dog';

function main:integer;
var
  key,
  iv,
  plaintext, cipherbytes     : TBytes;
  ciphertext    : array[0..127] of Byte;
  decryptedtext : array[0..127] of UTF8Char;
  enc_b64 : array of AnsiChar;
  decryptedtext_len, len, enc_len_b64,
  ciphertext_len , len_b64   : integer;
  S: string;
  F: PTextFile;
begin
    {
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     }
    { A 256 bit key }
    key := StrToBytes(SSL_String('01234567890123456789012345678901'));
    { A 128 bit IV }
    iv := StrToBytes(SSL_String('0123456789012345'));
    { Message to be encrypted }
    plaintext := StrToBytes(msg);

    {
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     }
    { Buffer for the decrypted text }
    { Encrypt the plaintext }
    ciphertext_len := encrypt (PByte(plaintext), Length(plaintext), PByte(key), PByte(iv),
                              PByte(@ciphertext));
    { Do something useful with the ciphertext here }
    Writeln('Ciphertext is:');
    F := @System.Output;
    len := (Length(msg) + 0) * SizeOf(UTF8Char);
    len  := ((len div AES_BLOCK_SIZE) + int(0 <> (len mod AES_BLOCK_SIZE))) * AES_BLOCK_SIZE;
    len_b64 := (len + 2) div 3 * 4 + ((len + 2) div 3 * 4 + 63) div 64;
    enc_len_b64 := 0;
    SetLength(enc_b64, len_b64);
    base64encode(PByte(@ciphertext), len, PAnsiChar(enc_b64), @enc_len_b64, 0);
    S := TNetEncoding.Base64.EncodeBytesToString(ciphertext);
    //S := Copy(S, 1, enc_len_b64);
    Writeln(PAnsiChar(enc_b64));
    Writeln(S);
    SetLength(cipherbytes, SizeOf(ciphertext));
    Move(ciphertext[0], cipherbytes[0], 127);
    BIO_dump_fp(F, PByte(cipherbytes), ciphertext_len);
    { Decrypt the ciphertext }
    decryptedtext_len := decrypt(@ciphertext, ciphertext_len, PByte(key), PByte(iv),
                                @decryptedtext);
    { Add a nil terminator. We are expecting printable text }
    decryptedtext[decryptedtext_len] := #0;
    { Show the decrypted text }
    Writeln('Decrypted text is:');
    if SizeOf(UTF8Char) = 2 then
       Writeln(Format('%s', [PChar(@decryptedtext)]))
    Else
       Writeln(Format('%s', [PAnsiChar(@decryptedtext)]));

    Setlength(key, 0);
    Setlength(iv, 0);
    Setlength(plaintext, 0);
    SetLength(cipherbytes, 0);
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


