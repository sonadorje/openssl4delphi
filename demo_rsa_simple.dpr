program demo_rsa_simple;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}
//{$I DICompilers.inc}


uses
  {$I openssl4d.inc}
  SysUtils;

//https://gist.github.com/c9n/3751453d5dc1466829c3

  {$define  PRINT_KEYS}
  {$define  WRITE_TO_FILE}
 const
    KEY_LENGTH = 512;//2048;
    PUB_EXP    = 3;
 function main:integer;
var
  pri_len,
  pub_len     : size_t;
  pri_key,
  pub_key     : PAnsiChar;
  msg         : array[0..(KEY_LENGTH div 8)-1] of AnsiChar;

  encrypt,
  decrypt     : Pbyte;
  err         : PAnsiChar;
  keypair     : PRSA;
  pri,
  pub         : PBIO;
  _out        : PFILE;
  encrypt_len : integer;

  label free_stuff;

begin
    encrypt := nil;
    decrypt := nil;
    // Generate key pair
    writeln(Format('Generating RSA (%d bits) keypair...', [KEY_LENGTH]));
    //fflush(stdout);
    keypair := RSA_generate_key(KEY_LENGTH, PUB_EXP, nil, nil);
    if nil = keypair then
       exit(0);
    // To get the C-string PEM form:
    pri := BIO_new(BIO_s_mem);
    pub := BIO_new(BIO_s_mem);
    PEM_write_bio_RSAPrivateKey(pri, keypair, nil, nil, 0, nil, nil);
    PEM_write_bio_RSAPublicKey(pub, keypair);
    pri_len := BIO_pending(pri);
    pub_len := BIO_pending(pub);
    pri_key := malloc(pri_len + 1);
    pub_key := malloc(pub_len + 1);
    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);
    pri_key[pri_len] := #0;
    pub_key[pub_len] := #0;
    {$IFDEF PRINT_KEYS}
        Write(Format(#10'%s'#10'%s'#10, [pri_key, pub_key]));
    {$ENDIF}
    Writeln('done.');
    // Get the message to encrypt
    Writeln('Message to encrypt: ');
    fgets(msg, KEY_LENGTH-1, @System.Input);
    msg[Length(msg)-1] := #0;
    // Encrypt the message
    encrypt := malloc(RSA_size(keypair));
    err := malloc(130);
    encrypt_len := RSA_public_encrypt(StrLen(msg) +1, PByte(@msg), PByte(encrypt),
                                         keypair, RSA_PKCS1_OAEP_PADDING);
    if encrypt_len = -1 then
    begin
        ERR_load_crypto_strings;
        ERR_error_string(ERR_get_error, err);
        WriteLn(Format('Error encrypting message: %s',[err]));
    end;
    {$IFDEF WRITE_TO_FILE}
    // Write the encrypted message to a file
        _out := fopen('out.bin', 'w');
        fwrite(encrypt, sizeof( encrypt^),  RSA_size(keypair), _out);
        fclose(_out);
        Writeln('Encrypted message written to file.');
        free(encrypt);
        encrypt := nil;
        // Read it back
        Writeln('Reading back encrypted message and attempting decryption...');
        encrypt := malloc(RSA_size(keypair));
        _out := fopen('out.bin', 'r');
        fread(encrypt, sizeof( encrypt^), RSA_size(keypair), _out);
        fclose(_out);
    {$ENDIF}
    // Decrypt it
    decrypt := malloc(encrypt_len);
    if RSA_private_decrypt(encrypt_len, PByte(encrypt), PByte(decrypt),
                           keypair, RSA_PKCS1_OAEP_PADDING) = -1 then
    begin
        ERR_load_crypto_strings;
        ERR_error_string(ERR_get_error, err);
        WriteLn(Format('Error decrypting message: %s',[err]));
    end;
    Writeln(Format('Decrypted message: %s', [decrypt]));
    free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);
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





