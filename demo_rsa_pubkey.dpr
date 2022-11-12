program demo_rsa_pubkey;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

uses

  {$I openssl4d.inc}

  SysUtils
  ;

  //http://hayageek.com/rsa-encryption-decryption-openssl-c/

const
  padding = RSA_PKCS1_PADDING;



   publicKey: PAnsichar ='-----BEGIN PUBLIC KEY-----'#10+
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY'#10+
'ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+'#10+
'vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp'#10+
'fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68'#10+
'i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV'#10+
'PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy'#10+
'wQIDAQAB'#10+
'-----END PUBLIC KEY-----'#10;

  privateKey: PAnsichar ='-----BEGIN RSA PRIVATE KEY-----'#10+
'MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy'#10+
'vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9'#10+
'Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9'#10+
'yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l'#10+
'WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q'#10+
'gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8'#10+
'omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e'#10+
'N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG'#10+
'X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd'#10+
'gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl'#10+
'vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF'#10+
'1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu'#10+
'm0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ'#10+
'uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D'#10+
'JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D'#10+
'4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV'#10+
'WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5'#10+
'nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG'#10+
'PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA'#10+
'SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1'#10+
'I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96'#10+
'ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF'#10+
'yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5'#10+
'w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX'#10+
'uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw'#10+
'-----END RSA PRIVATE KEY-----'#10;

function createRSA( key : PByte; _public : integer):PRSA;
var
  rsa : PRSA;
  keybio : PBIO;
begin
    rsa := nil;
    keybio := BIO_new_mem_buf(key, -1);
    if keybio=nil then begin
        WriteLn( 'Failed to create key BIO');
        Exit(0);
    end;
    if _public > 0 then begin
        rsa := PEM_read_bio_RSA_PUBKEY(keybio, @rsa,nil, nil);
    end
    else
    begin
        rsa := PEM_read_bio_RSAPrivateKey(keybio, @rsa,nil, nil);
    end;
    if rsa = nil then begin
        WriteLn( 'Failed to create RSA');
    end;
    Result := rsa;
end;

function public_encrypt( data : PByte; data_len : integer; key, encrypted : PByte):integer;
var
  rsa : PRSA;
begin
    rsa := createRSA(key,1);
    if rsa = nil then
       Exit(0);
    result := RSA_public_encrypt(data_len,data,encrypted,rsa, padding);

end;

function private_decrypt( Aenc_data : PByte; Adata_len : integer; Akey, Adecrypted : PByte):integer;
var
  rsa : PRSA;
begin
    rsa := createRSA(Akey,0);
    result := RSA_private_decrypt(Adata_len, Aenc_data, Adecrypted, rsa, padding);

end;

function private_encrypt( data : PByte; data_len : integer; key, encrypted : PByte):integer;
var
  rsa : PRSA;
begin
    rsa := createRSA(key,0);
    result := RSA_private_encrypt(data_len,data,encrypted,rsa,padding);

end;

function public_decrypt( enc_data : PByte; data_len : integer; key, decrypted : PByte):integer;
var
  rsa : PRSA;
begin
    rsa := createRSA(key,1);
    result := RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    Result := result;
end;


procedure printLastError( msg : PUTF8Char);
var
  err : PUTF8Char;
begin
    err := malloc(130);
    //ERR_load_crypto_strings;
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil);
    ERR_error_string(ERR_get_error, err);
    WriteLn(Format('%s ERROR: %s', [msg, err]));
    free(err);
end;


function main:integer;
var
  plainText        : array[0..(2048 div 8)-1] of AnsiChar;
  encrypted,
  decrypted        : array[0..4097] of Byte;
  encrypted_length,
  decrypted_length : integer;
  pub_key, pri_key, txt_bytes: TBytes;
begin
    plainText := 'Hello this is Ravi';
    FillChar(encrypted, 4098, 0);
    FillChar(decrypted, 4098, 0);

    //公钥加密
    pub_key := StrToBytes(publicKey);
    txt_bytes := StrToBytes(plainText);
    encrypted_length := public_encrypt(PByte(txt_bytes), strlen(plainText),
                                      PByte(pub_Key), @encrypted);

    if encrypted_length <= 0 then begin
        printLastError('Public Encrypt failed ');
        exit(0);
    end;
    WriteLn(Format('Encrypted length =%d', [encrypted_length]));

    //私钥解密
    pri_key := StrToBytes(privateKey);
    decrypted_length := private_decrypt(@encrypted, encrypted_length, PByte(pri_key), @decrypted);
    if decrypted_length = -1 then begin
        printLastError('Private Decrypt failed ');
        exit(0);
    end;
    WriteLn(Format('Decrypted Text =%s', [PAnsiChar(@decrypted)]));
    WriteLn(Format('Decrypted Length =%d', [decrypted_length]));

    //私钥加密
    FillChar(encrypted, 4098, 0);
    FillChar(decrypted, 4098, 0);
    txt_bytes := StrToBytes(plainText);
    pri_key := StrToBytes(privateKey);
    encrypted_length := private_encrypt(PByte(txt_bytes), strlen(plainText), PByte(pri_key), @encrypted);
    if encrypted_length = -1 then begin
        printLastError('Private Encrypt failed');
        exit(0);
    end;

    //公钥解密
    pub_key := StrToBytes(publicKey);
    WriteLn(Format('Encrypted length =%d', [encrypted_length]));
    decrypted_length := public_decrypt(@encrypted,encrypted_length, PByte(pub_key), @decrypted);
    if decrypted_length = -1 then begin
        printLastError('Public Decrypt failed');
        exit(0);
    end;
    WriteLn(Format('Decrypted Text =%s', [PAnsiChar(@decrypted)]));
    WriteLn(Format('Decrypted Length =%d', [decrypted_length]));
    Setlength(pub_key, 0);
    Setlength(pri_key, 0);
    Setlength(txt_bytes, 0);
end;

begin
  try
    Main;
  except
    on e:Exception do
      WriteLn(e.Message);
  end;
end.





