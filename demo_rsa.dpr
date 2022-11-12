
program demo_rsa;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  {$I openssl4d.inc}
  SysUtils,
  Crypto in 'Demo\Crypto_RSA\Crypto.pas';

//https://github.com/shanet/Crypto-Example
function getMessage(const prompt : PUTF8Char):string;
begin
  Writeln(prompt);
  //fflush(stdout);
  //getline(std.cin, message);
  Result := 'Hello, world!';
end;

procedure encryptRsa(var crypto : TCrypto);
var
  _message               :AnsiString;
  encryptedMessage,
  encryptedKey,
  iv                     : PByte;
  encryptedKeyLength,
  ivLength               : size_t;
  encryptedMessageLength : integer;
  b64Message             : PAnsiChar;
  decryptedMessage       : PUTF8Char;
  decryptedMessageLength : integer;
  bytes_message: TBytes;
begin
  // Get the message to encrypt
  _message := getMessage('Message to RSA encrypt: ');
  bytes_message := StrToBytes(_message);
  // Encrypt the message with RSA
  // +1 on the string length argument because we want to encrypt the NUL terminator too
  encryptedMessage := nil;
  encryptedMessageLength := crypto.rsaEncrypt(PByte(bytes_message), StrSize(PAnsiChar(_message)),
                                              @encryptedMessage, @encryptedKey,
                                              @encryptedKeyLength, @iv, @ivLength);
  if encryptedMessageLength = -1 then begin
    WriteLn('Encryption failed');
    exit;
  end;
  // Print the encrypted message as a base64 string
  b64Message := base64Encode(encryptedMessage, encryptedMessageLength);
  writeln(Format('Encrypted message: %s', [b64Message]));
  // Decrypt the message
  decryptedMessage := nil;
  decryptedMessageLength := crypto.rsaDecrypt(encryptedMessage, size_t(encryptedMessageLength),
                                              encryptedKey, encryptedKeyLength, iv, ivLength,
                                              @decryptedMessage);
  if decryptedMessageLength = -1 then begin
    WriteLn('Decryption failed');
    exit;
  end;
  WriteLn(Format('Decrypted message: %s', [decryptedMessage]));
  // Clean up
  freemem(encryptedMessage);
  freemem(decryptedMessage);
  freeMem(encryptedKey);
  freeMem(iv);
  freeMem(b64Message);
  encryptedMessage := nil;
  decryptedMessage := nil;
  encryptedKey := nil;
  iv := nil;
  b64Message := nil;
end;


procedure encryptAes(var crypto : TCrypto);
var
  _message                : Ansistring;
  encryptedMessage       : PByte;
  encryptedMessageLength : integer;
  b64Message,
  decryptedMessage       : PUTF8Char;
  decryptedMessageLength : integer;
  bytes_message: TBytes;
begin
  // Get the message to encrypt
  _message := getMessage('Message to AES encrypt: ');
  bytes_message := StrToBytes(_message);
  // Encrypt the message with AES
  encryptedMessage := nil;
  encryptedMessageLength := crypto.aesEncrypt(PByte(bytes_message), StrSize(PAnsiChar(_message)), @encryptedMessage);
  if encryptedMessageLength = -1 then begin
    WriteLn('Encryption failed');
    exit;
  end;
  // Print the encrypted message as a base64 string
  b64Message := base64Encode(encryptedMessage, encryptedMessageLength);
  writeln('Encrypted message: %s', b64Message);
  // Decrypt the message
  decryptedMessage := nil;
  decryptedMessageLength := crypto.aesDecrypt(encryptedMessage, size_t(encryptedMessageLength),
                                                  @decryptedMessage);
  if decryptedMessageLength = -1 then begin
    WriteLn('Decryption failed');
    exit;
  end;
  Writeln(Format('Decrypted message: %s', [decryptedMessage]));
  // Clean up
  freemem(encryptedMessage);
  freemem(decryptedMessage);
  freemem(b64Message);
  encryptedMessage := nil;
  decryptedMessage := nil;
  b64Message := nil;
end;

procedure printBytesAsHex(bytes : PByte; length : size_t;const message : PUTF8Char);
var
  i: Uint32;
begin
  writeln(Format('%s: ', [message]));
  for i :=0 to length-1 do
    Writeln(Format('%02hhx', [bytes[i]]));

  WriteLn('');
end;

procedure printKeys(var crypto : TCrypto);
var
    aesKey       : PByte;
    aesKeyLength : size_t;
    aesIv        : PByte;
    aesIvLength  : size_t;
begin
  // Write the RSA keys to stdout
  crypto.writeKeyToFile(@System.Output, KEY_SERVER_PRI);
  crypto.writeKeyToFile(@System.Output, KEY_SERVER_PUB);
  crypto.writeKeyToFile(@System.Output, KEY_CLIENT_PUB);
  // Write the AES key to stdout in hex
  aesKeyLength := crypto.getAesKey(@aesKey);
  printBytesAsHex(aesKey, aesKeyLength, 'AES Key');
  // Write the AES IV to stdout in hex
  aesIvLength := crypto.getAesIv(@aesIv);
  printBytesAsHex(aesIv, aesIvLength, 'AES IV');
end;




function main:integer;
var
  crypto : TCrypto;
  remotekey: PByte;
begin
  {$IFDEF PRINT_KEYS}
    printKeys(&crypto);
  {$ENDIF}
  //while not std.cin.eof() do
  crypto := TCrypto.Create;
  if crypto.getRemotePublicKey(@remotekey) <= 0 then
     Exit;
  begin
    encryptRsa(&crypto);
    encryptAes(&crypto);
  end;
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





