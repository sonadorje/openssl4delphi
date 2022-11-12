unit Crypto;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses {$I openssl4d.inc} SysUtils;

{$define PSEUDO_CLIENT}
//https://shanetully.com/2012/06/openssl-rsa-aes-and-c/
const
    RSA_KEYLEN = 2048;
    AES_ROUNDS = 6;
    SUCCESS        = 1;
    FAILURE        = -1;
    KEY_SERVER_PRI = 0;
    KEY_SERVER_PUB = 1;
    KEY_CLIENT_PUB = 2;
    KEY_AES        = 3;
    KEY_AES_IV     = 4;

type
 TCrypto = class
    public
        constructor Create; overload;
        constructor Create(remotePublicKey: PByte; remotePublicKeyLen: size_t ); overload;
        destructor Destroy;

        function rsaEncrypt(const _message : PByte; messageLength : size_t; encryptedMessage : PPByte; encryptedKey : PPByte; encryptedKeyLength : Psize_t; iv : PPByte; ivLength : Psize_t):integer;
        function rsaDecrypt( encryptedMessage : PByte; encryptedMessageLength : size_t; encryptedKey : PByte; encryptedKeyLength : size_t; iv : PByte; ivLength : size_t; decryptedMessage : PPByte):integer;
        function aesEncrypt(const _message : PByte; messageLength : size_t; encryptedMessage : PPByte):integer;
        function aesDecrypt( encryptedMessage : PByte; encryptedMessageLength : size_t; decryptedMessage : PPByte):integer;
        function getRemotePublicKey( publicKey : PPByte):integer;
        function setRemotePublicKey( publicKey : PByte; publicKeyLength : size_t):integer;
        function getLocalPublicKey( publicKey : PPByte):integer;
        function getLocalPrivateKey( privateKey : PPByte):integer;
        function getAesKey( aesKey : PPByte):integer;
        function setAesKey( aesKey : PByte; aesKeyLengthgth : size_t):integer;
        function getAesIv( aesIv : PPByte):integer;
        function setAesIv( aesIv : PByte; aesIvLengthgth : size_t):integer;
        function writeKeyToFile( &file : PFILE; key : integer):integer;

   private
        class var localKeypair: PEVP_PKEY;
        remotePublicKey   : PEVP_PKEY;
        rsaEncryptContext,
        aesEncryptContext,
        rsaDecryptContext,
        aesDecryptContext : PEVP_CIPHER_CTX;
        aesKey,
        aesIv             : PByte;
        aesKeyLength,
        aesIvLength       : size_t;
        init              : integer;
        function generateRsaKeypair( keypair : PPEVP_PKEY):integer;
        function generateAesKey( aesKey, aesIv : PPByte):integer;
        function bioToString( bio : PBIO; _string : PPByte):integer;
        function _init: int;
  end;

implementation

destructor TCrypto.Destroy;
begin
  EVP_PKEY_free(remotePublicKey);
  EVP_CIPHER_CTX_free(rsaEncryptContext);
  EVP_CIPHER_CTX_free(aesEncryptContext);
  EVP_CIPHER_CTX_free(rsaDecryptContext);
  EVP_CIPHER_CTX_free(aesDecryptContext);
  freeMem(aesKey);
  freeMem(aesIv);
end;

function TCrypto._init(): int;
begin
  // Initalize contexts
  rsaEncryptContext := EVP_CIPHER_CTX_new;
  aesEncryptContext := EVP_CIPHER_CTX_new;

  rsaDecryptContext := EVP_CIPHER_CTX_new;
  aesDecryptContext := EVP_CIPHER_CTX_new;

  // Check if any of the contexts initializations failed
  if(rsaEncryptContext = nil) or (aesEncryptContext = nil) or (rsaDecryptContext = nil) or (aesDecryptContext = nil) then
    Exit( FAILURE);


  (* Don't set key or IV right away; we want to set lengths *)
  EVP_CIPHER_CTX_init(aesEncryptContext);
  EVP_CIPHER_CTX_init(aesDecryptContext);

  EVP_CipherInit_ex(aesEncryptContext, EVP_aes_256_cbc, nil, nil, nil, 1);

  (* Now we can set key and IV lengths *)
  aesKeyLength := EVP_CIPHER_CTX_key_length(aesEncryptContext);
  aesIvLength := EVP_CIPHER_CTX_iv_length(aesEncryptContext);

  // Generate RSA and AES keys
  generateRsaKeypair(@localKeypair);
  generateAesKey(@aesKey, @aesIv);

  result := SUCCESS;
end;

constructor TCrypto.Create;
begin
  localKeypair := nil;
  remotePublicKey := nil;
  {$ifdef PSEUDO_CLIENT}
    if generateRsaKeypair(@remotePublicKey) <= 0 then
        Exit;
  {$endif}
  _init();
end;

constructor TCrypto.Create(remotePublicKey: PByte; remotePublicKeyLen: size_t );
begin
   localKeypair := nil;
   Self.remotePublicKey := nil;
  setRemotePublicKey(remotePublicKey, remotePublicKeyLen);
  _init();
end;

function TCrypto.generateRsaKeypair( keypair : PPEVP_PKEY):integer;
var
  context : PEVP_PKEY_CTX;
begin
  context := EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
  if EVP_PKEY_keygen_init(context) <= 0  then
  begin
    Exit(FAILURE);
  end;
  if EVP_PKEY_CTX_set_rsa_keygen_bits(context, RSA_KEYLEN) <= 0  then
  begin
    Exit(FAILURE);
  end;
  if openssl3.crypto.evp.pmeth_gn.EVP_PKEY_keygen(context, keypair) <= 0  then
  begin
    Exit(FAILURE);
  end;
  EVP_PKEY_CTX_free(context);
  Result := SUCCESS;
end;


function TCrypto.generateAesKey( aesKey, aesIv : PPByte):integer;
var
  aesPass, aesSalt : PByte;
begin
  aesKey^ := malloc(aesKeyLength);
  aesIv^  := malloc(aesIvLength);
  if (aesKey = nil)  or  (aesIv = nil) then
  begin
    Exit(FAILURE);
  end;
  // For the AES key we have the option of using a PBKDF or just using straight random
  // data for the key and IV. Depending on your use case, you will want to pick one or another.
  {$IFDEF USE_PBKDF}
    aesPass := (PByte)malloc(aesKeyLength);
    aesSalt := (PByte)malloc(8);
    if aesPass = nil  or  aesSalt = nil then begin
      Exit(FAILURE);
    end;
    // Get some random data to use as the AES pass and salt
    if RAND_bytes(aesPass, aesKeyLength then = 0) begin
      Exit(FAILURE);
    end;
    if RAND_bytes(aesSalt, 8 then = 0) begin
      Exit(FAILURE);
    end;
    if EVP_BytesToKey(EVP_aes_256_cbc, EVP_sha256, aesSalt, aesPass, aesKeyLength, AES_ROUNDS, aesKey, aesIv then = 0) begin
      Exit(FAILURE);
    end;
    free(aesPass);
    free(aesSalt);
  {$ELSE}
  if RAND_bytes( aesKey^, aesKeyLength) = 0  then
  begin
      Exit(FAILURE);
  end;
    if RAND_bytes( aesIv^, aesIvLength)  = 0 then
    begin
      Exit(FAILURE);
    end;
  {$ENDIF}
  Result := SUCCESS;
end;


function TCrypto.rsaEncrypt(const _message : PByte; messageLength : size_t;
                            encryptedMessage, encryptedKey : PPByte;
                            encryptedKeyLength : Psize_t; iv : PPByte;
                            ivLength : Psize_t):integer;
var
  encryptedMessageLength,
  blockLength            : size_t;
begin
  // Allocate memory for everything
  encryptedMessageLength := 0;
  blockLength := 0;
  encryptedKey^ := malloc(EVP_PKEY_size(remotePublicKey));
  iv^ := malloc(EVP_MAX_IV_LENGTH);
  ivLength^ := EVP_MAX_IV_LENGTH;
  if (encryptedKey^ = nil)  or  (iv^ = nil) then
  begin
    Exit(FAILURE);
  end;
  encryptedMessage^ := malloc(messageLength + EVP_MAX_IV_LENGTH);
  if encryptedMessage = nil then
  begin
    Exit(FAILURE);
  end;
  // Encrypt it!
  if 0>=EVP_SealInit(rsaEncryptContext, EVP_aes_256_cbc, encryptedKey, Pinteger(encryptedKeyLength), iv^, @remotePublicKey, 1) then
  begin
    Exit(FAILURE);
  end;
  if 0>=EVP_SealUpdate(rsaEncryptContext, encryptedMessage^ + encryptedMessageLength, PInteger(@blockLength),
                       _message, int(messageLength)) then
  begin
    Exit(FAILURE);
  end;
  encryptedMessageLength  := encryptedMessageLength + blockLength;
  if 0>=EVP_SealFinal(rsaEncryptContext, encryptedMessage^ + encryptedMessageLength, PInteger(@blockLength)) then
  begin
    Exit(FAILURE);
  end;
  encryptedMessageLength  := encryptedMessageLength + blockLength;
  Result := int(encryptedMessageLength);
end;


function TCrypto.rsaDecrypt( encryptedMessage : PByte; encryptedMessageLength : size_t; encryptedKey : PByte; encryptedKeyLength : size_t; iv : PByte; ivLength : size_t; decryptedMessage : PPByte):integer;
var
  decryptedMessageLength,
  blockLength            : size_t;
  key                    : PEVP_PKEY;
begin
  // Allocate memory for everything
  decryptedMessageLength := 0;
  blockLength := 0;
  decryptedMessage^ := malloc(encryptedMessageLength + ivLength);
  if decryptedMessage^ = nil then
  begin
    Exit(FAILURE);
  end;
  {$IFDEF PSEUDO_CLIENT}
    key := remotePublicKey;
  {$ELSE}
    key := localKeypair;
  {$ENDIF}
  // Decrypt it!
  if 0>=EVP_OpenInit(rsaDecryptContext, EVP_aes_256_cbc, encryptedKey, encryptedKeyLength, iv, key) then
  begin
    Exit(FAILURE);
  end;
  if 0>=EVP_OpenUpdate(rsaDecryptContext, decryptedMessage^ + decryptedMessageLength, PInteger(@blockLength),
                       encryptedMessage, int(encryptedMessageLength)) then
  begin
    Exit(FAILURE);
  end;
  decryptedMessageLength  := decryptedMessageLength + blockLength;
  if 0>=EVP_OpenFinal(rsaDecryptContext, decryptedMessage^ + decryptedMessageLength, PInteger(@blockLength)) then
  begin
    Exit(FAILURE);
  end;
  decryptedMessageLength  := decryptedMessageLength + blockLength;
  Result := int(decryptedMessageLength);
end;


function TCrypto.aesEncrypt(const _message : PByte; messageLength : size_t; encryptedMessage : PPByte):integer;
var
  blockLength,
  encryptedMessageLength : size_t;
begin
  // Allocate memory for everything
  blockLength := 0;
  encryptedMessageLength := 0;
  encryptedMessage^ := malloc(messageLength + AES_BLOCK_SIZE);
  if encryptedMessage = nil then begin
    Exit(FAILURE);
  end;
  // Encrypt it!
  if 0>=EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_256_cbc, nil, aesKey, aesIv) then
  begin
    Exit(FAILURE);
  end;
  if 0>=EVP_EncryptUpdate(aesEncryptContext, encryptedMessage^, PInteger(@blockLength), _message, messageLength) then
  begin
    Exit(FAILURE);
  end;
  encryptedMessageLength  := encryptedMessageLength + blockLength;
  if 0>=EVP_EncryptFinal_ex(aesEncryptContext, encryptedMessage^ + encryptedMessageLength, PInteger(@blockLength)) then
  begin
    Exit(FAILURE);
  end;
  Result := encryptedMessageLength + blockLength;
end;


function TCrypto.aesDecrypt( encryptedMessage : PByte; encryptedMessageLength : size_t; decryptedMessage : PPByte):integer;
var
  decryptedMessageLength,
  blockLength            : size_t;
begin
  // Allocate memory for everything
  decryptedMessageLength := 0;
  blockLength := 0;
  decryptedMessage^ := malloc(encryptedMessageLength);
  if decryptedMessage^ = nil then
  begin
    Exit(FAILURE);
  end;
  // Decrypt it!
  if 0>=EVP_DecryptInit_ex(aesDecryptContext, EVP_aes_256_cbc, nil, aesKey, aesIv) then
  begin
    Exit(FAILURE);
  end;
  if 0>=EVP_DecryptUpdate(aesDecryptContext, decryptedMessage^, PInteger(@blockLength), encryptedMessage, int(
                    encryptedMessageLength)) then
  begin
    Exit(FAILURE);
  end;
  decryptedMessageLength  := decryptedMessageLength + blockLength;
  if 0>=EVP_DecryptFinal_ex(aesDecryptContext, decryptedMessage^ + decryptedMessageLength, PInteger(@blockLength)) then
  begin
    Exit(FAILURE);
  end;
  decryptedMessageLength  := decryptedMessageLength + blockLength;
  Result := int(decryptedMessageLength);
end;


function TCrypto.getRemotePublicKey( publicKey : PPByte):integer;
var
  bio : PBIO;
begin
  bio := BIO_new(BIO_s_mem);
  PEM_write_bio_PUBKEY(bio, remotePublicKey);
  Result := bioToString(bio, publicKey);
end;


function TCrypto.setRemotePublicKey( publicKey : PByte; publicKeyLength : size_t):integer;
var
  bio : PBIO;
begin
  bio := BIO_new(BIO_s_mem);
  if BIO_write(bio, publicKey, publicKeyLength) <> int(publicKeyLength)  then
  begin
    Exit(FAILURE);
  end;
  PEM_read_bio_PUBKEY(bio, @remotePublicKey, nil, nil);
  BIO_free_all(bio);
  Result := SUCCESS;
end;


function TCrypto.getLocalPublicKey( publicKey : PPByte):integer;
var
  bio : PBIO;
begin
  bio := BIO_new(BIO_s_mem);
  PEM_write_bio_PUBKEY(bio, localKeypair);
  Result := bioToString(bio, publicKey);
end;


function TCrypto.getLocalPrivateKey( privateKey : PPByte):integer;
var
  bio : PBIO;
begin
  bio := BIO_new(BIO_s_mem);
  PEM_write_bio_PrivateKey(bio, localKeypair, nil, nil, 0, nil, nil);
  Result := bioToString(bio, privateKey);
end;


function TCrypto.getAesKey( aesKey : PPByte):integer;
begin
  aesKey^ := self.aesKey;
  Result := aesKeyLength;
end;


function TCrypto.setAesKey( aesKey : PByte; aesKeyLengthgth : size_t):integer;
begin
  // Ensure the new key is the proper size
  if aesKeyLengthgth <> aesKeyLength then begin
    Exit(FAILURE);
  end;
  memcpy(self.aesKey, aesKey, aesKeyLength);
  Result := SUCCESS;
end;


function TCrypto.getAesIv( aesIv : PPByte):integer;
begin
  aesIv^ := self.aesIv;
  Result := aesIvLength;
end;


function TCrypto.setAesIv( aesIv : PByte; aesIvLengthgth : size_t):integer;
begin
  // Ensure the new IV is the proper size
  if aesIvLengthgth <> aesIvLength then begin
    Exit(FAILURE);
  end;
  memcpy(Self.aesIv, aesIv, aesIvLength);
  Result := SUCCESS;
end;


function TCrypto.writeKeyToFile( &file : PFILE; key : integer):integer;
begin
  case key of
    KEY_SERVER_PRI:
      if 0>=PEM_write_PrivateKey(&file, localKeypair, nil, nil, 0, nil, nil) then
      begin
        Exit(FAILURE);
      end;
      //break;
    KEY_SERVER_PUB:
      if 0>=PEM_write_PUBKEY(&file, localKeypair) then
      begin
        Exit(FAILURE);
      end;
      //break;
    KEY_CLIENT_PUB:
      if 0>=PEM_write_PUBKEY(&file, remotePublicKey) then
      begin
        Exit(FAILURE);
      end;
      //break;
    KEY_AES:
      fwrite(aesKey, 1, aesKeyLength * 8, &file);
      //break;
    KEY_AES_IV:
      fwrite(aesIv, 1, aesIvLength * 8, &file);
      //break;
    else
      Exit(FAILURE);
  end;
  Result := SUCCESS;
end;


function TCrypto.bioToString( bio : PBIO; _string : PPByte):integer;
var
  bioLength : size_t;
begin
  bioLength := BIO_pending(bio);
  _string^ :=  malloc(bioLength + 1);
  if _string = nil then begin
    Exit(FAILURE);
  end;
  BIO_read(bio, _string^, bioLength);
  // Insert the NUL terminator
  (_string^)[bioLength] := Ord(#0);
  BIO_free_all(bio);
  Result := int(bioLength);
end;



end.
