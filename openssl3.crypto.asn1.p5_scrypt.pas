unit openssl3.crypto.asn1.p5_scrypt;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function PKCS5_v2_scrypt_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function PKCS5_v2_scrypt_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
function SCRYPT_PARAMS_it:PASN1_ITEM;

function d2i_SCRYPT_PARAMS(a : PPSCRYPT_PARAMS;const &in : PPByte; len : long):PSCRYPT_PARAMS;
  function i2d_SCRYPT_PARAMS(const a : PSCRYPT_PARAMS; _out : PPByte):integer;
  function SCRYPT_PARAMS_new:PSCRYPT_PARAMS;
  procedure SCRYPT_PARAMS_free( a : PSCRYPT_PARAMS);


var
   SCRYPT_PARAMS_seq_tt: array of TASN1_TEMPLATE;

implementation
 uses OpenSSL3.openssl.asn1t, openssl3.crypto.evp.evp_lib, OpenSSL3.Err,
      openssl3.crypto.asn1.a_int,  openssl3.crypto.evp.evp_enc,
      openssl3.crypto.mem,         openssl3.crypto.asn1.tasn_dec,
      openssl3.crypto.asn1.tasn_enc,  openssl3.crypto.asn1.tasn_new,
      openssl3.crypto.asn1.tasn_fre,  openssl3.crypto.asn1.tasn_typ,
      openssl3.crypto.evp.pbe_scrypt, openssl3.crypto.asn1.a_type;





function d2i_SCRYPT_PARAMS(a : PPSCRYPT_PARAMS;const &in : PPByte; len : long):PSCRYPT_PARAMS;
begin
 Result := PSCRYPT_PARAMS (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, SCRYPT_PARAMS_it));
end;


function i2d_SCRYPT_PARAMS(const a : PSCRYPT_PARAMS; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE (a), _out, SCRYPT_PARAMS_it);
end;


function SCRYPT_PARAMS_new:PSCRYPT_PARAMS;
begin
 Result := PSCRYPT_PARAMS (ASN1_item_new(SCRYPT_PARAMS_it));
end;


procedure SCRYPT_PARAMS_free( a : PSCRYPT_PARAMS);
begin
   ASN1_item_free(PASN1_VALUE(a), SCRYPT_PARAMS_it);
end;



function SCRYPT_PARAMS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @SCRYPT_PARAMS_seq_tt,
                sizeof(SCRYPT_PARAMS_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                sizeof(SCRYPT_PARAMS), 'SCRYPT_PARAMS');

        Result := @local_it;
end;




function PKCS5_v2_scrypt_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  p,
  r,
  N        : uint64;
  key: array[0..EVP_MAX_KEY_LENGTH-1] of Byte;
  salt:  PByte;
  saltlen,
  keylen   : size_t;
  t,
  rv       : integer;
  sparam   : PSCRYPT_PARAMS;
  spkeylen : uint64;
  label _err;
begin

    keylen := 0;
    rv := 0;
    sparam := nil;
    if EVP_CIPHER_CTX_get0_cipher(ctx) = nil  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        goto _err ;
    end;
    { Decode parameter }
    sparam := ASN1_TYPE_unpack_sequence(SCRYPT_PARAMS_it, param);
    if sparam = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto _err ;
    end;
    t := EVP_CIPHER_CTX_get_key_length(ctx);
    if t < 0 then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
        goto _err ;
    end;
    keylen := t;
    { Now check the parameters of sparam }
    if sparam.keyLength <> nil then
    begin
        if (ASN1_INTEGER_get_uint64(@spkeylen, sparam.keyLength) = 0 )
             or  (spkeylen <> keylen) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH);
            goto _err ;
        end;
    end;
    { Check all parameters fit in uint64_t and are acceptable to scrypt }
    if (ASN1_INTEGER_get_uint64(@N, sparam.costParameter) = 0)
         or  (ASN1_INTEGER_get_uint64(@r, sparam.blockSize) = 0)
         or  (ASN1_INTEGER_get_uint64(@p, sparam.parallelizationParameter) = 0 )
         or  (EVP_PBE_scrypt_ex(nil, 0, nil, 0, N, r, p, 0, nil, 0,
                             libctx, propq) = 0) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_ILLEGAL_SCRYPT_PARAMETERS);
        goto _err ;
    end;
    { it seems that its all OK }
    salt := sparam.salt.data;
    saltlen := sparam.salt.length;
    if EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, N, r, p, 0, @key,
                          keylen, libctx, propq) = 0  then
        goto _err ;
    rv := EVP_CipherInit_ex(ctx, nil, nil, @key, nil, en_de);
 _err:
    if keylen>0 then
       OPENSSL_cleanse(@key, keylen);
    SCRYPT_PARAMS_free(sparam);
    Result := rv;
end;


function PKCS5_v2_scrypt_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
begin
    Result := PKCS5_v2_scrypt_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, nil, nil);
end;

initialization
   SCRYPT_PARAMS_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PSCRYPT_PARAMS(0).salt), 'salt', ASN1_OCTET_STRING_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PSCRYPT_PARAMS(0).costParameter), 'costParameter', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PSCRYPT_PARAMS(0).blockSize), 'blockSize', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PSCRYPT_PARAMS(0).parallelizationParameter), 'parallelizationParameter', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@PSCRYPT_PARAMS(0).keyLength), 'keyLength', ASN1_INTEGER_it)
] ;

end.
