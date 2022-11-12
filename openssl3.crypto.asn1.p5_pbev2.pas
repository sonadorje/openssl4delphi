unit openssl3.crypto.asn1.p5_pbev2;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function PKCS5_pbe2_set_iv_ex(const cipher : PEVP_CIPHER; iter : integer; salt : PByte; saltlen : integer; aiv : PByte; prf_nid : integer; libctx : POSSL_LIB_CTX):PX509_ALGOR;
function PKCS5_pbkdf2_set_ex( iter : integer; salt : PByte; saltlen, prf_nid, keylen : integer; libctx : POSSL_LIB_CTX):PX509_ALGOR;
 function PBKDF2PARAM_it:PASN1_ITEM;

 function d2i_PBKDF2PARAM(a : PPPBKDF2PARAM;const &in : PPByte; len : long):PPBKDF2PARAM;
  function i2d_PBKDF2PARAM(const a : PPBKDF2PARAM; _out : PPByte):integer;
  function PBKDF2PARAM_new:PPBKDF2PARAM;
  procedure PBKDF2PARAM_free( a : PPBKDF2PARAM);

  function d2i_PBE2PARAM(a : PPPBE2PARAM;const &in : PPByte; len : long):PPBE2PARAM;
  function i2d_PBE2PARAM(const a : PPBE2PARAM; _out : PPByte):integer;
  function PBE2PARAM_new:PPBE2PARAM;
  procedure PBE2PARAM_free( a : PPBE2PARAM);
  function PBE2PARAM_it:PASN1_ITEM;

var
  PBKDF2PARAM_seq_tt: array[0..3] of TASN1_TEMPLATE ;
  PBE2PARAM_seq_tt: array of TASN1_TEMPLATE ;

implementation
uses openssl3.crypto.evp.evp_lib, OpenSSL3.Err, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.mem, openssl3.crypto.asn1.x_algor,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.a_type,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.evp.evp_enc,   openssl3.providers.fips.fipsprov,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_int;


function PBE2PARAM_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @PBE2PARAM_seq_tt,
            sizeof(PBE2PARAM_seq_tt) div sizeof(TASN1_TEMPLATE),
      Pointer(0) , sizeof(PBE2PARAM), 'PBE2PARAM');

      Result := @local_it;
end;




function d2i_PBE2PARAM(a : PPPBE2PARAM;const &in : PPByte; len : long):PPBE2PARAM;
begin
 Result := PPBE2PARAM (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, PBE2PARAM_it));
end;


function i2d_PBE2PARAM(const a : PPBE2PARAM; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE (a), _out, PBE2PARAM_it);
end;


function PBE2PARAM_new:PPBE2PARAM;
begin
 Result := PPBE2PARAM (ASN1_item_new(PBE2PARAM_it));
end;


procedure PBE2PARAM_free( a : PPBE2PARAM);
begin
 ASN1_item_free(PASN1_VALUE(a), PBE2PARAM_it);
end;





function d2i_PBKDF2PARAM(a : PPPBKDF2PARAM;const &in : PPByte; len : long):PPBKDF2PARAM;
begin
 Result := PPBKDF2PARAM  (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, PBKDF2PARAM_it));
end;


function i2d_PBKDF2PARAM(const a : PPBKDF2PARAM; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE (a), _out, PBKDF2PARAM_it);
end;


function PBKDF2PARAM_new:PPBKDF2PARAM;
begin
 Result := PPBKDF2PARAM(ASN1_item_new(PBKDF2PARAM_it));
end;


procedure PBKDF2PARAM_free( a : PPBKDF2PARAM);
begin
 ASN1_item_free(PASN1_VALUE(a), PBKDF2PARAM_it);
end;




function PBKDF2PARAM_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @PBKDF2PARAM_seq_tt,
                     sizeof(PBKDF2PARAM_seq_tt) div sizeof(TASN1_TEMPLATE),
                     Pointer(0) , sizeof(TPBKDF2PARAM), 'PBKDF2PARAM' );
   Result := @local_it;
end;

function PKCS5_pbkdf2_set_ex( iter : integer; salt : PByte; saltlen, prf_nid, keylen : integer; libctx : POSSL_LIB_CTX):PX509_ALGOR;
var
  keyfunc : PX509_ALGOR;
  kdf : PPBKDF2PARAM;
  osalt : PASN1_OCTET_STRING;
  label _merr;
begin
    keyfunc := nil;
    kdf := nil;
    osalt := nil;
    kdf := PBKDF2PARAM_new();
    if kdf = nil then
        goto _merr ;
    osalt := ASN1_OCTET_STRING_new();
    if osalt =  nil then
        goto _merr ;
    kdf.salt.value.octet_string := osalt;
    kdf.salt._type := V_ASN1_OCTET_STRING;
    if saltlen < 0 then goto _merr ;
    if saltlen = 0 then saltlen := PKCS5_SALT_LEN;
    osalt.data := OPENSSL_malloc(saltlen);
    if osalt.data = nil then
        goto _merr ;
    osalt.length := saltlen;
    if salt <> nil then
       memcpy(osalt.data, salt, saltlen)
    else
    if (RAND_bytes_ex(libctx, osalt.data, saltlen, 0) <= 0) then
        goto _merr ;
    if iter <= 0 then
       iter := PKCS5_DEFAULT_ITER;
    if 0>= ASN1_INTEGER_set(kdf.iter, iter) then
        goto _merr ;
    { If have a key len set it up }
    if keylen > 0 then
    begin
        kdf.keylength := ASN1_INTEGER_new();
        if (kdf.keylength) = nil then
            goto _merr ;
        if 0>= ASN1_INTEGER_set(kdf.keylength, keylen) then
            goto _merr ;
    end;
    { prf can stay nil if we are using hmacWithSHA1 }
    if (prf_nid > 0)  and  (prf_nid <> NID_hmacWithSHA1) then
    begin
        kdf.prf := ossl_X509_ALGOR_from_nid(prf_nid, V_ASN1_NULL, nil);
        if kdf.prf = nil then goto _merr ;
    end;
    { Finally setup the keyfunc structure }
    keyfunc := X509_ALGOR_new();
    if keyfunc = nil then goto _merr ;
    keyfunc.algorithm := OBJ_nid2obj(NID_id_pbkdf2);
    { Encode PBKDF2PARAM into parameter of pbe2 }
    if nil = ASN1_TYPE_pack_sequence(PBKDF2PARAM_it, kdf,
                                 @keyfunc.parameter)  then
         goto _merr ;
    PBKDF2PARAM_free(kdf);
    Exit(keyfunc);
 _merr:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    PBKDF2PARAM_free(kdf);
    X509_ALGOR_free(keyfunc);
    Result := nil;
end;

function PKCS5_pbe2_set_iv_ex(const cipher : PEVP_CIPHER; iter : integer; salt : PByte; saltlen : integer; aiv : PByte; prf_nid : integer; libctx : POSSL_LIB_CTX):PX509_ALGOR;
var
  scheme, ret : PX509_ALGOR;

  alg_nid, keylen, ivlen : integer;

  ctx : PEVP_CIPHER_CTX;

  iv : array[0..(EVP_MAX_IV_LENGTH)-1] of Byte;

  pbe2 : PPBE2PARAM;
  label _err,  _merr;
begin
    scheme := nil; ret := nil;
    ctx := nil;
    pbe2 := nil;
    alg_nid := EVP_CIPHER_get_type(cipher);
    if alg_nid = NID_undef then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        goto _err ;
    end;
    pbe2 := PBE2PARAM_new();
    if pbe2  = nil then
        goto _merr ;
    { Setup the AlgorithmIdentifier for the encryption scheme }
    scheme := pbe2.encryption;
    scheme.algorithm := OBJ_nid2obj(alg_nid);
    scheme.parameter := ASN1_TYPE_new();
    if scheme.parameter = nil then
        goto _merr ;
    { Create random IV }
    ivlen := EVP_CIPHER_get_iv_length(cipher);
    if ivlen > 0 then
    begin
        if aiv <> nil then
            memcpy(@iv, aiv, ivlen)
        else
        if (RAND_bytes_ex(libctx, @iv, ivlen, 0) <= 0) then
            goto _err ;
    end;
    ctx := EVP_CIPHER_CTX_new();
    if ctx = nil then
       goto _merr ;
    { Dummy cipherinit to just setup the IV, and PRF }
    if 0>= EVP_CipherInit_ex(ctx, cipher, nil, nil, @iv, 0 ) then
        goto _err ;
    if EVP_CIPHER_param_to_asn1(ctx, scheme.parameter) <= 0  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        goto _err ;
    end;
    {
     * If prf NID unspecified see if cipher has a preference. An error is OK
     * here: just means use default PRF.
     }
    ERR_set_mark();
    if (prf_nid = -1 )  and
       ( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_PBE_PRF_NID, 0, @prf_nid) <= 0) then
    begin
        prf_nid := NID_hmacWithSHA256;
    end;
    ERR_pop_to_mark();
    EVP_CIPHER_CTX_free(ctx);
    ctx := nil;
    { If its RC2 then we'd better setup the key length }
    if alg_nid = NID_rc2_cbc then
       keylen := EVP_CIPHER_get_key_length(cipher)
    else
        keylen := -1;
    { Setup keyfunc }
    X509_ALGOR_free(pbe2.keyfunc);
    pbe2.keyfunc := PKCS5_pbkdf2_set_ex(iter, salt, saltlen, prf_nid, keylen,
                                        libctx);
    if pbe2.keyfunc = nil then goto _merr ;
    { Now set up top level AlgorithmIdentifier }
    ret := X509_ALGOR_new();
    if ret = nil then
        goto _merr ;
    ret.algorithm := OBJ_nid2obj(NID_pbes2);
    { Encode PBE2PARAM into parameter }
    if nil = ASN1_TYPE_pack_sequence(PBE2PARAM_it , pbe2,
                                 @ret.parameter) then
         goto _merr ;
    PBE2PARAM_free(pbe2);
    pbe2 := nil;
    Exit(ret);
 _merr:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
 _err:
    EVP_CIPHER_CTX_free(ctx);
    PBE2PARAM_free(pbe2);
    { Note 'scheme' is freed as part of pbe2 }
    X509_ALGOR_free(ret);
    Result := nil;
end;

initialization

PBKDF2PARAM_seq_tt[0] := get_ASN1_TEMPLATE( 0,  0, size_t(@PPBKDF2PARAM(0).salt), 'salt', ASN1_ANY_it );
PBKDF2PARAM_seq_tt[1] := get_ASN1_TEMPLATE( 0,  0, size_t(@PPBKDF2PARAM(0).iter), 'iter', ASN1_INTEGER_it );
PBKDF2PARAM_seq_tt[2] := get_ASN1_TEMPLATE( $1, 0, size_t(@PPBKDF2PARAM(0).keylength), 'keylength', ASN1_INTEGER_it );
PBKDF2PARAM_seq_tt[3] := get_ASN1_TEMPLATE( $1, 0, size_t(@PPBKDF2PARAM(0).prf), 'prf', X509_ALGOR_it );

 PBE2PARAM_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPBE2PARAM(0).keyfunc), 'keyfunc', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPBE2PARAM(0).encryption), 'encryption', X509_ALGOR_it)
] ;

end.
