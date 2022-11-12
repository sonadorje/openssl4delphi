unit openssl3.crypto.asn1.p5_pbe;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function PKCS5_pbe_set_ex(alg, iter : integer;const salt : PByte; saltlen : integer; ctx : POSSL_LIB_CTX):PX509_ALGOR;
function PKCS5_pbe_set0_algor_ex(algor : PX509_ALGOR; alg, iter : integer;const salt : PByte; saltlen : integer; ctx : POSSL_LIB_CTX):integer;
function d2i_PBEPARAM(a : PPPBEPARAM;const &in : PPByte; len : long):PPBEPARAM;
function i2d_PBEPARAM(const a : PPBEPARAM; _out : PPByte):integer;
function PBEPARAM_new:PPBEPARAM;
procedure PBEPARAM_free( a : PPBEPARAM);
function PBEPARAM_it:PASN1_ITEM;

var
   PBEPARAM_seq_tt :array of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.evp.evp_lib, OpenSSL3.Err, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.mem, openssl3.crypto.asn1.x_algor,
     openssl3.crypto.asn1.a_int,    openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.asn_pack;




function PBEPARAM_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @PBEPARAM_seq_tt,
         sizeof(PBEPARAM_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
     sizeof(PBEPARAM), 'PBEPARAM');

     Result := @local_it;
end;



function d2i_PBEPARAM(a : PPPBEPARAM;const &in : PPByte; len : long):PPBEPARAM;
begin
 Result := PPBEPARAM (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, PBEPARAM_it));
end;


function i2d_PBEPARAM(const a : PPBEPARAM; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE (a), _out, PBEPARAM_it);
end;


function PBEPARAM_new:PPBEPARAM;
begin
 Result := PPBEPARAM (ASN1_item_new(PBEPARAM_it));
end;


procedure PBEPARAM_free( a : PPBEPARAM);
begin
  ASN1_item_free(PASN1_VALUE(a), PBEPARAM_it);
end;




function PKCS5_pbe_set0_algor_ex(algor : PX509_ALGOR; alg, iter : integer;const salt : PByte; saltlen : integer; ctx : POSSL_LIB_CTX):integer;
var
  pbe : PPBEPARAM;
  pbe_str : PASN1_STRING;
  sstr : PByte;
  label _err;
begin
    pbe := nil;
    pbe_str := nil;
    sstr := nil;
    pbe := PBEPARAM_new();
    if pbe = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if iter <= 0 then iter := PKCS5_DEFAULT_ITER;
    if 0>= ASN1_INTEGER_set(pbe.iter, iter) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if 0>= saltlen then saltlen := PKCS5_SALT_LEN;
    if saltlen < 0 then goto _err ;
    sstr := OPENSSL_malloc(saltlen);
    if sstr = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if salt <> nil then
       memcpy(sstr, salt, saltlen)
    else
    if (RAND_bytes_ex(ctx, sstr, saltlen, 0) <= 0) then
        goto _err ;
    ASN1_STRING_set0(PASN1_STRING(pbe.salt), sstr, saltlen);
    sstr := nil;
    if nil = ASN1_item_pack(pbe, PBEPARAM_it , @pbe_str) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    PBEPARAM_free(pbe);
    pbe := nil;
    if X509_ALGOR_set0(algor, OBJ_nid2obj(alg) , V_ASN1_SEQUENCE, pbe_str) >0 then
        Exit(1);
 _err:
    OPENSSL_free(Pointer(sstr));
    PBEPARAM_free(pbe);
    ASN1_STRING_free(pbe_str);
    Result := 0;
end;




function PKCS5_pbe_set_ex(alg, iter : integer;const salt : PByte; saltlen : integer; ctx : POSSL_LIB_CTX):PX509_ALGOR;
var
  ret : PX509_ALGOR;
begin
    ret := X509_ALGOR_new();
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if PKCS5_pbe_set0_algor_ex(ret, alg, iter, salt, saltlen, ctx) >0 then
        Exit(ret);
    X509_ALGOR_free(ret);
    Result := nil;
end;

initialization
   PBEPARAM_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPBEPARAM(0).salt), 'salt', ASN1_OCTET_STRING_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPBEPARAM(0).iter), 'iter', ASN1_INTEGER_it)
  ] ;


end.
