unit openssl3.crypto.asn1.x_algor;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_x509_algor_mgf1_decode( alg : PX509_ALGOR):PX509_ALGOR;
function X509_ALGOR_it():PASN1_ITEM;
function ossl_X509_ALGOR_from_nid( nid, ptype : integer; pval : Pointer):PX509_ALGOR;
procedure X509_ALGOR_get0(const paobj : PPASN1_OBJECT; pptype : PInteger;const ppval : PPointer; algor : PX509_ALGOR);
function X509_ALGOR_new:PX509_ALGOR;
function X509_ALGOR_set0( alg : PX509_ALGOR; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer):integer;
procedure X509_ALGOR_free( a : PX509_ALGOR);
function ossl_x509_algor_new_from_md(palg : PPX509_ALGOR;const md : PEVP_MD):integer;
procedure X509_ALGOR_set_md(alg : PX509_ALGOR;const md : PEVP_MD);
function ossl_x509_algor_md_to_mgf1(palg : PPX509_ALGOR;const mgf1md : PEVP_MD):integer;
function ossl_x509_algor_get_md( alg : PX509_ALGOR):PEVP_MD;
function X509_ALGOR_cmp(const a, b : PX509_ALGOR):integer;
function d2i_X509_ALGOR(a : PPX509_ALGOR;const _in : PPByte; len : long):PX509_ALGOR;
function i2d_X509_ALGOR(const a : PX509_ALGOR; _out : PPByte):integer;

implementation
 uses OpenSSL3.openssl.asn1t,         openssl3.crypto.objects.obj_dat,
      openssl3.crypto.asn1.asn_pack,  openssl3.crypto.asn1.asn1_lib,
      openssl3.crypto.asn1.tasn_new,  openssl3.crypto.asn1.tasn_typ,
      openssl3.crypto.asn1.tasn_dec,  openssl3.crypto.asn1.tasn_enc,
      openssl3.crypto.asn1.tasn_fre,  openssl3.crypto.evp.evp_lib,
      openssl3.crypto.evp.legacy_sha, openssl3.crypto.evp,
      OpenSSL3.Err,                   openssl3.crypto.objects.obj_lib,
      openssl3.crypto.asn1.a_object,  openssl3.crypto.asn1.a_type;

var
   X509_ALGOR_seq_tt:array[0..1] of TASN1_TEMPLATE ;

function d2i_X509_ALGOR(a : PPX509_ALGOR;const _in : PPByte; len : long):PX509_ALGOR;
begin
 Result := PX509_ALGOR(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_ALGOR_it));
end;


function i2d_X509_ALGOR(const a : PX509_ALGOR; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_ALGOR_it);
end;


function X509_ALGOR_cmp(const a, b : PX509_ALGOR):integer;
var
  rv : integer;
begin
    rv := _OBJ_cmp(a.algorithm, b.algorithm);
    if rv > 0 then Exit(rv);
    if (nil = a.parameter)  and  (nil = b.parameter) then Exit(0);
    Result := ASN1_TYPE_cmp(a.parameter, b.parameter);
end;

function ossl_x509_algor_get_md( alg : PX509_ALGOR):PEVP_MD;
var
  md : PEVP_MD;
begin
    if alg = nil then
       Exit(EVP_sha1());
    md := EVP_get_digestbyobj(alg.algorithm);
    if md = nil then
       ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_DIGEST);
    Result := md;
end;

function ossl_x509_algor_md_to_mgf1(palg : PPX509_ALGOR;const mgf1md : PEVP_MD):integer;
var
  algtmp : PX509_ALGOR;
  stmp : PASN1_STRING;
  label _err;
begin
    algtmp := nil;
    stmp := nil;
    palg^ := nil;
    if (mgf1md = nil)  or  (EVP_MD_is_a(mgf1md, 'SHA1')) then
        Exit(1);
    { need to embed algorithm ID inside another }
    if 0>= ossl_x509_algor_new_from_md(@algtmp, mgf1md ) then
        goto _err ;
    if ASN1_item_pack(algtmp, X509_ALGOR_it , @stmp) = nil  then
         goto _err ;
    palg^ := ossl_X509_ALGOR_from_nid(NID_mgf1, V_ASN1_SEQUENCE, stmp);
    if palg^ = nil then
       goto _err ;
    stmp := nil;
 _err:
    ASN1_STRING_free(stmp);
    X509_ALGOR_free(algtmp);
    Result := Int(palg^ <> nil);
end;

procedure X509_ALGOR_set_md(alg : PX509_ALGOR;const md : PEVP_MD);
var
  _type : integer;
begin
    _type := get_result( (md.flags and EVP_MD_FLAG_DIGALGID_ABSENT)>0 , V_ASN1_UNDEF
                                                       , V_ASN1_NULL);
    X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_get_type(md)), _type, nil);
end;

function ossl_x509_algor_new_from_md(palg : PPX509_ALGOR;const md : PEVP_MD):integer;
var
  alg : PX509_ALGOR;
begin
    { Default is SHA1 so no need to create it - still success }
    if (md = nil)  or  (EVP_MD_is_a(md, 'SHA1')) then
        Exit(1);
    alg := X509_ALGOR_new();
    if alg =  nil then
        Exit(0);
    X509_ALGOR_set_md(alg, md);
    palg^ := alg;
    Result := 1;
end;

procedure X509_ALGOR_free( a : PX509_ALGOR);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_ALGOR_it);
end;

function X509_ALGOR_set0( alg : PX509_ALGOR; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer):integer;
begin
    if alg = nil then
       Exit(0);
    alg.parameter := ASN1_TYPE_new();
    if (ptype <> V_ASN1_UNDEF)  and  (alg.parameter = nil)
             and  (alg.parameter = nil) then
        Exit(0);
    ASN1_OBJECT_free(alg.algorithm);
    alg.algorithm := aobj;
    if ptype = V_ASN1_EOC then
       Exit(1);
    if ptype = V_ASN1_UNDEF then
    begin
        ASN1_TYPE_free(alg.parameter);
        alg.parameter := nil;
    end
    else
        ASN1_TYPE_set(alg.parameter, ptype, pval);
    Result := 1;
end;

function X509_ALGOR_new:PX509_ALGOR;
begin
   result := ASN1_item_new(X509_ALGOR_it);
end;

procedure X509_ALGOR_get0(const paobj : PPASN1_OBJECT; pptype : PInteger;const ppval : PPointer; algor : PX509_ALGOR);
begin
    if paobj <> nil then
       paobj^ := algor.algorithm;
    if pptype <> nil then
    begin
        if algor.parameter = nil then
        begin
            pptype^ := V_ASN1_UNDEF;
            exit;
        end
        else
            pptype^ := algor.parameter._type;
        if ppval <> nil then
           ppval^ := algor.parameter.value.ptr;
    end;
end;





function ossl_X509_ALGOR_from_nid( nid, ptype : integer; pval : Pointer):PX509_ALGOR;
var
  algo : PASN1_OBJECT;

  alg : PX509_ALGOR;
  label _err;
begin
    algo := OBJ_nid2obj(nid);
    alg := nil;
    if algo = nil then Exit(nil);
    alg := X509_ALGOR_new();
    if alg = nil then
        goto _err ;
    if X509_ALGOR_set0(alg, algo, ptype, pval )>0 then
        Exit(alg);
    alg.algorithm := nil; { precaution to prevent double free }
 _err:
    X509_ALGOR_free(alg);
    { ASN1_OBJECT_free(algo) is not needed due to OBJ_nid2obj() }
    Result := nil;
end;

const
    local_it: TASN1_ITEM = (
      itype:ASN1_ITYPE_SEQUENCE;
      utype:V_ASN1_SEQUENCE;
      templates:@X509_ALGOR_seq_tt;
      tcount:sizeof(X509_ALGOR_seq_tt) div sizeof(TASN1_TEMPLATE);
      funcs:nil;
      size:sizeof(TX509_ALGOR);
      sname:'X509_ALGOR';
     );

function X509_ALGOR_it():PASN1_ITEM;
begin
  Result := @local_it;
end;

function ossl_x509_algor_mgf1_decode( alg : PX509_ALGOR):PX509_ALGOR;
begin
    if OBJ_obj2nid(alg.algorithm) <> NID_mgf1  then
        Exit(nil);
    Exit(ASN1_TYPE_unpack_sequence(X509_ALGOR_it(),
                                     alg.parameter));
end;

initialization
  X509_ALGOR_seq_tt[0] := get_ASN1_TEMPLATE(0,  0, size_t(@TX509_ALGOR(nil^).algorithm), 'algorithm', ASN1_OBJECT_it );
  X509_ALGOR_seq_tt[1] := get_ASN1_TEMPLATE($1, 0, size_t(@TX509_ALGOR(nil^).parameter), 'parameter', ASN1_ANY_it );

end.
