unit openssl3.crypto.x509.x_x509a;

interface
uses OpenSSL.Api;

function X509_trusted(const x : PX509):integer;
  function aux_get( x : PX509):PX509_CERT_AUX;
  function X509_alias_set1(x : PX509;const name : PByte; len : integer):integer;
  function X509_keyid_set1(x : PX509;const id : PByte; len : integer):integer;
  function X509_alias_get0( x : PX509; len : PInteger):PByte;
  function X509_keyid_get0( x : PX509; len : PInteger):PByte;
  function X509_add1_trust_object(x : PX509;const obj : PASN1_OBJECT):integer;
  function X509_add1_reject_object(x : PX509;const obj : PASN1_OBJECT):integer;
  procedure X509_trust_clear( x : PX509);
  procedure X509_reject_clear( x : PX509);
  function X509_get0_trust_objects( x : PX509):Pstack_st_ASN1_OBJECT;
  function X509_get0_reject_objects( x : PX509):Pstack_st_ASN1_OBJECT;
  function d2i_X509_CERT_AUX(a : PPX509_CERT_AUX;const _in : PPByte; len : long):PX509_CERT_AUX;
  function i2d_X509_CERT_AUX(const a : PX509_CERT_AUX; _out : PPByte):integer;
  function X509_CERT_AUX_new:PX509_CERT_AUX;
  procedure X509_CERT_AUX_free( a : PX509_CERT_AUX);
  function X509_CERT_AUX_it:PASN1_ITEM;

var
   X509_CERT_AUX_seq_tt: array[0..4] of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.a_i2d_fp,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.objects.obj_lib,
     OpenSSL3.include.openssl.asn1, openssl3.crypto.asn1.a_object,
     openssl3.crypto.asn1.x_algor;






function X509_CERT_AUX_it:PASN1_ITEM;
const
  local_it: TASN1_ITEM = (
      itype:   $1;
      utype:  16;
      templates: @X509_CERT_AUX_seq_tt;
      tcount:  sizeof(X509_CERT_AUX_seq_tt) div sizeof(TASN1_TEMPLATE);
      funcs: Pointer(0) ;
      size:  sizeof(TX509_CERT_AUX);
      sname: 'X509_CERT_AUX' );
begin
  result := @local_it;
end;




function d2i_X509_CERT_AUX(a : PPX509_CERT_AUX;const _in : PPByte; len : long):PX509_CERT_AUX;
begin
  Result := PX509_CERT_AUX( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_CERT_AUX_it));
end;


function i2d_X509_CERT_AUX(const a : PX509_CERT_AUX; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_CERT_AUX_it);
end;


function X509_CERT_AUX_new:PX509_CERT_AUX;
begin
  Result := PX509_CERT_AUX( ASN1_item_new(X509_CERT_AUX_it));
end;


procedure X509_CERT_AUX_free( a : PX509_CERT_AUX);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_CERT_AUX_it);
end;

function X509_trusted(const x : PX509):integer;
begin
    Result := get_result(x.aux <> nil , 1 , 0);
end;


function aux_get( x : PX509):PX509_CERT_AUX;
begin
    if x = nil then Exit(nil);
    if x.aux = nil  then
    begin
       x.aux := X509_CERT_AUX_new();
      if (x.aux = nil) then
        Exit(nil);
    end;
    Result := x.aux;
end;


function X509_alias_set1(x : PX509;const name : PByte; len : integer):integer;
var
  aux : PX509_CERT_AUX;
begin
    if nil = name then
    begin
        if (nil = x)  or  (nil = x.aux)  or  (nil = x.aux.alias) then
            Exit(1);
        ASN1_UTF8STRING_free(x.aux.alias);
        x.aux.alias := nil;
        Exit(1);
    end;
    aux := aux_get(x);
    if aux = nil then
        Exit(0);
    aux.alias := ASN1_UTF8STRING_new;
    if (aux.alias = nil)  and  (aux.alias = nil) then
        Exit(0);
    Result := ASN1_STRING_set(PASN1_STRING(aux.alias), name, len);
end;


function X509_keyid_set1(x : PX509;const id : PByte; len : integer):integer;
var
  aux : PX509_CERT_AUX;
begin
    if nil = id then
    begin
        if (nil = x)  or  (nil = x.aux)  or  (nil = x.aux.keyid) then
            Exit(1);
        ASN1_OCTET_STRING_free(x.aux.keyid);
        x.aux.keyid := nil;
        Exit(1);
    end;
    aux := aux_get(x);
    if aux = nil then
        Exit(0);
    if aux.keyid = nil then
    begin
        aux.keyid := ASN1_OCTET_STRING_new;
        if aux.keyid = nil then
        Exit(0);
    end;
    Result := ASN1_STRING_set(PASN1_STRING(aux.keyid), id, len);
end;


function X509_alias_get0( x : PX509; len : PInteger):PByte;
begin
    if (nil = x.aux)  or  (nil = x.aux.alias) then
       Exit(nil);
    if len <> nil then
       len^ := x.aux.alias.length;
    Result := x.aux.alias.data;
end;


function X509_keyid_get0( x : PX509; len : PInteger):PByte;
begin
    if (nil = x.aux)  or  (nil = x.aux.keyid) then
       Exit(nil);
    if len <> nil then
       len^ := x.aux.keyid.length;
    Result := x.aux.keyid.data;
end;


function X509_add1_trust_object(x : PX509;const obj : PASN1_OBJECT):integer;
var
  aux : PX509_CERT_AUX;

  objtmp : PASN1_OBJECT;
  label _err;
begin
    objtmp := nil;
    if obj <> nil then
    begin
        objtmp := OBJ_dup(obj);
        if nil = objtmp then
           Exit(0);
    end;
    aux := aux_get(x);
    if aux = nil then
        goto _err ;
    if aux.trust = nil then
    begin
        aux.trust := sk_ASN1_OBJECT_new_null;
        if aux.trust = nil then
           goto _err ;
    end;
    if (nil = objtmp)  or  (sk_ASN1_OBJECT_push(aux.trust, objtmp)>0) then
        Exit(1);
 _err:
    ASN1_OBJECT_free(objtmp);
    Result := 0;
end;


function X509_add1_reject_object(x : PX509;const obj : PASN1_OBJECT):integer;
var
  aux : PX509_CERT_AUX;

  objtmp : PASN1_OBJECT;

  res : integer;
  label _err;
begin
    res := 0;
    objtmp := OBJ_dup(obj);
    if objtmp = nil then
        Exit(0);
     aux := aux_get(x);
    if aux = nil then
        goto _err ;
    if aux.reject = nil then
    begin
       aux.reject := sk_ASN1_OBJECT_new_null;
       if aux.reject = nil then
          goto _err ;
    end;
    if sk_ASN1_OBJECT_push(aux.reject, objtmp) > 0  then
        res := 1;
 _err:
    if 0>= res then
       ASN1_OBJECT_free(objtmp);
    Result := res;
end;


procedure X509_trust_clear( x : PX509);
begin
    if x.aux <> nil then
    begin
        sk_ASN1_OBJECT_pop_free(x.aux.trust, ASN1_OBJECT_free);
        x.aux.trust := nil;
    end;
end;


procedure X509_reject_clear( x : PX509);
begin
    if x.aux <> nil then
    begin
        sk_ASN1_OBJECT_pop_free(x.aux.reject, ASN1_OBJECT_free);
        x.aux.reject := nil;
    end;
end;


function X509_get0_trust_objects( x : PX509):Pstack_st_ASN1_OBJECT;
begin
    if x.aux <> nil then Exit(x.aux.trust);
    Result := nil;
end;


function X509_get0_reject_objects( x : PX509):Pstack_st_ASN1_OBJECT;
begin
    if x.aux <> nil then Exit(x.aux.reject);
    Result := nil;
end;

initialization

  X509_CERT_AUX_seq_tt[0] := get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), 0, size_t(@PX509_CERT_AUX(0).trust), 'trust', ASN1_OBJECT_it );
  X509_CERT_AUX_seq_tt[1] := get_ASN1_TEMPLATE( ((($1 shl 3) or ($2 shl 6))  or  (($2 shl 1) or ($1))), 0, size_t(@PX509_CERT_AUX(0).reject), 'reject', ASN1_OBJECT_it );
  X509_CERT_AUX_seq_tt[2] := get_ASN1_TEMPLATE( (($1)), 0, size_t(@PX509_CERT_AUX(0).alias), 'alias', ASN1_UTF8STRING_it );
  X509_CERT_AUX_seq_tt[3] := get_ASN1_TEMPLATE( (($1)), 0, size_t(@PX509_CERT_AUX(0).keyid), 'keyid', ASN1_OCTET_STRING_it );
  X509_CERT_AUX_seq_tt[4] := get_ASN1_TEMPLATE( ((($1 shl 3) or ($2 shl 6))  or  (($2 shl 1) or ($1))), 1, size_t(@PX509_CERT_AUX(0).other), 'other', X509_ALGOR_it );

end.
