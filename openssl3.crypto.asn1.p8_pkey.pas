unit openssl3.crypto.asn1.p8_pkey;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function pkey_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
  function PKCS8_pkey_set0( priv : PPKCS8_PRIV_KEY_INFO; aobj : PASN1_OBJECT; version, ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;
  function PKCS8_pkey_get0(const ppkalg : PPASN1_OBJECT; pk : PPByte; ppklen : PInteger;const pa : PPX509_ALGOR; p8 : PPKCS8_PRIV_KEY_INFO):integer;
  function PKCS8_pkey_get0_attrs(const p8 : PPKCS8_PRIV_KEY_INFO):Pstack_st_X509_ATTRIBUTE;
  function PKCS8_pkey_add1_attr_by_NID(p8 : PPKCS8_PRIV_KEY_INFO; nid, _type : integer;const bytes : PByte; len : integer):integer;
  function PKCS8_pkey_add1_attr_by_OBJ(p8 : PPKCS8_PRIV_KEY_INFO;const obj : PASN1_OBJECT; &type : integer;const bytes : PByte; len : integer):integer;
  function PKCS8_pkey_add1_attr(p8 : PPKCS8_PRIV_KEY_INFO; attr : PX509_ATTRIBUTE):integer;
  function PKCS8_PRIV_KEY_INFO_it:PASN1_ITEM;
  function d2i_PKCS8_PRIV_KEY_INFO(a : PPPKCS8_PRIV_KEY_INFO;const _in : PPByte; len : long):PPKCS8_PRIV_KEY_INFO;


  function i2d_PKCS8_PRIV_KEY_INFO(const a : PPKCS8_PRIV_KEY_INFO; _out : PPByte):integer;
  function PKCS8_PRIV_KEY_INFO_new:PPKCS8_PRIV_KEY_INFO;
  procedure PKCS8_PRIV_KEY_INFO_free( a : PPKCS8_PRIV_KEY_INFO);

var
  PKCS8_PRIV_KEY_INFO_seq_tt :array of TASN1_TEMPLATE;
  PKCS8_PRIV_KEY_INFO_aux:  TASN1_AUX;

implementation
uses openssl3.crypto.mem, openssl3.crypto.asn1.a_int, openssl3.crypto.asn1.x_algor,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.x509.x509_att,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.x509.x_attrib;



function i2d_PKCS8_PRIV_KEY_INFO(const a : PPKCS8_PRIV_KEY_INFO; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, PKCS8_PRIV_KEY_INFO_it);
end;


function PKCS8_PRIV_KEY_INFO_new:PPKCS8_PRIV_KEY_INFO;
begin
   Result := PPKCS8_PRIV_KEY_INFO (ASN1_item_new(PKCS8_PRIV_KEY_INFO_it));
end;


procedure PKCS8_PRIV_KEY_INFO_free( a : PPKCS8_PRIV_KEY_INFO);
begin
   ASN1_item_free(PASN1_VALUE(a), PKCS8_PRIV_KEY_INFO_it);
end;


function d2i_PKCS8_PRIV_KEY_INFO(a : PPPKCS8_PRIV_KEY_INFO;const _in : PPByte; len : long):PPKCS8_PRIV_KEY_INFO;
begin
 Result := PPKCS8_PRIV_KEY_INFO(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, PKCS8_PRIV_KEY_INFO_it));
end;




function PKCS8_PRIV_KEY_INFO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @PKCS8_PRIV_KEY_INFO_seq_tt,
                 sizeof(PKCS8_PRIV_KEY_INFO_seq_tt) div sizeof(TASN1_TEMPLATE),
                 @PKCS8_PRIV_KEY_INFO_aux, sizeof(TPKCS8_PRIV_KEY_INFO), 'PKCS8_PRIV_KEY_INFO');

   Result := @local_it;
end;

function pkey_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  key : PPKCS8_PRIV_KEY_INFO;
begin
    { Since the structure must still be valid use ASN1_OP_FREE_PRE }
    if operation = ASN1_OP_FREE_PRE then
    begin
        key := PPKCS8_PRIV_KEY_INFO(pval^);
        if key.pkey <> nil then
           OPENSSL_cleanse(key.pkey.data, key.pkey.length);
    end;
    Result := 1;
end;


function PKCS8_pkey_set0( priv : PPKCS8_PRIV_KEY_INFO; aobj : PASN1_OBJECT; version, ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;
begin
    if version >= 0 then
    begin
        if 0>= ASN1_INTEGER_set(priv.version, version) then
            Exit(0);
    end;
    if 0>= X509_ALGOR_set0(priv.pkeyalg, aobj, ptype, pval) then
        Exit(0);
    if penc <> nil then
       ASN1_STRING_set0(PASN1_STRING(priv.pkey), penc, penclen);
    Result := 1;
end;


function PKCS8_pkey_get0(const ppkalg : PPASN1_OBJECT; pk : PPByte; ppklen : PInteger;const pa : PPX509_ALGOR; p8 : PPKCS8_PRIV_KEY_INFO):integer;
begin
    if ppkalg <> nil then
       ppkalg^ := p8.pkeyalg.algorithm;
    if pk <> nil then
    begin
        pk^ := ASN1_STRING_get0_data(PASN1_STRING(p8.pkey));
        ppklen^ := ASN1_STRING_length(PASN1_STRING(p8.pkey));
    end;
    if pa <> nil then
       pa^ := p8.pkeyalg;
    Result := 1;
end;


function PKCS8_pkey_get0_attrs(const p8 : PPKCS8_PRIV_KEY_INFO):Pstack_st_X509_ATTRIBUTE;
begin
    Result := p8.attributes;
end;


function PKCS8_pkey_add1_attr_by_NID(p8 : PPKCS8_PRIV_KEY_INFO; nid, _type : integer;const bytes : PByte; len : integer):integer;
begin
    if X509at_add1_attr_by_NID(@p8.attributes, nid, _type, bytes, len) <> nil  then
        Exit(1);
    Result := 0;
end;


function PKCS8_pkey_add1_attr_by_OBJ(p8 : PPKCS8_PRIV_KEY_INFO;const obj : PASN1_OBJECT; &type : integer;const bytes : PByte; len : integer):integer;
begin
    Result := int(X509at_add1_attr_by_OBJ(@p8.attributes, obj, &type, bytes, len) <> nil);
end;


function PKCS8_pkey_add1_attr(p8 : PPKCS8_PRIV_KEY_INFO; attr : PX509_ATTRIBUTE):integer;
begin
    Result := int(X509at_add1_attr(@p8.attributes, attr) <> nil);
end;

initialization
   PKCS8_PRIV_KEY_INFO_aux :=  get_ASN1_AUX(Pointer(0) , 0, 0, 0, pkey_cb, 0, Pointer(0) );

   PKCS8_PRIV_KEY_INFO_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPKCS8_PRIV_KEY_INFO(0).version), 'version', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPKCS8_PRIV_KEY_INFO(0).pkeyalg), 'pkeyalg', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PPKCS8_PRIV_KEY_INFO(0).pkey), 'pkey', ASN1_OCTET_STRING_it) ,
        get_ASN1_TEMPLATE( ((($1 shl 3) or ($2 shl 6)) or (($1 shl 1) or ($1))), 0, size_t(@PPKCS8_PRIV_KEY_INFO(0).attributes), 'attributes', X509_ATTRIBUTE_it)
  ] ;



end.
