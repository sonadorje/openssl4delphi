unit OpenSSL3.crypto.x509.v3_extku;

interface
uses OpenSSL.Api, SysUtils;

function i2v_EXTENDED_KEY_USAGE(const method : PX509V3_EXT_METHOD; a : Pointer; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_EXTENDED_KEY_USAGE(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
function EXTENDED_KEY_USAGE_it:PASN1_ITEM;

var
  ossl_v3_ext_ku, ossl_v3_ocsp_accresp :TX509V3_EXT_METHOD ;
  EXTENDED_KEY_USAGE_item_tt :TASN1_TEMPLATE;



implementation
uses openssl3.crypto.asn1.tasn_typ, OpenSSL3.include.openssl.asn1,
     OpenSSL3.openssl.conf,  OpenSSL3.Err, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.a_object, OpenSSL3.crypto.x509.v3_utl;





function i2v_EXTENDED_KEY_USAGE(const method : PX509V3_EXT_METHOD; a : Pointer; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
  eku : PEXTENDED_KEY_USAGE;
  i : integer;
  obj : PASN1_OBJECT;
  obj_tmp : array[0..79] of UTF8Char;
begin
    eku := a;
    for i := 0 to sk_ASN1_OBJECT_num(eku)-1 do
    begin
        obj := sk_ASN1_OBJECT_value(eku, i);
        i2t_ASN1_OBJECT(obj_tmp, 80, obj);
        X509V3_add_value(nil, obj_tmp, @ext_list);
    end;
    Result := ext_list;
end;


function v2i_EXTENDED_KEY_USAGE(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
var
  extku : PEXTENDED_KEY_USAGE;
  extval : PUTF8Char;
  objtmp : PASN1_OBJECT;
  val : PCONF_VALUE;
  num, i : integer;
begin
    num := sk_CONF_VALUE_num(nval);
    extku := sk_ASN1_OBJECT_new_reserve(nil, num);
    if extku = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        sk_ASN1_OBJECT_free(extku);
        Exit(nil);
    end;
    for i := 0 to num-1 do
    begin
        val := sk_CONF_VALUE_value(nval, i);
        if val.value <> nil then
           extval := val.value
        else
            extval := val.name;
        objtmp := OBJ_txt2obj(extval, 0 );
        if objtmp = nil then
        begin
            sk_ASN1_OBJECT_pop_free(extku, ASN1_OBJECT_free);
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                          Format(' %s' , [extval]));
            Exit(nil);
        end;
        sk_ASN1_OBJECT_push(extku, objtmp);  { no failure as it was reserved }
    end;
    Result := extku;
end;

function EXTENDED_KEY_USAGE_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($0, -1, @EXTENDED_KEY_USAGE_item_tt,
                          0, Pointer(0) , 0, ' EXTENDED_KEY_USAGE');
   Result := @local_it;
end;

initialization
  EXTENDED_KEY_USAGE_item_tt := get_ASN1_TEMPLATE
        ( ($2 shl  1), 0,  0, ' EXTENDED_KEY_USAGE' , ASN1_OBJECT_it) ;

  ossl_v3_ext_ku := get_V3_EXT_METHOD (
    NID_ext_key_usage, 0,
    EXTENDED_KEY_USAGE_it,
    nil, nil, nil, nil,
    nil, nil,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    nil, nil,
    nil);

   ossl_v3_ocsp_accresp := get_V3_EXT_METHOD(
    NID_id_pkix_OCSP_acceptableResponses, 0,
    EXTENDED_KEY_USAGE_it,
    nil, nil, nil, nil,
    nil, nil,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    nil, nil,
    nil);
end.
