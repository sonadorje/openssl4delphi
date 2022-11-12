unit OpenSSL3.crypto.x509.v3_pmaps;

interface
uses OpenSSL.Api, SysUtils;

function POLICY_MAPPINGS_it:PASN1_ITEM;
function i2v_POLICY_MAPPINGS(const method : PX509V3_EXT_METHOD; a : Pointer; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_POLICY_MAPPINGS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
function POLICY_MAPPING_new:PPOLICY_MAPPING;
 procedure POLICY_MAPPING_free( a : PPOLICY_MAPPING);
function POLICY_MAPPING_it:PASN1_ITEM;


var
   ossl_v3_policy_mappings: TX509V3_EXT_METHOD;
   POLICY_MAPPINGS_item_tt :TASN1_TEMPLATE;
   POLICY_MAPPING_seq_tt: array of TASN1_TEMPLATE;

implementation

uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     openssl3.crypto.x509.v3_genn,  OpenSSL3.common,
     openssl3.crypto.bio.bio_lib,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;




function POLICY_MAPPING_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM( $1, 16, @POLICY_MAPPING_seq_tt,
                    sizeof(POLICY_MAPPING_seq_tt) div sizeof(TASN1_TEMPLATE),
                    Pointer(0) , sizeof(POLICY_MAPPING), ' POLICY_MAPPING'  );
   Result := @local_it;
end;




function POLICY_MAPPING_new:PPOLICY_MAPPING;
begin
 Result := PPOLICY_MAPPING(ASN1_item_new(POLICY_MAPPING_it));
end;


procedure POLICY_MAPPING_free( a : PPOLICY_MAPPING);
begin
 ASN1_item_free(PASN1_VALUE( a), POLICY_MAPPING_it);
end;


function i2v_POLICY_MAPPINGS(const method : PX509V3_EXT_METHOD; a : Pointer; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
    pmaps    : PPOLICY_MAPPINGS;
    pmap     : PPOLICY_MAPPING;
    i        : integer;
    obj_tmp1,
    obj_tmp2 : array[0..79] of UTF8Char;
begin
    pmaps := a;
    for i := 0 to sk_POLICY_MAPPING_num(pmaps)-1 do
    begin
        pmap := sk_POLICY_MAPPING_value(pmaps, i);
        i2t_ASN1_OBJECT(obj_tmp1, 80, pmap.issuerDomainPolicy);
        i2t_ASN1_OBJECT(obj_tmp2, 80, pmap.subjectDomainPolicy);
        X509V3_add_value(obj_tmp1, obj_tmp2, &ext_list);
    end;
    Result := ext_list;
end;


function v2i_POLICY_MAPPINGS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
var
  pmap : PPOLICY_MAPPING;
  obj2,
  obj1 : PASN1_OBJECT;
  val : PCONF_VALUE;
  pmaps : PPOLICY_MAPPINGS;
  num, i : integer;
  label _err;
begin
    pmap := nil;
    obj1 := nil; obj2 := nil;
   num := sk_CONF_VALUE_num(nval);
   pmaps := sk_POLICY_MAPPING_new_reserve(nil, num);
    if pmaps = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to num-1 do
    begin
        val := sk_CONF_VALUE_value(nval, i);
        if (nil = val.value)  or  (nil = val.name) then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                          Format(' %s' , [val.name]));
            goto _err ;
        end;
        obj1 := OBJ_txt2obj(val.name, 0);
        obj2 := OBJ_txt2obj(val.value, 0);
        if (nil = obj1)  or  (nil = obj2) then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                          Format(' %s' , [val.name]));
            goto _err ;
        end;
        pmap := POLICY_MAPPING_new();
        if pmap = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        pmap.issuerDomainPolicy := obj1;
        pmap.subjectDomainPolicy := obj2;
        obj1 := nil; obj2 := nil;
        sk_POLICY_MAPPING_push(pmaps, pmap); { no failure as it was reserved }
    end;
    Exit(pmaps);
 _err:
    ASN1_OBJECT_free(obj1);
    ASN1_OBJECT_free(obj2);
    sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
    Result := nil;
end;






function POLICY_MAPPINGS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($0, -1, @POLICY_MAPPINGS_item_tt, 0,
                             Pointer(0) , 0, ' POLICY_MAPPINGS'  );
   Result := @local_it;
end;

initialization
  ossl_v3_policy_mappings := get_V3_EXT_METHOD(
    NID_policy_mappings, 0,
    POLICY_MAPPINGS_it,
    nil, nil, nil, nil,
    nil, nil,
    i2v_POLICY_MAPPINGS,
    v2i_POLICY_MAPPINGS,
    nil, nil,
    nil);
   POLICY_MAPPINGS_item_tt := get_ASN1_TEMPLATE
        ( (($2 shl  1)), 0,  0, ' POLICY_MAPPINGS' , POLICY_MAPPING_it);
   POLICY_MAPPING_seq_tt := [
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PPOLICY_MAPPING(0).issuerDomainPolicy), ' issuerDomainPolicy' , ASN1_OBJECT_it) ,
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PPOLICY_MAPPING(0).subjectDomainPolicy), ' subjectDomainPolicy' , ASN1_OBJECT_it)
   ] ;

end.
