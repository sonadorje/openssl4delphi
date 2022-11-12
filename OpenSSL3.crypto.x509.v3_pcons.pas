unit OpenSSL3.crypto.x509.v3_pcons;

interface
uses OpenSSL.Api, SysUtils;

function POLICY_CONSTRAINTS_it:PASN1_ITEM;
function i2v_POLICY_CONSTRAINTS(const method : PX509V3_EXT_METHOD; a : Pointer; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_POLICY_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE):Pointer;
function POLICY_CONSTRAINTS_new:PPOLICY_CONSTRAINTS;
  procedure POLICY_CONSTRAINTS_free( a : PPOLICY_CONSTRAINTS);

var
  ossl_v3_policy_constraints: TX509V3_EXT_METHOD ;
  POLICY_CONSTRAINTS_seq_tt :array of TASN1_TEMPLATE;

implementation
uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     openssl3.crypto.x509.v3_genn,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;





function POLICY_CONSTRAINTS_new:PPOLICY_CONSTRAINTS;
begin
   Result := PPOLICY_CONSTRAINTS(ASN1_item_new(POLICY_CONSTRAINTS_it));
end;


procedure POLICY_CONSTRAINTS_free( a : PPOLICY_CONSTRAINTS);
begin
   ASN1_item_free(PASN1_VALUE( a), POLICY_CONSTRAINTS_it);
end;






function i2v_POLICY_CONSTRAINTS(const method : PX509V3_EXT_METHOD; a : Pointer; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
  pcons : PPOLICY_CONSTRAINTS;
begin
    pcons := a;
    X509V3_add_value_int(' Require Explicit Policy' ,
                         pcons.requireExplicitPolicy, &extlist);
    X509V3_add_value_int(' Inhibit Policy Mapping' ,
                         pcons.inhibitPolicyMapping, &extlist);
    Result := extlist;
end;


function v2i_POLICY_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE):Pointer;
var
  pcons : PPOLICY_CONSTRAINTS;

  val : PCONF_VALUE;

  i : integer;
  label _err;
begin
    pcons := nil;
    pcons := POLICY_CONSTRAINTS_new();
    if pcons = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(values)-1 do
    begin
        val := sk_CONF_VALUE_value(values, i);
        if strcmp(val.name, ' requireExplicitPolicy') = 0   then
        begin
            if 0>= X509V3_get_value_int(val, @pcons.requireExplicitPolicy) then
                goto _err ;
        end
        else
        if (strcmp(val.name, ' inhibitPolicyMapping' ) = 0) then
        begin
            if 0>= X509V3_get_value_int(val, @pcons.inhibitPolicyMapping) then
                goto _err ;
        end
        else
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_NAME, Format(' %s' , [val.name]));
            goto _err ;
        end;
    end;
    if (pcons.inhibitPolicyMapping = nil)
             and  (pcons.requireExplicitPolicy = nil) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_ILLEGAL_EMPTY_EXTENSION);
        goto _err ;
    end;
    Exit(pcons);
 _err:
    POLICY_CONSTRAINTS_free(pcons);
    Result := nil;
end;



function POLICY_CONSTRAINTS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @POLICY_CONSTRAINTS_seq_tt,
                            sizeof(POLICY_CONSTRAINTS_seq_tt) div sizeof(TASN1_TEMPLATE),
                            Pointer(0) , sizeof(POLICY_CONSTRAINTS), ' POLICY_CONSTRAINTS');

  Result := @local_it;
end;

initialization
  ossl_v3_policy_constraints := get_V3_EXT_METHOD (
    NID_policy_constraints, 0,
    POLICY_CONSTRAINTS_it,
    nil, nil, nil, nil,
    nil, nil,
    i2v_POLICY_CONSTRAINTS,
    v2i_POLICY_CONSTRAINTS,
    nil, nil,
    nil);

  POLICY_CONSTRAINTS_seq_tt := [
          get_ASN1_TEMPLATE( ((($1 shl  3) or ($2 shl 6))  or  $1), 0, size_t(@PPOLICY_CONSTRAINTS(0).requireExplicitPolicy), ' requireExplicitPolicy' , ASN1_INTEGER_it),
          get_ASN1_TEMPLATE( ((($1 shl  3) or ($2 shl 6))  or  $1), 1, size_t(@PPOLICY_CONSTRAINTS(0).inhibitPolicyMapping), ' inhibitPolicyMapping' ,   ASN1_INTEGER_it)
  ] ;

end.
