unit OpenSSL3.crypto.x509.v3_tlsf;

interface
 uses OpenSSL.Api;

type
  TTLS_FEATURE_NAME = record
    num : long;
    name : PUTF8Char;
  end;
 function TLS_FEATURE_it:PASN1_ITEM;
 function v2i_TLS_FEATURE(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PTLS_FEATURE;



function i2v_TLS_FEATURE(const method : PX509V3_EXT_METHOD; tls_feature : PTLS_FEATURE; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;

 var
    ossl_v3_tls_feature: TX509V3_EXT_METHOD;
    TLS_FEATURE_item_tt :TASN1_TEMPLATE;
    tls_feature_tbl: array[0..1] of TTLS_FEATURE_NAME = (
      ( num:5;  name: 'status_request' ),
      ( num:17; name: 'status_request_v2' )
    );

implementation

uses OpenSSL3.include.openssl.asn1, openssl3.crypto.asn1.a_int,
     openssl3.crypto.asn1.tasn_typ,
     OpenSSL3.crypto.x509.v3_utl, OpenSSL3.Err, OpenSSL3.openssl.conf;






function v2i_TLS_FEATURE(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PTLS_FEATURE;
var
    tlsf     : PTLS_FEATURE;
    extval,
    endptr   : PUTF8Char;
    ai       : PASN1_INTEGER;
    val      : PCONF_VALUE;
    i        : integer;
    j        : size_t;
    tlsextid : long;
    label _err;
begin
    ai := nil;
    tlsf := sk_ASN1_INTEGER_new_null;
    if tlsf =  nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        val := sk_CONF_VALUE_value(nval, i);
        if val.value <> nil then
           extval := val.value
        else
            extval := val.name;
        for j := 0 to Length(tls_feature_tbl)-1 do
            if strcasecmp(extval, tls_feature_tbl[j].name) = 0  then
                break;
        if j < Length(tls_feature_tbl )then
            tlsextid := tls_feature_tbl[j].num
        else
        begin
            tlsextid := strtol(extval, @endptr, 10);
            if ( endptr^ <> #0)  or  (extval = endptr)  or  (tlsextid < 0 )   or
                (tlsextid > 65535) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX);
                X509V3_conf_add_error_name_value(val);
                goto _err;
            end;
        end;
        ai := ASN1_INTEGER_new;
        if (ai = nil)
                 or  (0>=ASN1_INTEGER_set(ai, tlsextid))
                 or  (sk_ASN1_INTEGER_push(tlsf, ai) <= 0) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        { So it doesn't get purged if an error occurs next time around }
        ai := nil;
    end;
    Exit(tlsf);
 _err:
    sk_ASN1_INTEGER_pop_free(tlsf, ASN1_INTEGER_free);
    ASN1_INTEGER_free(ai);
    Result := nil;
end;

function i2v_TLS_FEATURE(const method : PX509V3_EXT_METHOD; tls_feature : PTLS_FEATURE; ext_list : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
    i        : integer;
    j        : size_t;
    ai       : PASN1_INTEGER;
    tlsextid : long;
begin
    for i := 0 to sk_ASN1_INTEGER_num(tls_feature)-1 do
    begin
        ai := sk_ASN1_INTEGER_value(tls_feature, i);
        tlsextid := ASN1_INTEGER_get(ai);
        for j := 0 to Length(tls_feature_tbl)-1 do
            if tlsextid = tls_feature_tbl[j].num then
               break;
        if j < Length(tls_feature_tbl) then
            X509V3_add_value(nil, tls_feature_tbl[j].name, @ext_list)
        else
            X509V3_add_value_int(nil, ai, @ext_list);
    end;
    Result := ext_list;
end;




function TLS_FEATURE_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($0, -1, @TLS_FEATURE_item_tt, 0,
                               Pointer(0) , 0, 'TLS_FEATURE');
    Result := @local_it;
end;


initialization
  ossl_v3_tls_feature := get_V3_EXT_METHOD (
    NID_tlsfeature, 0,
    TLS_FEATURE_it,
    nil, nil, nil, nil,
    nil, nil,
    PX509V3_EXT_I2V(@i2v_TLS_FEATURE)^,
    PX509V3_EXT_V2I(@v2i_TLS_FEATURE)^,
    nil, nil,
    Nil
);
  TLS_FEATURE_item_tt :=  get_ASN1_TEMPLATE ( (($2 shl 1)), 0, 0, 'TLS_FEATURE', ASN1_INTEGER_it) ;


end.
