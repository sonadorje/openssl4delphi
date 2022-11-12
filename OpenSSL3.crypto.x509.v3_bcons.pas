unit OpenSSL3.crypto.x509.v3_bcons;

interface
uses OpenSSL.Api;

function BASIC_CONSTRAINTS_it:PASN1_ITEM;
function i2v_BASIC_CONSTRAINTS(const method : PX509V3_EXT_METHOD; bcons :Pointer{ PBASIC_CONSTRAINTS}; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_BASIC_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE): Pointer{PBASIC_CONSTRAINTS};
function d2i_BASIC_CONSTRAINTS(a : PPBASIC_CONSTRAINTS;const _in : PPByte; len : long):PBASIC_CONSTRAINTS;
  function i2d_BASIC_CONSTRAINTS(const a : PBASIC_CONSTRAINTS; _out : PPByte):integer;
  function BASIC_CONSTRAINTS_new:PBASIC_CONSTRAINTS;
  procedure BASIC_CONSTRAINTS_free( a : PBASIC_CONSTRAINTS);


const  ossl_v3_bcons: TX509V3_EXT_METHOD = (
    ext_nid: NID_basic_constraints; ext_flags: 0;
    it: BASIC_CONSTRAINTS_it;
    ext_new: nil; ext_free: nil; d2i: nil; i2d: nil;
    i2s: nil; s2i: nil;
    i2v: {X509V3_EXT_I2V} i2v_BASIC_CONSTRAINTS;
    v2i: {X509V3_EXT_V2I} v2i_BASIC_CONSTRAINTS;
    i2r: nil; r2i: nil;
    usr_data: nil
);

var
  BASIC_CONSTRAINTS_seq_tt: array[0..1] of TASN1_TEMPLATE;

implementation
uses OpenSSL3.Err, openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     OpenSSL3.openssl.conf, OpenSSL3.crypto.x509.v3_utl,
     OpenSSL3.crypto.x509.v3_crld, openssl3.crypto.asn1.tasn_typ;





function d2i_BASIC_CONSTRAINTS(a : PPBASIC_CONSTRAINTS;const _in : PPByte; len : long):PBASIC_CONSTRAINTS;
begin
   Result := PBASIC_CONSTRAINTS(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, BASIC_CONSTRAINTS_it));
end;


function i2d_BASIC_CONSTRAINTS(const a : PBASIC_CONSTRAINTS; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, BASIC_CONSTRAINTS_it);
end;


function BASIC_CONSTRAINTS_new:PBASIC_CONSTRAINTS;
begin
   Result := PBASIC_CONSTRAINTS(ASN1_item_new(BASIC_CONSTRAINTS_it));
end;


procedure BASIC_CONSTRAINTS_free( a : PBASIC_CONSTRAINTS);
begin
   ASN1_item_free(PASN1_VALUE( a), BASIC_CONSTRAINTS_it);
end;

function v2i_BASIC_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE): Pointer{PBASIC_CONSTRAINTS};
var
  bcons : PBASIC_CONSTRAINTS;
  val : PCONF_VALUE;
  i : integer;
  label _err;
begin
    bcons := nil;
    bcons := BASIC_CONSTRAINTS_new();
    if bcons = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;

    for i := 0 to sk_CONF_VALUE_num(values)-1 do
    begin
        val := sk_CONF_VALUE_value(values, i);
        if strcmp(val.name, 'CA') = 0  then
        begin
            if 0>= X509V3_get_value_bool(val, @bcons.ca) then
                goto _err ;
        end
        else
        if (strcmp(val.name, 'pathlen') = 0) then
        begin
            if 0>= X509V3_get_value_int(val, @bcons.pathlen) then
                goto _err ;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NAME);
            X509V3_conf_add_error_name_value(val);
            goto _err ;
        end;
    end;
    Exit(bcons);
 _err:
    BASIC_CONSTRAINTS_free(bcons);
    Result := nil;
end;




function i2v_BASIC_CONSTRAINTS(const method : PX509V3_EXT_METHOD; bcons : Pointer{PBASIC_CONSTRAINTS}; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
begin
    X509V3_add_value_bool('CA', PBASIC_CONSTRAINTS(bcons).ca, @extlist);
    X509V3_add_value_int('pathlen', PBASIC_CONSTRAINTS(bcons).pathlen, @extlist);
    Result := extlist;
end;



function BASIC_CONSTRAINTS_it:PASN1_ITEM;
var
  local_it :TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @BASIC_CONSTRAINTS_seq_tt,
                             sizeof(BASIC_CONSTRAINTS_seq_tt) div sizeof(TASN1_TEMPLATE),
                             Pointer(0) , sizeof(BASIC_CONSTRAINTS), 'BASIC_CONSTRAINTS');

  Result := @local_it;
end;



initialization

  BASIC_CONSTRAINTS_seq_tt[0] := get_ASN1_TEMPLATE( $1, 0, size_t(@PBASIC_CONSTRAINTS(0).ca), 'ca', ASN1_FBOOLEAN_it);
  BASIC_CONSTRAINTS_seq_tt[1] := get_ASN1_TEMPLATE( $1, 0, size_t(@PBASIC_CONSTRAINTS(0).pathlen), 'pathlen', ASN1_INTEGER_it);

end.
