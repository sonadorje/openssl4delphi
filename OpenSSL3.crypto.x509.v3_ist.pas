unit OpenSSL3.crypto.x509.v3_ist;

interface
uses OpenSSL.Api;

function ISSUER_SIGN_TOOL_it:PASN1_ITEM;

var
  ossl_v3_issuer_sign_tool :TX509V3_EXT_METHOD;
  ISSUER_SIGN_TOOL_seq_tt :array of TASN1_TEMPLATE;

function v2i_issuer_sign_tool( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PISSUER_SIGN_TOOL;
  function i2r_issuer_sign_tool( method : PX509V3_EXT_METHOD; ist : PISSUER_SIGN_TOOL; _out : PBIO; indent : integer):integer;

 function d2i_ISSUER_SIGN_TOOL(a : PPISSUER_SIGN_TOOL;const _in : PPByte; len : long):PISSUER_SIGN_TOOL;
  function i2d_ISSUER_SIGN_TOOL(const a : PISSUER_SIGN_TOOL; _out : PPByte):integer;
  function ISSUER_SIGN_TOOL_new:PISSUER_SIGN_TOOL;
  procedure ISSUER_SIGN_TOOL_free( a : PISSUER_SIGN_TOOL);

implementation
uses openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.asn1.asn1_lib,  openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bio_print,
     OpenSSL3.Err, OpenSSL3.openssl.conf, openssl3.crypto.asn1.tasn_typ;

function d2i_ISSUER_SIGN_TOOL(a : PPISSUER_SIGN_TOOL;const _in : PPByte; len : long):PISSUER_SIGN_TOOL;
begin
 Result := PISSUER_SIGN_TOOL(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ISSUER_SIGN_TOOL_it));
end;


function i2d_ISSUER_SIGN_TOOL(const a : PISSUER_SIGN_TOOL; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ISSUER_SIGN_TOOL_it);
end;


function ISSUER_SIGN_TOOL_new:PISSUER_SIGN_TOOL;
begin
   Result := PISSUER_SIGN_TOOL(ASN1_item_new(ISSUER_SIGN_TOOL_it));
end;


procedure ISSUER_SIGN_TOOL_free( a : PISSUER_SIGN_TOOL);
begin
   ASN1_item_free(PASN1_VALUE( a), ISSUER_SIGN_TOOL_it);
end;


function v2i_issuer_sign_tool( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PISSUER_SIGN_TOOL;
var
  ist : PISSUER_SIGN_TOOL;

  i : integer;

  cnf : PCONF_VALUE;
begin
    ist := ISSUER_SIGN_TOOL_new();
    if ist = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        if cnf = nil then
        begin
            continue;
        end;
        if strcmp(cnf.name, ' signTool') = 0   then
        begin
            ist.signTool := ASN1_UTF8STRING_new();
            if ist.signTool = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                ISSUER_SIGN_TOOL_free(ist);
                Exit(nil);
            end;
            ASN1_STRING_set(PASN1_STRING(ist.signTool), cnf.value, Length(cnf.value));
        end
        else
        if (strcmp(cnf.name, ' cATool' ) = 0) then
        begin
            ist.cATool := ASN1_UTF8STRING_new();
            if ist.cATool = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                ISSUER_SIGN_TOOL_free(ist);
                Exit(nil);
            end;
            ASN1_STRING_set(PASN1_STRING(ist.cATool), cnf.value, Length(cnf.value));
        end
        else
        if (strcmp(cnf.name, ' signToolCert' ) = 0) then
        begin
            ist.signToolCert := ASN1_UTF8STRING_new();
            if ist.signToolCert = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                ISSUER_SIGN_TOOL_free(ist);
                Exit(nil);
            end;
            ASN1_STRING_set(PASN1_STRING(ist.signToolCert), cnf.value, Length(cnf.value));
        end
        else
        if (strcmp(cnf.name, ' cAToolCert' ) = 0) then
        begin
            ist.cAToolCert := ASN1_UTF8STRING_new();
            if ist.cAToolCert = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                ISSUER_SIGN_TOOL_free(ist);
                Exit(nil);
            end;
            ASN1_STRING_set(PASN1_STRING(ist.cAToolCert), cnf.value, Length(cnf.value));
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT);
            ISSUER_SIGN_TOOL_free(ist);
            Exit(nil);
        end;
    end;
    Result := ist;
end;


function i2r_issuer_sign_tool( method : PX509V3_EXT_METHOD; ist : PISSUER_SIGN_TOOL; _out : PBIO; indent : integer):integer;
var
  new_line : integer;
begin
    new_line := 0;
    if ist = nil then begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    if ist.signTool <> nil then
    begin
        if new_line = 1 then
        begin
            BIO_write(_out, PUTF8Char(#10) , 1);
        end;
        BIO_printf(_out, ' %*ssignTool    : ' , [indent, ' '] );
        BIO_write(_out, ist.signTool.data, ist.signTool.length);
        new_line := 1;
    end;
    if ist.cATool <> nil then
    begin
        if new_line = 1 then
        begin
            BIO_write(_out, PUTF8Char(#10) , 1);
        end;
        BIO_printf(_out, ' %*scATool      : ' , [indent, ' '] );
        BIO_write(_out, ist.cATool.data, ist.cATool.length);
        new_line := 1;
    end;
    if ist.signToolCert <> nil then
    begin
        if new_line = 1 then
        begin
            BIO_write(_out, PUTF8Char(#10) , 1);
        end;
        BIO_printf(_out, ' %*ssignToolCert: ' , [indent, ' '] );
        BIO_write(_out, ist.signToolCert.data, ist.signToolCert.length);
        new_line := 1;
    end;
    if ist.cAToolCert <> nil then
    begin
        if new_line = 1 then
        begin
            BIO_write(_out, PUTF8Char(#10) , 1);
        end;
        BIO_printf(_out, ' %*scAToolCert  : ' , [indent, ' '] );
        BIO_write(_out, ist.cAToolCert.data, ist.cAToolCert.length);
        new_line := 1;
    end;
    Result := 1;
end;


function ISSUER_SIGN_TOOL_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM ($1, 16, @ISSUER_SIGN_TOOL_seq_tt,
                    sizeof(ISSUER_SIGN_TOOL_seq_tt) div sizeof(TASN1_TEMPLATE),
          Pointer(0) , sizeof(TISSUER_SIGN_TOOL), ' ISSUER_SIGN_TOOL');

    Result := @local_it;
end;

initialization
   ossl_v3_issuer_sign_tool := get_V3_EXT_METHOD(
    NID_issuerSignTool,                   // nid */
    X509V3_EXT_MULTILINE,                 // flags */
    ISSUER_SIGN_TOOL_it,      // template */
    nil, nil, nil, nil,                           // old functions, ignored */
    nil,                                    // i2s */
    nil,                                    // s2i */
    nil,                                    // i2v */
    PX509V3_EXT_V2I(@v2i_issuer_sign_tool)^, // v2i */
    PX509V3_EXT_I2R(@i2r_issuer_sign_tool)^, // i2r */
    nil,                                    // r2i */
    nil                                  // extension-specific data */
  );

   ISSUER_SIGN_TOOL_seq_tt := [
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PISSUER_SIGN_TOOL(0).signTool), 'signTool' , ASN1_UTF8STRING_it) ,
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PISSUER_SIGN_TOOL(0).cATool), 'cATool' , ASN1_UTF8STRING_it) ,
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PISSUER_SIGN_TOOL(0).signToolCert), 'signToolCert' , ASN1_UTF8STRING_it) ,
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PISSUER_SIGN_TOOL(0).cAToolCert), 'cAToolCert' , ASN1_UTF8STRING_it)
  ] ;

end.
