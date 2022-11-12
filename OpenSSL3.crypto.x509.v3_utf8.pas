unit OpenSSL3.crypto.x509.v3_utf8;

interface
uses OpenSSL.Api;

var
  ossl_v3_utf8_list: array[0..0] of TX509V3_EXT_METHOD;
  function i2s_ASN1_UTF8STRING( method : PX509V3_EXT_METHOD; utf8 : PASN1_UTF8STRING):PUTF8Char;
  function s2i_ASN1_UTF8STRING(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):PASN1_UTF8STRING;

implementation
uses openssl3.crypto.asn1.tasn_typ, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.asn1.asn1_lib ;





function i2s_ASN1_UTF8STRING( method : PX509V3_EXT_METHOD; utf8 : PASN1_UTF8STRING):PUTF8Char;
var
  tmp : PUTF8Char;
begin
    if (utf8 = nil)  or  (utf8.length = 0) then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    tmp := OPENSSL_malloc(utf8.length + 1);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    memcpy(tmp, utf8.data, utf8.length);
    tmp[utf8.length] := chr(0);
    Result := tmp;
end;


function s2i_ASN1_UTF8STRING(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):PASN1_UTF8STRING;
var
  utf8 : PASN1_UTF8STRING;
begin
    if str = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT);
        Exit(nil);
    end;

    utf8 := ASN1_UTF8STRING_new();
    if utf8 = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>= ASN1_STRING_set(PASN1_STRING( utf8), str, Length(str))  then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        ASN1_UTF8STRING_free(utf8);
        Exit(nil);
    end;
{$IFDEF CHARSET_EBCDIC}
    ebcdic2ascii(utf8.data, utf8.data, utf8.length);
{$endif}                          { CHARSET_EBCDIC }
    Result := utf8;
end;

initialization
  ossl_v3_utf8_list[0] := get_V3_EXT_METHOD
    ( 1007, 0, ASN1_UTF8STRING_it, nil,nil,nil,nil,
    PX509V3_EXT_I2S(@i2s_ASN1_UTF8STRING)^,
    PX509V3_EXT_S2I(@s2i_ASN1_UTF8STRING)^,
    nil,nil,nil,nil, Pointer(0)
);
end.
