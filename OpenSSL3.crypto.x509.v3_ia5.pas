unit OpenSSL3.crypto.x509.v3_ia5;

interface
uses OpenSSL.Api;

function i2s_ASN1_IA5STRING(const method : PX509V3_EXT_METHOD; ia5 : Pointer{PASN1_IA5STRING}):PUTF8Char;
function s2i_ASN1_IA5STRING(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):Pointer{PASN1_IA5STRING};

var
  ossl_v3_ns_ia5_list: array[0..7] of TX509V3_EXT_METHOD;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.asn1_lib;



function i2s_ASN1_IA5STRING(const method : PX509V3_EXT_METHOD; ia5 : Pointer{PASN1_IA5STRING}):PUTF8Char;
var
  tmp : PUTF8Char;
begin
    if (ia5 = nil)  or  (PASN1_IA5STRING(ia5).length <= 0) then
       Exit(nil);
    tmp := OPENSSL_malloc(PASN1_IA5STRING(ia5).length + 1);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    memcpy(tmp, PASN1_IA5STRING(ia5).data, PASN1_IA5STRING(ia5).length);
    tmp[PASN1_IA5STRING(ia5).length] := Chr(0);
    Result := tmp;
end;


function s2i_ASN1_IA5STRING(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char): Pointer{PASN1_IA5STRING};
var
  ia5 : PASN1_IA5STRING;
  label _err;
begin
    if str = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT);
        Exit(nil);
    end;
    ia5 := ASN1_IA5STRING_new();
    if ia5 = nil then
        goto _err ;
    if 0>= ASN1_STRING_set(PASN1_STRING( ia5), str, Length(str))  then
    begin
        ASN1_IA5STRING_free(ia5);
        Exit(nil);
    end;
{$IFDEF CHARSET_EBCDIC}
    ebcdic2ascii(ia5.data, ia5.data, ia5.length);
{$endif}                          { CHARSET_EBCDIC }
    Exit(ia5);
 _err:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    Result := nil;
end;

initialization
  ossl_v3_ns_ia5_list[0] := get_V3_EXT_METHOD( 72, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[1] := get_V3_EXT_METHOD( 73, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[2] := get_V3_EXT_METHOD( 74, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[3] := get_V3_EXT_METHOD( 75, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[4] := get_V3_EXT_METHOD( 76, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[5] := get_V3_EXT_METHOD( 77, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[6] := get_V3_EXT_METHOD( 78, 0, ASN1_IA5STRING_it, nil,nil,nil,nil, i2s_ASN1_IA5STRING, s2i_ASN1_IA5STRING, nil,nil,nil,nil, nil);
  ossl_v3_ns_ia5_list[7] := get_V3_EXT_METHOD( -1, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil);

end.
