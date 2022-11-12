unit openssl3.crypto.asn1.a_octet;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ASN1_OCTET_STRING_dup(const x : PASN1_OCTET_STRING):PASN1_OCTET_STRING;
  function ASN1_OCTET_STRING_cmp(const a, b : PASN1_OCTET_STRING):integer;
  function ASN1_OCTET_STRING_set(x : PASN1_OCTET_STRING;const d : PByte; len : integer):integer;

implementation
uses openssl3.crypto.asn1.asn1_lib;

function ASN1_OCTET_STRING_dup(const x : PASN1_OCTET_STRING):PASN1_OCTET_STRING;
begin
    Result := PASN1_OCTET_STRING(ASN1_STRING_dup(PASN1_STRING(x)));
end;


function ASN1_OCTET_STRING_cmp(const a, b : PASN1_OCTET_STRING):integer;
begin
    Result := ASN1_STRING_cmp(PASN1_STRING(a), PASN1_STRING(b));
end;


function ASN1_OCTET_STRING_set(x : PASN1_OCTET_STRING;const d : PByte; len : integer):integer;
begin
    Result := ASN1_STRING_set(PASN1_STRING(x), d, len);
end;

end.
