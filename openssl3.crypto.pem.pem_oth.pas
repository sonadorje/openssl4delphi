unit openssl3.crypto.pem.pem_oth;

interface
uses OpenSSL.Api;


function PEM_ASN1_read_bio(d2i : Td2i_of_void;const name : PUTF8Char; bp : PBIO; x : PPointer; cb : Tpem_password_cb; u : Pointer):Pointer;

implementation

uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.pem.pem_lib;

function PEM_ASN1_read_bio(d2i : Td2i_of_void;const name : PUTF8Char; bp : PBIO; x : PPointer; cb : Tpem_password_cb; u : Pointer):Pointer;
var
  p, data : PByte;
  len : long;
  ret : PUTF8Char;
begin
    p := nil;
    data := nil;
    ret := nil;
    if 0>= PEM_bytes_read_bio(@data, @len, nil, name, bp, cb, u) then
        Exit(nil);
    p := data;
    ret := d2i(x, @p, len);
    if ret = nil then
       ERR_raise(ERR_LIB_PEM, ERR_R_ASN1_LIB);
    OPENSSL_free(data);
    Result := ret;
end;





end.
