unit openssl3.crypto.rsa.rsa_none;

interface
uses OpenSSL.Api;

function RSA_padding_add_none(_to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
function RSA_padding_check_none(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;

implementation
uses OpenSSL3.Err;

function RSA_padding_add_none(_to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
begin
    if flen > tlen then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(0);
    end;
    if flen < tlen then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
        Exit(0);
    end;
    memcpy(_to, from, uint32( flen));
    Result := 1;
end;


function RSA_padding_check_none(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
begin
    if flen > tlen then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        Exit(-1);
    end;
    memset(_to, 0, tlen - flen);
    memcpy(_to + tlen - flen, from, flen);
    Result := tlen;
end;

end.
