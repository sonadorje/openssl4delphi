unit openssl3.crypto.pkcs12.p12_utl;

interface
uses OpenSSL.Api;

 function OPENSSL_asc2uni(const asc : PUTF8Char; asclen : integer; uni : PPByte; unilen : PInteger):PByte;
 function OPENSSL_uni2asc({const} uni : PByte; unilen : integer):PUTF8Char;

implementation
uses openssl3.crypto.mem, OpenSSL3.Err;

function OPENSSL_asc2uni(const asc : PUTF8Char; asclen : integer; uni : PPByte; unilen : PInteger):PByte;
var
  ulen, i : integer;
  unitmp : PByte;
begin
    if asclen = -1 then asclen := Length(asc);
    if asclen < 0 then Exit(nil);
    ulen := asclen * 2 + 2;
    unitmp := OPENSSL_malloc(ulen);
    if unitmp = nil then  begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    i := 0;
    while i < ulen - 2 do
    begin
        unitmp[i] := 0;
        unitmp[i + 1] := Ord(asc[i  shr  1]);
        i := i+2;
    end;
    { Make result double null terminated }
    unitmp[ulen - 2] := 0;
    unitmp[ulen - 1] := 0;
    if unilen <> nil then unilen^ := ulen;
    if uni <> nil then uni^ := unitmp;
    Result := unitmp;
end;


function OPENSSL_uni2asc({const} uni : PByte; unilen : integer):PUTF8Char;
var
  asclen, i : integer;

  asctmp : PUTF8Char;
begin
    { string must contain an even number of bytes }
    if unilen and 1 > 0 then Exit(nil);
    if unilen < 0 then Exit(nil);
    asclen := unilen div 2;
    { If no terminating zero allow for one }
    if 0>=unilen  or  uni[unilen - 1] then
       PostInc(asclen);
    PostInc(uni);
    asctmp := OPENSSL_malloc(asclen);
    if asctmp = nil then  begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    i := 0;
    while i < unilen do
    begin
        asctmp[i  shr  1] := UTF8Char(uni[i]);
         i := i + 2;
    end;
    asctmp[asclen - 1] := UTF8Char(0);
    Result := asctmp;
end;


end.
