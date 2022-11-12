unit openssl3.crypto.camellia.cmll_misc;

interface
uses OpenSSL.Api;

function Camellia_set_key(const userKey : PByte; bits : integer; key : PCAMELLIA_KEY):integer;
procedure Camellia_encrypt(const _in : PByte; _out : PByte;const key : PCAMELLIA_KEY);
procedure Camellia_decrypt(const _in : PByte; _out : PByte;const key : PCAMELLIA_KEY);

implementation

uses openssl3.crypto.camellia.camellia;

procedure Camellia_decrypt(const _in : PByte; _out : PByte;const key : PCAMELLIA_KEY);
begin
    Camellia_DecryptBlock_Rounds(key.grand_rounds, _in, key.u.rd_key, _out);
end;




procedure Camellia_encrypt(const _in : PByte; _out : PByte;const key : PCAMELLIA_KEY);
begin
    Camellia_EncryptBlock_Rounds(key.grand_rounds, _in, key.u.rd_key, _out);
end;




function Camellia_set_key(const userKey : PByte; bits : integer; key : PCAMELLIA_KEY):integer;
begin
    if (nil =userKey)  or  (nil=key) then Exit(-1);
    if (bits <> 128)  and  (bits <> 192)  and  (bits <> 256) then Exit(-2);
    key.grand_rounds := Camellia_Ekeygen(bits, userKey, key.u.rd_key);
    Result := 0;
end;


end.
