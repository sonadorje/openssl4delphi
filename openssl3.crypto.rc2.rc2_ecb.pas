unit openssl3.crypto.rc2.rc2_ecb;

interface
 uses OpenSSL.Api;

procedure RC2_ecb_encrypt(const _in : PByte; _out : PByte; ks : PRC2_KEY; encrypt : integer);

implementation
uses openssl3.crypto.rc2.rc2_local, openssl3.crypto.rc2.rc2_cbc;

procedure RC2_ecb_encrypt(const _in : PByte; _out : PByte; ks : PRC2_KEY; encrypt : integer);
var
  l : Cardinal;
  d : array[0..1] of Cardinal;
begin
    c2l(_in, l);
    d[0] := l;
    c2l(_in, l);
    d[1] := l;
    if encrypt > 0 then
       RC2_encrypt(@d, ks)
    else
        RC2_decrypt(@d, ks);
    l := d[0];
    l2c(l, _out);
    l := d[1];
    l2c(l, _out);
    l := 0; d[0] := 0; d[1] := 0;
end;


end.
