unit openssl3.crypto.cast.c_ecb;

interface
uses OpenSSL.Api;

procedure CAST_ecb_encrypt(const _in : PByte; _out : PByte;const ks : PCAST_KEY; enc : integer);

implementation
uses openssl3.crypto.cast.cast_local, openssl3.crypto.cast.c_enc;

procedure CAST_ecb_encrypt(const _in : PByte; _out : PByte;const ks : PCAST_KEY; enc : integer);
var
  l: CAST_LONG;
  d: array[0..1] of CAST_LONG;
begin

    n2l(_in, l);
    d[0] := l;
    n2l(_in, l);
    d[1] := l;
    if enc > 0 then
       CAST_encrypt(@d, ks)
    else
        CAST_decrypt(@d, ks);
    l := d[0];
    l2n(l, _out);
    l := d[1];
    l2n(l, _out);
    l := 0; d[0] := 0; d[1] := 0;
end;


end.
