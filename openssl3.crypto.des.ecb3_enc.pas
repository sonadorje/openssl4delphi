unit openssl3.crypto.des.ecb3_enc;

interface
uses OpenSSL.Api;

procedure DES_ecb3_encrypt( input : Pconst_DES_cblock; output : PDES_cblock; ks1, ks2, ks3 : PDES_key_schedule; enc : integer);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_ecb3_encrypt( input : Pconst_DES_cblock; output : PDES_cblock; ks1, ks2, ks3 : PDES_key_schedule; enc : integer);
var
  l0, l1 : DES_LONG;
  ll : array[0..1] of DES_LONG;
  _in, _out : PByte;
begin
    _in := @( input^)[0];
    _out := @( output^)[0];
    c2l(_in, l0);
    c2l(_in, l1);
    ll[0] := l0;
    ll[1] := l1;
    if enc > 0 then
       DES_encrypt3(@ll, ks1, ks2, ks3)
    else
        DES_decrypt3(@ll, ks1, ks2, ks3);
    l0 := ll[0];
    l1 := ll[1];
    l2c(l0, _out);
    l2c(l1, _out);
end;


end.
