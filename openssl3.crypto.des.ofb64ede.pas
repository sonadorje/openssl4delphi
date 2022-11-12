unit openssl3.crypto.des.ofb64ede;

interface
uses OpenSSL.Api;

procedure DES_ede3_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; k1, k2, k3 : PDES_key_schedule; ivec : PDES_cblock; num : PInteger);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_ede3_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; k1, k2, k3 : PDES_key_schedule; ivec : PDES_cblock; num : PInteger);
var
  v0, v1 : DES_LONG;
  n : integer;
  l : long;
  d : TDES_cblock;
  dp : PByte;
  ti : array[0..1] of DES_LONG;
  iv : PByte;
  save : integer;
begin
     n := num^;
     l := length;
    save := 0;
    iv := @( ivec^)[0];
    c2l(iv, v0);
    c2l(iv, v1);
    ti[0] := v0;
    ti[1] := v1;
    dp := {PUTF8Char}(@d);
    l2c(v0, dp);
    l2c(v1, dp);
    while PostDec(l) > 0 do
    begin
        if n = 0 then
        begin
            { ti[0]=v0; }
            { ti[1]=v1; }
            DES_encrypt3(@ti, k1, k2, k3);
            v0 := ti[0];
            v1 := ti[1];
            dp := {PUTF8Char}@d;
            l2c(v0, dp);
            l2c(v1, dp);
            PostInc(save);
        end;
        PostInc(_out)^ := PostInc(_in)^  xor  d[n];
        n := (n + 1) and $07;
    end;
    if save > 0 then
    begin
        iv := @( ivec^)[0];
        l2c(v0, iv);
        l2c(v1, iv);
    end;
    v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0;
    num^ := n;
end;


end.
