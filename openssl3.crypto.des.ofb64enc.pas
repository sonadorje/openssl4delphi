unit openssl3.crypto.des.ofb64enc;

interface
uses OpenSSL.Api;

 procedure DES_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; num : PInteger);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; num : PInteger);
var
  v0, v1, t : DES_LONG;
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
    dp := @d;
    l2c(v0, dp);
    l2c(v1, dp);
    while PostDec(l) > 0 do
    begin
        if n = 0 then
        begin
            DES_encrypt1(@ti, schedule, DES_ENCRYPT);
            dp := @d;
            t := ti[0];
            l2c(t, dp);
            t := ti[1];
            l2c(t, dp);
            PostInc(save);
        end;
        PostInc(_out)^ := PostInc(_in)^  xor  d[n];
        n := (n + 1) and $07;
    end;
    if save > 0 then
    begin
        v0 := ti[0];
        v1 := ti[1];
        iv := @( ivec^)[0];
        l2c(v0, iv);
        l2c(v1, iv);
    end;
    t := 0; v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0;
    num^ := n;
end;

end.
