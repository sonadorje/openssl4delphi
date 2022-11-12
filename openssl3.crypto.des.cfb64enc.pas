unit openssl3.crypto.des.cfb64enc;

interface
uses OpenSSL.Api;

 procedure DES_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; num : PInteger; enc : integer);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; num : PInteger; enc : integer);
var
  v0, v1 : DES_LONG;
  l : long;
  n : integer;
  ti : array[0..1] of DES_LONG;
  iv : PByte;
  c, cc :Byte;
begin
    l := length;
    n := num^;
    iv := @( ivec^)[0];
    if enc > 0 then
    begin
        while PostDec(l) > 0 do
        begin
            if n = 0 then  begin
                c2l(iv, v0);
                ti[0] := v0;
                c2l(iv, v1);
                ti[1] := v1;
                DES_encrypt1(@ti, schedule, DES_ENCRYPT);
                iv := @( ivec^)[0];
                v0 := ti[0];
                l2c(v0, iv);
                v0 := ti[1];
                l2c(v0, iv);
                iv := @( ivec^)[0];
            end;
            c := PostInc(_in)^  xor  iv[n];
            PostInc(_out)^ := c;
            iv[n] := c;
            n := (n + 1) and $07;
        end;
    end
    else
    begin
        while PostDec(l) > 0 do
        begin
            if n = 0 then
            begin
                c2l(iv, v0);
                ti[0] := v0;
                c2l(iv, v1);
                ti[1] := v1;
                DES_encrypt1(@ti, schedule, DES_ENCRYPT);
                iv := @( ivec^)[0];
                v0 := ti[0];
                l2c(v0, iv);
                v0 := ti[1];
                l2c(v0, iv);
                iv := @( ivec^)[0];
            end;
            cc := PostInc(_in)^;
            c := iv[n];
            iv[n] := cc;
            PostInc(_out)^ := c  xor  cc;
            n := (n + 1) and $07;
        end;
    end;
    v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0; c := 0; cc := 0;
    num^ := n;
end;

end.
