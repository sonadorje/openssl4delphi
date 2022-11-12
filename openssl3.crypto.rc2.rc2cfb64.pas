unit openssl3.crypto.rc2.rc2cfb64;

interface
uses OpenSSL.Api;

 procedure RC2_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PRC2_KEY; ivec : PByte; num : PInteger; encrypt : integer);

implementation
 uses openssl3.crypto.rc2.rc2_local,           openssl3.crypto.rc2.rc2_cbc;

procedure RC2_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PRC2_KEY; ivec : PByte; num : PInteger; encrypt : integer);
var
  v0, v1, t : Cardinal;
  n : integer;
  l : long;
  ti : array[0..1] of Cardinal;
  iv : PByte;
  c, cc : Byte;
begin
      n := num^;
      l := length;
    iv := PByte(ivec);
    if encrypt > 0 then
    begin
        while PostDec(l) > 0 do
        begin
            if n = 0 then
            begin
                c2l(iv, v0);
                ti[0] := v0;
                c2l(iv, v1);
                ti[1] := v1;
                RC2_encrypt(Pulong (@ti), schedule);
                iv := PByte(ivec);
                t := ti[0];
                l2c(t, iv);
                t := ti[1];
                l2c(t, iv);
                iv := PByte(ivec);
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
                RC2_encrypt(Pulong (@ti), schedule);
                iv := PByte(ivec);
                t := ti[0];
                l2c(t, iv);
                t := ti[1];
                l2c(t, iv);
                iv := PByte(ivec);
            end;
            cc := PostInc(_in)^;
            c := iv[n];
            iv[n] := cc;
            PostInc(_out)^ := c  xor  cc;
            n := (n + 1) and $07;
        end;
    end;
    v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0; t := 0; c := 0; cc := 0;
    num^ := n;
end;



end.
