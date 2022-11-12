unit openssl3.crypto.cast.c_cfb64;

interface
uses OpenSSL.Api;

procedure CAST_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long;const schedule : PCAST_KEY; ivec : PByte; num : PInteger; enc : integer);

implementation
uses openssl3.crypto.cast.c_enc, openssl3.crypto.cast.cast_local;

procedure CAST_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long;const schedule : PCAST_KEY; ivec : PByte; num : PInteger; enc : integer);
var
  v0, v1, t : CAST_LONG;
  n : integer;
  l : long;
  ti : array[0..1] of CAST_LONG;
  iv: PByte;
  c, cc :Byte;
begin
     n := num^;
     l := length;
    iv := ivec;
    if enc > 0 then
    begin
        while PostDec(l) > 0  do
        begin
            if n = 0 then
            begin
                n2l(iv, v0);
                ti[0] := v0;
                n2l(iv, v1);
                ti[1] := v1;
                CAST_encrypt(PCAST_LONG (@ti), schedule);
                iv := ivec;
                t := ti[0];
                l2n(t, iv);
                t := ti[1];
                l2n(t, iv);
                iv := ivec;
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
                n2l(iv, v0);
                ti[0] := v0;
                n2l(iv, v1);
                ti[1] := v1;
                CAST_encrypt(PCAST_LONG (@ti), schedule);
                iv := ivec;
                t := ti[0];
                l2n(t, iv);
                t := ti[1];
                l2n(t, iv);
                iv := ivec;
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
