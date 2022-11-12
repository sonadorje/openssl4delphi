unit openssl3.crypto.idea.i_cfb64;

interface
uses OpenSSL.Api;

procedure IDEA_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PIDEA_KEY_SCHEDULE; ivec : PByte; num : PInteger; encrypt : integer);

implementation
uses openssl3.crypto.idea.idea_local, openssl3.crypto.idea.i_cbc;

procedure IDEA_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PIDEA_KEY_SCHEDULE; ivec : PByte; num : PInteger; encrypt : integer);
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
    if n < 0 then
    begin
        num^ := -1;
        exit;
    end;
    iv := PByte(ivec);
    if encrypt > 0 then
    begin
        while PostDec(l)>0 do
        begin
            if n = 0 then  begin
                n2l(iv, v0);
                ti[0] := v0;
                n2l(iv, v1);
                ti[1] := v1;
                IDEA_encrypt(Pulong(@ti), schedule);
                iv := PByte(ivec);
                t := ti[0];
                l2n(t, iv);
                t := ti[1];
                l2n(t, iv);
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
        while PostDec(l)>0 do
        begin
            if n = 0 then begin
                n2l(iv, v0);
                ti[0] := v0;
                n2l(iv, v1);
                ti[1] := v1;
                IDEA_encrypt(Pulong(@ti), schedule);
                iv := PByte(ivec);
                t := ti[0];
                l2n(t, iv);
                t := ti[1];
                l2n(t, iv);
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
