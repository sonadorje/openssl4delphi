unit openssl3.crypto.idea.i_ofb64;

interface
uses OpenSSL.Api;

procedure IDEA_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PIDEA_KEY_SCHEDULE; ivec : PByte; num : PInteger);

implementation
uses openssl3.crypto.idea.idea_local, openssl3.crypto.idea.i_cbc;

procedure IDEA_ofb64_encrypt({const} _in : PByte; _out : PByte; length : long; schedule : PIDEA_KEY_SCHEDULE; ivec : PByte; num : PInteger);
var
  v0, v1, t : Cardinal;
  n : integer;
  l : long;
  d : array[0..7] of Byte;
  dp : PByte;
  ti : array[0..1] of Cardinal;
  iv : PByte;
  save : integer;
begin
      n := num^;
      l := length;
    save := 0;
    if n < 0 then begin
        num^ := -1;
        Exit;
    end;
    iv := PByte(ivec);
    n2l(iv, v0);
    n2l(iv, v1);
    ti[0] := v0;
    ti[1] := v1;
    dp := {PUTF8Char}( @d);
    l2n(v0, dp);
    l2n(v1, dp);
    while PostDec(l)>0 do
    begin
        if n = 0 then
        begin
            IDEA_encrypt(Pulong(@ti), schedule);
            dp := @d;
            t := ti[0];
            l2n(t, dp);
            t := ti[1];
            l2n(t, dp);
            PostInc(save);
        end;
        PostInc(_out)^ := PostInc(_in)^  xor  d[n];
        n := (n + 1) and $07;
    end;
    if save > 0 then
    begin
        v0 := ti[0];
        v1 := ti[1];
        iv := PByte(ivec);
        l2n(v0, iv);
        l2n(v1, iv);
    end;
    t := 0; v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0;
    num^ := n;
end;


end.
