unit openssl3.crypto.idea.i_cbc;

interface
uses OpenSSL.Api;

 procedure IDEA_cbc_encrypt(const _in : PByte; _out : PByte; length : long; ks : PIDEA_KEY_SCHEDULE; iv : PByte; encrypt : integer);
  procedure IDEA_encrypt(d: Pulong; key : PIDEA_KEY_SCHEDULE);

implementation
uses openssl3.crypto.idea.idea_local;

procedure IDEA_cbc_encrypt(const _in : PByte; _out : PByte; length : long; ks : PIDEA_KEY_SCHEDULE; iv : PByte; encrypt : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1 : Cardinal;
  l : long;
  tin : array[0..1] of Cardinal;
begin
    l := length;
    if encrypt > 0 then
    begin
        n2l(iv, tout0);
        n2l(iv, tout1);
        iv  := iv - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            n2l(_in, tin0);
            n2l(_in, tin1);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            IDEA_encrypt(@tin, ks);
            tout0 := tin[0];
            l2n(tout0, _out);
            tout1 := tin[1];
            l2n(tout1, _out);
            l  := l - 8;
        end;
        if l <> -8 then
        begin
            n2ln(_in, tin0, tin1, l + 8);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            IDEA_encrypt(@tin, ks);
            tout0 := tin[0];
            l2n(tout0, _out);
            tout1 := tin[1];
            l2n(tout1, _out);
        end;
        l2n(tout0, iv);
        l2n(tout1, iv);
    end
    else
    begin
        n2l(iv, xor0);
        n2l(iv, xor1);
        iv  := iv - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            n2l(_in, tin0);
            tin[0] := tin0;
            n2l(_in, tin1);
            tin[1] := tin1;
            IDEA_encrypt(@tin, ks);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2n(tout0, _out);
            l2n(tout1, _out);
            xor0 := tin0;
            xor1 := tin1;
        end;
        if l <> -8 then
        begin
            n2l(_in, tin0);
            tin[0] := tin0;
            n2l(_in, tin1);
            tin[1] := tin1;
            IDEA_encrypt(@tin, ks);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2nn(tout0, tout1, _out, l + 8);
            xor0 := tin0;
            xor1 := tin1;
        end;
        l2n(xor0, iv);
        l2n(xor1, iv);
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    tin[0] := 0; tin[1] := 0;
end;


procedure IDEA_encrypt(d: Pulong; key : PIDEA_KEY_SCHEDULE);
var
  p : PIDEA_INT;
  x1, x2, x3, x4, t0, t1, ul : Cardinal;
  procedure E_IDEA(num: int);
  begin
        x1 := x1 and $ffff;
        idea_mul(x1,x1,p^,ul);
        PostInc(p);
        x2 := x2 + PostInc(p^);
        x3 := x3 + PostInc(p)^;
        x4 := x4 and $ffff;
        idea_mul(x4,x4,p^,ul);
        PostInc(p);
        t0 := (x1 xor x3) and $ffff;
        idea_mul(t0,t0,p^,ul);
        PostInc(p);
        t1 := (t0+(x2 xor x4)) and $ffff;
        idea_mul(t1,t1,p^,ul);
        PostInc(p);
        t0 := t0 + t1;
        x1 := x1 xor t1;
        x4 := x4 xor t0;
        ul := x2 xor t0; { do the swap to x3 }
        x2 := x3 xor t1;
        x3 := ul;
   end;
begin
{$POINTERMATH ON}
    x2 := d[0];
    x1 := (x2  shr  16);
    x4 := d[1];
    x3 := (x4  shr  16);
    p := @(key.data[0][0]);
    E_IDEA(0);
    E_IDEA(1);
    E_IDEA(2);
    E_IDEA(3);
    E_IDEA(4);
    E_IDEA(5);
    E_IDEA(6);
    E_IDEA(7);
    x1 := x1 and $ffff;
    idea_mul(x1, x1, p^, ul);
    PostInc(p);
    t0 := x3 + PostInc(p)^;
    t1 := x2 + PostInc(p)^;
    x4 := x4 and  $ffff;
    idea_mul(x4, x4, p^, ul);
    d[0] := (t0 and $ffff) or ((x1 and $ffff) shl 16);
    d[1] := (x4 and $ffff) or ((t1 and $ffff) shl 16);
{$POINTERMATH OFF}
end;


end.
