unit openssl3.crypto.rc2.rc2_cbc;

interface
uses OpenSSL.Api;

procedure RC2_cbc_encrypt(const _in : PByte; _out : PByte; length : long; ks : PRC2_KEY; iv : PByte; encrypt : integer);
  procedure RC2_encrypt(d:Pulong; key : PRC2_KEY);
  procedure RC2_decrypt(d:Pulong; key : PRC2_KEY);

implementation
uses openssl3.crypto.rc2.rc2_local;

procedure RC2_cbc_encrypt(const _in : PByte; _out : PByte; length : long; ks : PRC2_KEY; iv : PByte; encrypt : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1 : Cardinal;
  l : long;
  tin : array[0..1] of Cardinal;
begin
      l := length;
    if encrypt > 0 then
    begin
        c2l(iv, tout0);
        c2l(iv, tout1);
        iv  := iv - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            RC2_encrypt(@tin, ks);
            tout0 := tin[0];
            l2c(tout0, _out);
            tout1 := tin[1];
            l2c(tout1, _out);
             l := l - 8;
        end;
        if l <> -8 then
        begin
            c2ln(_in, tin0, tin1, l + 8);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            RC2_encrypt(@tin, ks);
            tout0 := tin[0];
            l2c(tout0, _out);
            tout1 := tin[1];
            l2c(tout1, _out);
        end;
        l2c(tout0, iv);
        l2c(tout1, iv);
    end
    else
    begin
        c2l(iv, xor0);
        c2l(iv, xor1);
        iv  := iv - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            tin[0] := tin0;
            c2l(_in, tin1);
            tin[1] := tin1;
            RC2_decrypt(@tin, ks);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2c(tout0, _out);
            l2c(tout1, _out);
            xor0 := tin0;
            xor1 := tin1;
            l  := l - 8;
        end;
        if l <> -8 then
        begin
            c2l(_in, tin0);
            tin[0] := tin0;
            c2l(_in, tin1);
            tin[1] := tin1;
            RC2_decrypt(@tin, ks);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2cn(tout0, tout1, _out, l + 8);
            xor0 := tin0;
            xor1 := tin1;
        end;
        l2c(xor0, iv);
        l2c(xor1, iv);
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    tin[0] := 0; tin[1] := 0;
end;


procedure RC2_encrypt(d: Pulong; key : PRC2_KEY);
var
  i, n : integer;
  p0, p1 : PRC2_INT;
  x0, x1, x2, x3, t : RC2_INT;
  l : Cardinal;
begin
{$POINTERMATH ON}
    l := d[0];
    x0 := RC2_INT( l) and $ffff;
    x1 := RC2_INT (l  shr  16);
    l := d[1];
    x2 := RC2_INT( l) and $ffff;
    x3 := RC2_INT (l  shr  16);
    n := 3;
    i := 5;
    p0 := @(key.data[0]); p1 := @(key.data[0]);
    while true do begin
        t := (x0 + (x1 and not x3) + (x2 and x3) + PostInc(p0)^) and $ffff;
        x0 := (t shl 1) or (t  shr  15);
        t := (x1 + (x2 and not x0) + (x3 and x0) + PostInc(p0)^) and $ffff;
        x1 := (t shl 2) or (t  shr  14);
        t := (x2 + (x3 and not x1) + (x0 and x1) + PostInc(p0)^) and $ffff;
        x2 := (t shl 3) or (t  shr  13);
        t := (x3 + (x0 and not x2) + (x1 and x2) + PostInc(p0)^) and $ffff;
        x3 := (t shl 5) or (t  shr  11);
        if PreDec(i) = 0  then
        begin
            if PreDec(n) = 0 then
                break;
            i := get_result(n = 2 , 6 , 5);
            x0  := x0 + (p1[x3 and $3f]);
            x1  := x1 + (p1[x0 and $3f]);
            x2  := x2 + (p1[x1 and $3f]);
            x3  := x3 + (p1[x2 and $3f]);
        end;
    end;
    d[0] := ulong(x0 and $ffff) or (ulong(x1 and $ffff) shl 16);
    d[1] := ulong(x2 and $ffff) or (ulong(x3 and $ffff) shl 16);
{$POINTERMATH OFF}
end;


procedure RC2_decrypt(d: Pulong; key : PRC2_KEY);
var
  i, n : integer;
  p0, p1 : PRC2_INT;
  x0, x1, x2, x3, t : RC2_INT;
  l : Cardinal;
begin
{$POINTERMATH ON}
    l := d[0];
    x0 := RC2_INT(l) and $ffff;
    x1 := RC2_INT (l  shr  16);
    l := d[1];
    x2 := RC2_INT(l) and $ffff;
    x3 := RC2_INT(l  shr  16);
    n := 3;
    i := 5;
    p0 := @(key.data[63]);
    p1 := @(key.data[0]);
    while true do
    begin
        t := ((x3 shl 11) or (x3  shr  5)) and $ffff;
        x3 := (t - (x0 and not x2) - (x1 and x2) - PostDec(p0)^) and $ffff;
        t := ((x2 shl 13) or (x2  shr  3)) and $ffff;
        x2 := (t - (x3 and not x1) - (x0 and x1) - PostDec(p0)^) and $ffff;
        t := ((x1 shl 14) or (x1  shr  2)) and $ffff;
        x1 := (t - (x2 and not x0) - (x3 and x0) - PostDec(p0)^) and $ffff;
        t := ((x0 shl 15) or (x0  shr  1)) and $ffff;
        x0 := (t - (x1 and not x3) - (x2 and x3) - PostDec(p0)^) and $ffff;
        if PreDec(i) = 0  then
        begin
            if PreDec(n) = 0 then
                break;
            i := get_result(n = 2 , 6 , 5);
            x3 := (x3 - p1[x2 and $3f]) and $ffff;
            x2 := (x2 - p1[x1 and $3f]) and $ffff;
            x1 := (x1 - p1[x0 and $3f]) and $ffff;
            x0 := (x0 - p1[x3 and $3f]) and $ffff;
        end;
    end;
    d[0] := ulong(x0 and $ffff) or (ulong(x1 and $ffff) shl 16);
    d[1] := ulong(x2 and $ffff) or (ulong(x3 and $ffff) shl 16);
{$POINTERMATH OFF}
end;


end.
