unit openssl3.crypto.cast.c_enc;

interface
uses OpenSSL.Api;

procedure CAST_encrypt(data : PCAST_LONG;const key : PCAST_KEY);
procedure CAST_decrypt(data : PCAST_LONG;const key : PCAST_KEY);
procedure CAST_cbc_encrypt(const _in : PByte; _out : PByte; _length : long;const ks : PCAST_KEY; iv : PByte; enc : integer);



implementation
uses openssl3.crypto.cast.cast_s,   openssl3.crypto.cast.cast_local;

procedure CAST_encrypt(data : PCAST_LONG;const key : PCAST_KEY);
var
  l, r, t : uint32;
  k : Puint32;
  a, b, c, d : uint32;
begin
{$POINTERMATH ON}
    k := @(key.data[0]);
    l := data[0];
    r := data[1];
    begin
     t := (k[0*2] + r) and $ffffffff;
     t := ((((t) shl ((k[0*2+1]))) and $ffffffff) or ((t) shr ((32-((k[0*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
  end;

    begin
     t := (k[1*2]  xor  l) and $ffffffff;
     t := ((((t)shl((k[1*2+1]))) and $ffffffff) or ((t) shr ((32-((k[1*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
  end;

  begin
     t := (k[2*2] - r) and $ffffffff;
     t := ((((t)shl((k[2*2+1]))) and $ffffffff) or ((t) shr ((32-((k[2*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
  end;

    begin
     t := (k[3*2] + l) and $ffffffff;
     t := ((((t)shl((k[3*2+1]))) and $ffffffff) or ((t) shr ((32-((k[3*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
  end;

    begin
     t := (k[4*2]  xor  r) and $ffffffff;
     t := ((((t)shl((k[4*2+1]))) and $ffffffff) or ((t) shr ((32-((k[4*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
  end;

    begin
     t := (k[5*2] - l) and $ffffffff;
     t := ((((t)shl((k[5*2+1]))) and $ffffffff) or ((t) shr ((32-((k[5*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
  end;

    begin
     t := (k[6*2] + r) and $ffffffff;
     t := ((((t) shl ((k[6*2+1]))) and $ffffffff) or ((t) shr ((32-((k[6*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
  end;

  begin
     t := (k[7*2]  xor  l) and $ffffffff;
     t := ((((t)shl((k[7*2+1]))) and $ffffffff) or ((t) shr ((32-((k[7*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
  end;

  begin
     t := (k[8*2] - r) and $ffffffff;
     t := ((((t)shl((k[8*2+1]))) and $ffffffff) or ((t) shr ((32-((k[8*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
  end;

  begin
     t := (k[9*2] + l) and $ffffffff;
     t := ((((t)shl((k[9*2+1]))) and $ffffffff) or ((t) shr ((32-((k[9*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
  end;
;
    begin
     t := (k[10*2]  xor  r) and $ffffffff;
     t := ((((t)shl((k[10*2+1]))) and $ffffffff) or ((t) shr ((32-((k[10*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
  end;

  begin
     t := (k[11*2] - l) and $ffffffff;
     t := ((((t)shl((k[11*2+1]))) and $ffffffff) or ((t) shr ((32-((k[11*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
  end;

 if 0>=key.short_key then
  begin
        begin
           t := (k[12*2] + r) and $ffffffff;
           t := ((((t)shl((k[12*2+1]))) and $ffffffff) or ((t) shr ((32-((k[12*2+1]))) and 31)));
           a := CAST_S_table0[(t shr  8) and $ff];
           b := CAST_S_table1[(t ) and $ff];
           c := CAST_S_table2[(t shr 24) and $ff];
           d := CAST_S_table3[(t shr 16) and $ff];
           l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
        end;

        begin
           t := (k[13*2]  xor  l) and $ffffffff;
           t := ((((t)shl((k[13*2+1]))) and $ffffffff) or ((t) shr ((32-((k[13*2+1]))) and 31)));
           a := CAST_S_table0[(t shr  8) and $ff];
           b := CAST_S_table1[(t ) and $ff];
           c := CAST_S_table2[(t shr 24) and $ff];
           d := CAST_S_table3[(t shr 16) and $ff];
           r := r xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
        end;

        begin
           t := (k[14*2] - r) and $ffffffff;
           t := ((((t)shl((k[14*2+1]))) and $ffffffff) or ((t) shr ((32-((k[14*2+1]))) and 31)));
           a := CAST_S_table0[(t shr  8) and $ff];
           b := CAST_S_table1[(t ) and $ff];
           c := CAST_S_table2[(t shr 24) and $ff];
           d := CAST_S_table3[(t shr 16) and $ff];
           l := l xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
        end;

        begin
           t := (k[15*2] + l) and $ffffffff;
           t := ((((t)shl((k[15*2+1]))) and $ffffffff) or ((t) shr ((32-((k[15*2+1]))) and 31)));
           a := CAST_S_table0[(t shr  8) and $ff];
           b := CAST_S_table1[(t ) and $ff];
           c := CAST_S_table2[(t shr 24) and $ff];
           d := CAST_S_table3[(t shr 16) and $ff];
           r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
        end;

    end;
    data[1] := l  and  $ffffffff;
    data[0] := r  and  $ffffffff;

{$POINTERMATH OFF}
end;





procedure CAST_decrypt(data : PCAST_LONG;const key : PCAST_KEY);
var
  l, r, t, a, b, c, d : uint32;
  k : Puint32;
begin
{$POINTERMATH ON}
    k := @(key.data[0]);
    l := data[0];
    r := data[1];
    if 0>=key.short_key then
    begin
        begin
       t := (k[15*2] + r) and $ffffffff;
       t := ((((t)shl((k[15*2+1]))) and $ffffffff) or ((t) shr ((32-((k[15*2+1]))) and 31)));
       a := CAST_S_table0[(t shr  8) and $ff];
       b := CAST_S_table1[(t ) and $ff];
       c := CAST_S_table2[(t shr 24) and $ff];
       d := CAST_S_table3[(t shr 16) and $ff];
       l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
       end;

        begin
       t := (k[14*2] - l) and $ffffffff;
       t := ((((t)shl((k[14*2+1]))) and $ffffffff) or ((t) shr ((32-((k[14*2+1]))) and 31)));
       a := CAST_S_table0[(t shr  8) and $ff];
       b := CAST_S_table1[(t ) and $ff];
       c := CAST_S_table2[(t shr 24) and $ff];
       d := CAST_S_table3[(t shr 16) and $ff];
       r := r xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
       end;
;
        begin
       t := (k[13*2]  xor  r) and $ffffffff;
       t := ((((t)shl((k[13*2+1]))) and $ffffffff) or ((t) shr ((32-((k[13*2+1]))) and 31)));
       a := CAST_S_table0[(t shr  8) and $ff];
       b := CAST_S_table1[(t ) and $ff];
       c := CAST_S_table2[(t shr 24) and $ff];
       d := CAST_S_table3[(t shr 16) and $ff];
       l := l xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
       end;

        begin
       t := (k[12*2] + l) and $ffffffff;
       t := ((((t)shl((k[12*2+1]))) and $ffffffff) or ((t) shr ((32-((k[12*2+1]))) and 31)));
       a := CAST_S_table0[(t shr  8) and $ff];
       b := CAST_S_table1[(t ) and $ff];
       c := CAST_S_table2[(t shr 24) and $ff];
       d := CAST_S_table3[(t shr 16) and $ff];
       r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
       end;

    end;
    begin
     t := (k[11*2] - r) and $ffffffff;
     t := ((((t)shl((k[11*2+1]))) and $ffffffff) or ((t) shr ((32-((k[11*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
     end;
;
    begin
     t := (k[10*2]  xor  l) and $ffffffff;
     t := ((((t)shl((k[10*2+1]))) and $ffffffff) or ((t) shr ((32-((k[10*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
     end;

    begin
     t := (k[9*2] + r) and $ffffffff;
     t := ((((t)shl((k[9*2+1]))) and $ffffffff) or ((t) shr ((32-((k[9*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
     end;

    begin
     t := (k[8*2] - l) and $ffffffff;
     t := ((((t)shl((k[8*2+1]))) and $ffffffff) or ((t) shr ((32-((k[8*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
     end;

    begin
     t := (k[7*2]  xor  r) and $ffffffff;
     t := ((((t)shl((k[7*2+1]))) and $ffffffff) or ((t) shr ((32-((k[7*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
     end;

    begin
     t := (k[6*2] + l) and $ffffffff;
     t := ((((t)shl((k[6*2+1]))) and $ffffffff) or ((t) shr ((32-((k[6*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
     end;

    begin
     t := (k[5*2] - r) and $ffffffff;
     t := ((((t)shl((k[5*2+1]))) and $ffffffff) or ((t) shr ((32-((k[5*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
     end;

    begin
     t := (k[4*2]  xor  l) and $ffffffff;
     t := ((((t)shl((k[4*2+1]))) and $ffffffff) or ((t) shr ((32-((k[4*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
     end;

    begin
     t := (k[3*2] + r) and $ffffffff;
     t := ((((t)shl((k[3*2+1]))) and $ffffffff) or ((t) shr ((32-((k[3*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
     end;

    begin
     t := (k[2*2] - l) and $ffffffff;
     t := ((((t)shl((k[2*2+1]))) and $ffffffff) or ((t) shr ((32-((k[2*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a + b) and $ffffffff) xor c) and $ffffffff) - d) and $ffffffff);
     end;

    begin
     t := (k[1*2]  xor  r) and $ffffffff;
     t := ((((t)shl((k[1*2+1]))) and $ffffffff) or ((t) shr ((32-((k[1*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     l := l xor ((((((a - b) and $ffffffff) + c) and $ffffffff) xor d) and $ffffffff);
     end;

    begin
     t := (k[0*2] + l) and $ffffffff;
     t := ((((t)shl((k[0*2+1]))) and $ffffffff) or ((t) shr ((32-((k[0*2+1]))) and 31)));
     a := CAST_S_table0[(t shr  8) and $ff];
     b := CAST_S_table1[(t ) and $ff];
     c := CAST_S_table2[(t shr 24) and $ff];
     d := CAST_S_table3[(t shr 16) and $ff];
     r := r xor ((((((a xor b) and $ffffffff) - c) and $ffffffff) + d) and $ffffffff);
     end;

    data[1] := l  and  $ffffffff;
    data[0] := r  and  $ffffffff;
{$POINTERMATH OFF}
end;

procedure CAST_cbc_encrypt(const _in : PByte; _out : PByte; _length : long;const ks : PCAST_KEY; iv : PByte; enc : integer);
var
  tin : array[0..1] of CAST_LONG;
   tin0, tin1:  CAST_LONG;
   tout0, tout1, xor0, xor1:  CAST_LONG;
   l: Long;
begin

    l := _length;
    if enc > 0 then
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
            CAST_encrypt(@tin, ks);
            tout0 := tin[0];
            tout1 := tin[1];
            l2n(tout0, _out);
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
            CAST_encrypt(@tin, ks);
            tout0 := tin[0];
            tout1 := tin[1];
            l2n(tout0, _out);
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
            n2l(_in, tin1);
            tin[0] := tin0;
            tin[1] := tin1;
            CAST_decrypt(@tin, ks);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2n(tout0, _out);
            l2n(tout1, _out);
            xor0 := tin0;
            xor1 := tin1;
            l  := l - 8;
        end;
        if l <> -8 then
        begin
            n2l(_in, tin0);
            n2l(_in, tin1);
            tin[0] := tin0;
            tin[1] := tin1;
            CAST_decrypt(@tin, ks);
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


end.
