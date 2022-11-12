unit openssl3.crypto.cast.c_skey;

interface
uses OpenSSL.Api;

procedure CAST_set_key(key : PCAST_KEY; len : integer;const data : PByte);

implementation
uses openssl3.crypto.cast.cast_s;

const
   S4: PCAST_LONG = @CAST_S_table4;
   S5: PCAST_LONG = @CAST_S_table5;
   S6: PCAST_LONG = @CAST_S_table6;
   S7: PCAST_LONG = @CAST_S_table7;

procedure CAST_exp(l: CAST_LONG; _A,a: PCAST_LONG; n: CAST_LONG);
begin
{$POINTERMATH ON}
  _A[n div 4] := l;
  a[n+3] := (l    )    and $ff;
  a[n+2] := (l shr  8) and $ff;
  a[n+1] := (l shr 16) and $ff;
  a[n+0] := (l shr 24) and $ff;
{$POINTERMATH OFF}
end;

procedure CAST_set_key(key : PCAST_KEY; len : integer;const data : PByte);
var
  x, z : array[0..15] of CAST_LONG;
  k : array[0..31] of CAST_LONG;
  _X, _Z : array[0..3] of CAST_LONG;
  l : CAST_LONG;
  _K : PCAST_LONG;
  i : integer;
begin
{$POINTERMATH ON}
    for i := 0 to 15 do
        x[i] := 0;
    if len > 16 then
       len := 16;
    for i := 0 to len-1 do
        x[i] := data[i];
    if len <= 10 then
       key.short_key := 1
    else
       key.short_key := 0;
    _K := @k[0];
    _X[0] := ((x[0] shl 24) or (x[1] shl 16) or (x[2] shl 8) or x[3]) and $ffffffff;
    _X[1] := ((x[4] shl 24) or (x[5] shl 16) or (x[6] shl 8) or x[7]) and $ffffffff;
    _X[2] := ((x[8] shl 24) or (x[9] shl 16) or (x[10] shl 8) or x[11]) and $ffffffff;
    _X[3] := ((x[12] shl 24) or (x[13] shl 16) or (x[14] shl 8) or x[15]) and $ffffffff;
    while true do
    begin
        l := _X[0]  xor  S4[x[13]]  xor  S5[x[15]]  xor  S6[x[12]]  xor  S7[x[14]]  xor  S6[x[8]];
        CAST_exp(l, @_Z, @z, 0);
        l := _X[2]  xor  S4[z[0]]  xor  S5[z[2]]  xor  S6[z[1]]  xor  S7[z[3]]  xor  S7[x[10]];
        CAST_exp(l, @_Z, @z, 4);
        l := _X[3]  xor  S4[z[7]]  xor  S5[z[6]]  xor  S6[z[5]]  xor  S7[z[4]]  xor  S4[x[9]];
        CAST_exp(l, @_Z, @z, 8);
        l := _X[1]  xor  S4[z[10]]  xor  S5[z[9]]  xor  S6[z[11]]  xor  S7[z[8]]  xor  S5[x[11]];
        CAST_exp(l, @_Z, @z, 12);
        K[0] := S4[z[8]]  xor  S5[z[9]]  xor  S6[z[7]]  xor  S7[z[6]]  xor  S4[z[2]];
        K[1] := S4[z[10]]  xor  S5[z[11]]  xor  S6[z[5]]  xor  S7[z[4]]  xor  S5[z[6]];
        K[2] := S4[z[12]]  xor  S5[z[13]]  xor  S6[z[3]]  xor  S7[z[2]]  xor  S6[z[9]];
        K[3] := S4[z[14]]  xor  S5[z[15]]  xor  S6[z[1]]  xor  S7[z[0]]  xor  S7[z[12]];
        l := _Z[2]  xor  S4[z[5]]  xor  S5[z[7]]  xor  S6[z[4]]  xor  S7[z[6]]  xor  S6[z[0]];
        CAST_exp(l, @_X, @x, 0);
        l := _Z[0]  xor  S4[x[0]]  xor  S5[x[2]]  xor  S6[x[1]]  xor  S7[x[3]]  xor  S7[z[2]];
        CAST_exp(l, @_X, @x, 4);
        l := _Z[1]  xor  S4[x[7]]  xor  S5[x[6]]  xor  S6[x[5]]  xor  S7[x[4]]  xor  S4[z[1]];
        CAST_exp(l, @_X, @x, 8);
        l := _Z[3]  xor  S4[x[10]]  xor  S5[x[9]]  xor  S6[x[11]]  xor  S7[x[8]]  xor  S5[z[3]];
        CAST_exp(l, @_X, @x, 12);
        K[4] := S4[x[3]]  xor  S5[x[2]]  xor  S6[x[12]]  xor  S7[x[13]]  xor  S4[x[8]];
        K[5] := S4[x[1]]  xor  S5[x[0]]  xor  S6[x[14]]  xor  S7[x[15]]  xor  S5[x[13]];
        K[6] := S4[x[7]]  xor  S5[x[6]]  xor  S6[x[8]]  xor  S7[x[9]]  xor  S6[x[3]];
        K[7] := S4[x[5]]  xor  S5[x[4]]  xor  S6[x[10]]  xor  S7[x[11]]  xor  S7[x[7]];
        l := _X[0]  xor  S4[x[13]]  xor  S5[x[15]]  xor  S6[x[12]]  xor  S7[x[14]]  xor  S6[x[8]];
        CAST_exp(l, @_Z, @z, 0);
        l := _X[2]  xor  S4[z[0]]  xor  S5[z[2]]  xor  S6[z[1]]  xor  S7[z[3]]  xor  S7[x[10]];
        CAST_exp(l, @_Z, @z, 4);
        l := _X[3]  xor  S4[z[7]]  xor  S5[z[6]]  xor  S6[z[5]]  xor  S7[z[4]]  xor  S4[x[9]];
        CAST_exp(l, @_Z, @z, 8);
        l := _X[1]  xor  S4[z[10]]  xor  S5[z[9]]  xor  S6[z[11]]  xor  S7[z[8]]  xor  S5[x[11]];
        CAST_exp(l, @_Z, @z, 12);
        K[8] := S4[z[3]]  xor  S5[z[2]]  xor  S6[z[12]]  xor  S7[z[13]]  xor  S4[z[9]];
        K[9] := S4[z[1]]  xor  S5[z[0]]  xor  S6[z[14]]  xor  S7[z[15]]  xor  S5[z[12]];
        K[10] := S4[z[7]]  xor  S5[z[6]]  xor  S6[z[8]]  xor  S7[z[9]]  xor  S6[z[2]];
        K[11] := S4[z[5]]  xor  S5[z[4]]  xor  S6[z[10]]  xor  S7[z[11]]  xor  S7[z[6]];
        l := _Z[2]  xor  S4[z[5]]  xor  S5[z[7]]  xor  S6[z[4]]  xor  S7[z[6]]  xor  S6[z[0]];
        CAST_exp(l, @_X, @x, 0);
        l := _Z[0]  xor  S4[x[0]]  xor  S5[x[2]]  xor  S6[x[1]]  xor  S7[x[3]]  xor  S7[z[2]];
        CAST_exp(l, @_X, @x, 4);
        l := _Z[1]  xor  S4[x[7]]  xor  S5[x[6]]  xor  S6[x[5]]  xor  S7[x[4]]  xor  S4[z[1]];
        CAST_exp(l, @_X, @x, 8);
        l := _Z[3]  xor  S4[x[10]]  xor  S5[x[9]]  xor  S6[x[11]]  xor  S7[x[8]]  xor  S5[z[3]];
        CAST_exp(l, @_X, @x, 12);
        _K[12] := S4[x[8]]  xor  S5[x[9]]  xor  S6[x[7]]  xor  S7[x[6]]  xor  S4[x[3]];
        _K[13] := S4[x[10]]  xor  S5[x[11]]  xor  S6[x[5]]  xor  S7[x[4]]  xor  S5[x[7]];
        _K[14] := S4[x[12]]  xor  S5[x[13]]  xor  S6[x[3]]  xor  S7[x[2]]  xor  S6[x[8]];
        _K[15] := S4[x[14]]  xor  S5[x[15]]  xor  S6[x[1]]  xor  S7[x[0]]  xor  S7[x[13]];
        if _K <> @k then break;
        _K  := _K + 16;
    end;
    for i := 0 to 15 do begin
        key.data[i * 2] := k[i];
        key.data[i * 2 + 1] := ((k[i + 16]) + 16) and $1f;
    end;

{$POINTERMATH OFF}
end;


end.
