unit openssl3.crypto.modes.xts128;

interface
uses OpenSSL.Api;

type
  u64_a1= uint64;
  Pu64_a1 = ^u64_a1;

function CRYPTO_xts128_encrypt( ctx : PXTS128_CONTEXT;{const} iv, inp : PByte; _out : PByte; len : size_t; enc : integer):integer;

implementation


function CRYPTO_xts128_encrypt( ctx : PXTS128_CONTEXT;{const} iv, inp : PByte; _out : PByte; len : size_t; enc : integer):integer;
type
 u_st = record
    case integer of
      0:( u: array [0..1]  of uint64);
      1:( d: array[0..4-1] of uint32);
      2:( c: array[0..16-1] of uint8);
  end;
 u1_st = record
    case integer of
      0:( u: array [0..1]  of uint64);
      1:( c: array[0..16-1] of uint8);
  end;
var
  i, carry, res : uint32;
  c1 : size_t;
  c2 : uint8;

  //carry, res : uint32;
  c4 : size_t;
  c5 : uint8;
  tweak, scratch: u_st;
  tweak1: u1_st;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    //DECLARE_IS_ENDIAN;
    if len < 16 then Exit(-1);
    memcpy(@tweak.c, iv, 16);
    ctx.block2(@tweak.c, @tweak.c, ctx.key2);
    if (0>=enc)  and  (len mod 16 > 0) then
        len  := len - 16;
    while len >= 16 do  begin
{$IF defined(STRICT_ALIGNMENT)}
        memcpy(scratch.c, inp, 16);
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
{$ELSE} scratch.u[0] := Pu64_a1(inp)[0]  xor  tweak.u[0];
        scratch.u[1] := Pu64_a1(inp)[1]  xor  tweak.u[1];
{$ENDIF}
        ctx.block1 (@scratch.c, @scratch.c, ctx.key1);
{$IF defined(STRICT_ALIGNMENT)}
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        memcpy(out, scratch.c, 16);
{$ELSE}
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        Pu64_a1(_out)[0] := scratch.u[0];
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        Pu64_a1(_out)[1] := scratch.u[1];
{$ENDIF}
        inp  := inp + 16;
        _out  := _out + 16;
        len  := len - 16;
        if len = 0 then Exit(0);
        if ossl_is_endian.little <> 0 then
        begin
            res := $87 and (int(tweak.d[3])  shr  31);
            carry := uint32(tweak.u[0]  shr  63);
            tweak.u[0] := (tweak.u[0] shl 1)  xor  res;
            tweak.u[1] := (tweak.u[1] shl 1) or carry;
        end
        else
        begin
            c1 := 0;
            for i := 0 to 16-1 do
            begin
                {
                 * + substitutes for |, because c is 1 bit
                 }
                c1  := c1 + (size_t(tweak.c[i]) shl 1);
                tweak.c[i] := uint8(c1);
                c1 := c1  shr  8;
            end;
            tweak.c[0]  := tweak.c[0] xor (uint8($87 and (0 - c1)));
        end;
    end;
    if enc > 0 then
    begin
        for i := 0 to len-1 do
        begin
            c2 := inp[i];
            _out[i] := scratch.c[i];
            scratch.c[i] := c2;
        end;
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        ctx.block1 (@scratch.c, @scratch.c, ctx.key1);
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        memcpy(_out - 16, @scratch.c, 16);
    end
    else
    begin
       
        if ossl_is_endian.little <> 0 then
        begin
            res := $87 and (int(tweak.d[3])  shr  31);
            carry := uint32(tweak.u[0]  shr  63);
            tweak1.u[0] := (tweak.u[0] shl 1)  xor  res;
            tweak1.u[1] := (tweak.u[1] shl 1) or carry;
        end
        else
        begin
            c1 := 0;
            for i := 0 to 16-1 do
            begin
                {
                 * + substitutes for |, because c is 1 bit
                 }
                c1  := c1 + (size_t(tweak.c[i]) shl 1);
                tweak1.c[i] := uint8(c1);
                c1 := c1  shr  8;
            end;
            tweak1.c[0]  := tweak1.c[0] xor (uint8($87 and (0 - c1)));
        end;
{$IF defined(STRICT_ALIGNMENT)}
        memcpy(scratch.c, inp, 16);
        scratch.u[0]  := scratch.u[0] xor (tweak1.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak1.u[1]);
{$ELSE} scratch.u[0] := Pu64_a1(inp)[0]  xor  tweak1.u[0];
        scratch.u[1] := Pu64_a1(inp)[1]  xor  tweak1.u[1];
{$ENDIF}
        ctx.block1 (@scratch.c, @scratch.c, ctx.key1);
        scratch.u[0]  := scratch.u[0] xor (tweak1.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak1.u[1]);
        for i := 0 to len-1 do
        begin
            c5 := inp[16 + i];
            _out[16 + i] := scratch.c[i];
            scratch.c[i] := c5;
        end;
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        ctx.block1 (@scratch.c, @scratch.c, ctx.key1);
{$IF defined(STRICT_ALIGNMENT)}
        scratch.u[0]  := scratch.u[0] xor (tweak.u[0]);
        scratch.u[1]  := scratch.u[1] xor (tweak.u[1]);
        memcpy(_out, scratch.c, 16);
{$ELSE} Pu64_a1(_out)[0] := scratch.u[0]  xor  tweak.u[0];
        Pu64_a1(_out)[1] := scratch.u[1]  xor  tweak.u[1];
{$ENDIF}
    end;
    Result := 0;
{$POINTERMATH OFF}
end;


end.
