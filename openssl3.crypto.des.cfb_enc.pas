unit openssl3.crypto.des.cfb_enc;

interface
uses OpenSSL.Api;

procedure DES_cfb_encrypt({const} _in : PByte; _out : PByte; numbits : integer; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; enc : integer);

implementation
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_cfb_encrypt({const} _in : PByte; _out : PByte; numbits : integer; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; enc : integer);
var
  d0, d1, v0, v1 : DES_LONG;
  l : Cardinal;
  num, n, rem, i : integer;
  ti : array[0..1] of DES_LONG;
  iv : PByte;
  ovec : array[0..15] of Byte;
  sh : array[0..3] of uint32;
  //ovec : PByte;
begin
      l := length;
      num := numbits div 8;
      n := (numbits + 7) div 8;
      rem := numbits mod 8;
{$IFNDEF L_ENDIAN}
{$ELSE} ovec := PByte(sh;
    { I kind of count that compiler optimizes away this assertion, }
    assert(sizeof(sh[0]) = 4); { as this holds true for all, }
    { but 16-bit platforms...      }
{$ENDIF}
    if (numbits <= 0)  or  (numbits > 64) then exit;
    iv := @( ivec^)[0];
    c2l(iv, v0);
    c2l(iv, v1);
    if enc > 0 then
    begin
        while l >= ulong(n) do
        begin
            l  := l - n;
            ti[0] := v0;
            ti[1] := v1;
            DES_encrypt1(PDES_LONG(@ti), schedule, DES_ENCRYPT);
            c2ln(_in, d0, d1, n);
            _in  := _in + n;
            d0  := d0 xor (ti[0]);
            d1  := d1 xor (ti[1]);
            l2cn(d0, d1, _out, n);
            _out  := _out + n;
            {
             * 30-08-94 - eay - changed because l shr 32 and lshl32 are bad under
             * gcc :-(
             }
            if numbits = 32 then
            begin
                v0 := v1;
                v1 := d0;
            end
            else
            if (numbits = 64)  then
            begin
                v0 := d0;
                v1 := d1;
            end
            else
            begin
{$IFNDEF L_ENDIAN}
                iv := @ovec[0];
                l2c(v0, iv);
                l2c(v1, iv);
                l2c(d0, iv);
                l2c(d1, iv);
{$ELSE} sh[0] := v0, sh[1] = v1, sh[2] = d0, sh[3] = d1;
{$ENDIF}
                if rem = 0 then
                   memmove(@ovec, PByte(@ovec) + num, 8)
                else
                    for i := 0 to 8-1 do
                        ovec[i] := ovec[i + num] shl rem or  ovec[i + num + 1]  shr  (8 - rem);
{$IFDEF L_ENDIAN}
                v0 := sh[0], v1 = sh[1];
{$ELSE}
                iv := @ovec[0];
                c2l(iv, v0);
                c2l(iv, v1);
{$ENDIF}
            end;
        end;
    end
    else
    begin
        while l >= ulong(n) do
        begin
            l  := l - n;
            ti[0] := v0;
            ti[1] := v1;
            DES_encrypt1(PDES_LONG(@ti), schedule, DES_ENCRYPT);
            c2ln(_in, d0, d1, n);
            _in  := _in + n;
            {
             * 30-08-94 - eay - changed because l shr 32 and lshl32 are bad under
             * gcc :-(
             }
            if numbits = 32 then begin
                v0 := v1;
                v1 := d0;
            end
            else
            if (numbits = 64) then
            begin
                v0 := d0;
                v1 := d1;
            end
            else
            begin
{$IFNDEF L_ENDIAN}
                iv := @ovec[0];
                l2c(v0, iv);
                l2c(v1, iv);
                l2c(d0, iv);
                l2c(d1, iv);
{$ELSE} sh[0] := v0, sh[1] = v1, sh[2] = d0, sh[3] = d1;
{$ENDIF}
                if rem = 0 then
                   memmove(@ovec, PByte(@ovec) + num, 8)
                else
                    for i := 0 to 8-1 do
                        ovec[i] := ovec[i + num] shl rem or ovec[i + num + 1]  shr  (8 - rem);
{$IFDEF L_ENDIAN}
                v0 := sh[0], v1 = sh[1];
{$ELSE}
                iv := @ovec[0];
                c2l(iv, v0);
                c2l(iv, v1);
{$ENDIF}
            end;
            d0  := d0 xor (ti[0]);
            d1  := d1 xor (ti[1]);
            l2cn(d0, d1, _out, n);
            _out  := _out + n;
        end;
    end;
    iv := @( ivec^)[0];
    l2c(v0, iv);
    l2c(v1, iv);
    v0 := 0; v1 := 0; d0 := 0; d1 := 0; ti[0] := 0; ti[1] := 0;
end;


end.
