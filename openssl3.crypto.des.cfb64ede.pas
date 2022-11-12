unit openssl3.crypto.des.cfb64ede;

interface
uses OpenSSL.Api;

procedure DES_ede3_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; num : PInteger; enc : integer);
procedure DES_ede3_cfb_encrypt({const} _in : PByte; _out : PByte; numbits : integer; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; enc : integer);

implementation

uses openssl3.crypto.des.des_local, {$IFDEF MSWINDOWS}libc.win,{$ENDIF}openssl3.crypto.des.des_enc;



procedure DES_ede3_cfb_encrypt({const} _in : PByte; _out : PByte; numbits : integer; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; enc : integer);
var
  d0, d1, v0, v1 : DES_LONG;
  l, n : Cardinal;
  num, i : integer;
  ti : array[0..1] of DES_LONG;
  iv : PByte;
  ovec : array[0..15] of Byte;
begin
     l := length; n := uint32(numbits + 7) div 8;
     num := numbits;
    if num > 64 then Exit;
    iv := @( ivec^)[0];
    c2l(iv, v0);
    c2l(iv, v1);
    if enc > 0 then
    begin
        while l >= n do  begin
            l  := l - n;
            ti[0] := v0;
            ti[1] := v1;
            DES_encrypt3(@ti, ks1, ks2, ks3);
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
            if num = 32 then begin
                v0 := v1;
                v1 := d0;
            end
            else
            if (num = 64) then
            begin
                v0 := d0;
                v1 := d1;
            end
            else
            begin
                iv := @ovec[0];
                l2c(v0, iv);
                l2c(v1, iv);
                l2c(d0, iv);
                l2c(d1, iv);
                { shift ovec left most of the bits... }
                memmove(@ovec, PByte(@ovec) + num div 8, 8 + get_result(num mod 8 > 0, 1 , 0));
                { now the remaining bits }
                if num mod 8 <> 0 then
                    for i := 0 to 8-1 do
                    begin
                        ovec[i] := ovec[i] shl (num mod 8);
                        ovec[i] := ovec[i]  or (ovec[i + 1]  shr  (8 - num mod 8));
                    end;
                iv := @ovec[0];
                c2l(iv, v0);
                c2l(iv, v1);
            end;
        end;
    end
    else
    begin
        while l >= n do
        begin
            l  := l - n;
            ti[0] := v0;
            ti[1] := v1;
            DES_encrypt3(@ti, ks1, ks2, ks3);
            c2ln(_in, d0, d1, n);
            _in  := _in + n;
            {
             * 30-08-94 - eay - changed because l shr 32 and lshl32 are bad under
             * gcc :-(
             }
            if num = 32 then begin
                v0 := v1;
                v1 := d0;
            end
            else
            if (num = 64) then
            begin
                v0 := d0;
                v1 := d1;
            end
            else
            begin
                iv := @ovec[0];
                l2c(v0, iv);
                l2c(v1, iv);
                l2c(d0, iv);
                l2c(d1, iv);
                { shift ovec left most of the bits... }
                memmove(@ovec, PByte(@ovec) + num div 8, 8 + get_result(num mod 8 > 0, 1 , 0));
                { now the remaining bits }
                if num mod 8 <> 0 then
                   for i := 0 to 8-1 do
                   begin
                        ovec[i] := ovec[i] shl (num mod 8);
                        ovec[i]  := ovec[i]  or (ovec[i + 1]  shr  (8 - num mod 8));
                    end;
                iv := @ovec[0];
                c2l(iv, v0);
                c2l(iv, v1);
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

procedure DES_ede3_cfb64_encrypt({const} _in : PByte; _out : PByte; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; num : PInteger; enc : integer);
var
  v0, v1 : DES_LONG;
  l : long;
  n : integer;
  ti : array[0..1] of DES_LONG;
  iv : PByte;
  c, cc : Byte;
begin
     l := length;
     n := num^;
    iv := @( ivec^)[0];
    if enc > 0 then
    begin
        while PostDec(l) > 0 do
        begin
            if n = 0 then  begin
                c2l(iv, v0);
                c2l(iv, v1);
                ti[0] := v0;
                ti[1] := v1;
                DES_encrypt3(@ti, ks1, ks2, ks3);
                v0 := ti[0];
                v1 := ti[1];
                iv := @( ivec^)[0];
                l2c(v0, iv);
                l2c(v1, iv);
                iv := @( ivec^)[0];
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
            if n = 0 then begin
                c2l(iv, v0);
                c2l(iv, v1);
                ti[0] := v0;
                ti[1] := v1;
                DES_encrypt3(@ti, ks1, ks2, ks3);
                v0 := ti[0];
                v1 := ti[1];
                iv := @( ivec^)[0];
                l2c(v0, iv);
                l2c(v1, iv);
                iv := @( ivec^)[0];
            end;
            cc := PostInc(_in)^;
            c := iv[n];
            iv[n] := cc;
            PostInc(_out)^ := c  xor  cc;
            n := (n + 1) and $07;
        end;
    end;
    v0 := 0; v1 := 0; ti[0] := 0; ti[1] := 0; c := 0; cc := 0;
    num^ := n;
end;


end.
