unit openssl3.crypto.des.ncbc_enc;

interface
uses OpenSSL.Api;

procedure DES_ncbc_encrypt(const _in : PByte; _out : PByte; length : long; _schedule : PDES_key_schedule; ivec : PDES_cblock; enc : integer);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_ncbc_encrypt(const _in : PByte; _out : PByte; length : long; _schedule : PDES_key_schedule; ivec : PDES_cblock; enc : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1 : DES_LONG;
  l : long;
  tin : array[0..1] of DES_LONG;
  iv : PByte;
begin
    l := length;
    iv := @( ivec^)[0];
    if enc > 0 then
    begin
        c2l(iv, tout0);
        c2l(iv, tout1);
        l := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            tin0  := tin0 xor tout0;
            tin[0] := tin0;
            tin1  := tin1 xor tout1;
            tin[1] := tin1;
            DES_encrypt1(PDES_LONG(@tin), _schedule, DES_ENCRYPT);
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
            tin[0] := tin0;
            tin1  := tin1 xor tout1;
            tin[1] := tin1;
            DES_encrypt1(PDES_LONG(@tin), _schedule, DES_ENCRYPT);
            tout0 := tin[0];
            l2c(tout0, _out);
            tout1 := tin[1];
            l2c(tout1, _out);
        end;
{$IFNDEF CBC_ENC_C__DONT_UPDATE_IV}
        iv := @( ivec^)[0];
        l2c(tout0, iv);
        l2c(tout1, iv);
{$ENDIF}
    end
    else
    begin
        c2l(iv, xor0);
        c2l(iv, xor1);
        l  := l - 8;
        while (l >= 0) do
        begin
            c2l(_in, tin0);
            tin[0] := tin0;
            c2l(_in, tin1);
            tin[1] := tin1;
            DES_encrypt1(PDES_LONG(@tin), _schedule, DES_DECRYPT);
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
            DES_encrypt1(PDES_LONG(@tin), _schedule, DES_DECRYPT);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2cn(tout0, tout1, _out, l + 8);
{$IFNDEF CBC_ENC_C__DONT_UPDATE_IV}
            xor0 := tin0;
            xor1 := tin1;
{$ENDIF}
        end;
{$IFNDEF CBC_ENC_C__DONT_UPDATE_IV}
        iv := @( ivec^)[0];
        l2c(xor0, iv);
        l2c(xor1, iv);
{$ENDIF}
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    tin[0] := 0; tin[1] := 0;
end;


end.
