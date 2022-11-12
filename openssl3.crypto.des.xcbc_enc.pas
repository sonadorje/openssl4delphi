unit openssl3.crypto.des.xcbc_enc;

interface
uses OpenSSL.Api;

 procedure DES_xcbc_encrypt(const _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; inw, outw : Pconst_DES_cblock; enc : integer);

implementation
uses openssl3.crypto.des.des_local, openssl3.crypto.des.des_enc;

procedure DES_xcbc_encrypt(const _in : PByte; _out : PByte; length : long; schedule : PDES_key_schedule; ivec : PDES_cblock; inw, outw : Pconst_DES_cblock; enc : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1, inW0, inW1, outW0, outW1 : DES_LONG;
  l : long;
  tin : array[0..1] of DES_LONG;
  iv, in2 : PByte;
begin
    l := length;
    in2 := @( inw^)[0];
    c2l(in2, inW0);
    c2l(in2, inW1);
    in2 := @( outw^)[0];
    c2l(in2, outW0);
    c2l(in2, outW1);
    iv := @( ivec^)[0];
    if enc > 0 then
    begin
        c2l(iv, tout0);
        c2l(iv, tout1);
        l  := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            tin0  := tin0 xor (tout0 xor inW0);
            tin[0] := tin0;
            tin1  := tin1 xor (tout1 xor inW1);
            tin[1] := tin1;
            DES_encrypt1(@tin, schedule, DES_ENCRYPT);
            tout0 := tin[0]  xor  outW0;
            l2c(tout0, _out);
            tout1 := tin[1]  xor  outW1;
            l2c(tout1, _out);
            l  := l - 8;
        end;
        if l <> -8 then
        begin
            c2ln(_in, tin0, tin1, l + 8);
            tin0  := tin0 xor (tout0 xor inW0);
            tin[0] := tin0;
            tin1  := tin1 xor (tout1 xor inW1);
            tin[1] := tin1;
            DES_encrypt1(@tin, schedule, DES_ENCRYPT);
            tout0 := tin[0]  xor  outW0;
            l2c(tout0, _out);
            tout1 := tin[1]  xor  outW1;
            l2c(tout1, _out);
        end;
        iv := @( ivec^)[0];
        l2c(tout0, iv);
        l2c(tout1, iv);
    end
    else
    begin
        c2l(iv, xor0);
        c2l(iv, xor1);
        l  := l - 8;
        while l > 0 do
        begin
            c2l(_in, tin0);
            tin[0] := tin0  xor  outW0;
            c2l(_in, tin1);
            tin[1] := tin1  xor  outW1;
            DES_encrypt1(@tin, schedule, DES_DECRYPT);
            tout0 := tin[0]  xor  xor0  xor  inW0;
            tout1 := tin[1]  xor  xor1  xor  inW1;
            l2c(tout0, _out);
            l2c(tout1, _out);
            xor0 := tin0;
            xor1 := tin1;
            l  := l - 8;
        end;
        if l <> -8 then
        begin
            c2l(_in, tin0);
            tin[0] := tin0  xor  outW0;
            c2l(_in, tin1);
            tin[1] := tin1  xor  outW1;
            DES_encrypt1(@tin, schedule, DES_DECRYPT);
            tout0 := tin[0]  xor  xor0  xor  inW0;
            tout1 := tin[1]  xor  xor1  xor  inW1;
            l2cn(tout0, tout1, _out, l + 8);
            xor0 := tin0;
            xor1 := tin1;
        end;
        iv := @( ivec^)[0];
        l2c(xor0, iv);
        l2c(xor1, iv);
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    inW0 := 0; inW1 := 0; outW0 := 0; outW1 := 0;
    tin[0] := 0; tin[1] := 0;
end;



end.
