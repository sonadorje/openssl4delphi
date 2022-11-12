unit openssl3.crypto.bf.bf_enc;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

procedure BF_encrypt(data : PBF_LONG;const key : PBF_KEY);
  procedure BF_decrypt(data : PBF_LONG;const key : PBF_KEY);
  procedure BF_cbc_encrypt(const _in : PByte; _out : PByte; length : long;const schedule : PBF_KEY; ivec : PByte; encrypt : integer);

implementation
uses  openssl3.crypto.bf.bf_local;

procedure BF_encrypt(data : PBF_LONG;const key : PBF_KEY);
var
  l, r : BF_LONG;
  p, s: PBF_LONG;
begin
{$POINTERMATH ON}
    p := @key.P;
    s := @(key.S[0]);
    l := data[0];
    r := data[1];
    l  := l xor (p[0]);
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
{$IF BF_ROUNDS = 20}
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);
{$ENDIF}
    r  := r xor (p[BF_ROUNDS + 1]);
    data[1] := l and $ffffffff;
    data[0] := r and $ffffffff;

{$POINTERMATH OFF}
end;


procedure BF_decrypt(data : PBF_LONG;const key : PBF_KEY);
var
  l, r : BF_LONG;
  p, s: PBF_LONG;
begin
{$POINTERMATH ON}
    p := @key.P;
    s := @(key.S[0]);
    l := data[0];
    r := data[1];
    l  := l xor (p[BF_ROUNDS + 1]);
{$IF BF_ROUNDS = 20}
    BF_ENC(r, l, s, p[20]);
    BF_ENC(l, r, s, p[19]);
    BF_ENC(r, l, s, p[18]);
    BF_ENC(l, r, s, p[17]);
{$ENDIF}
    BF_ENC(r, l, s, p[16]);
    BF_ENC(l, r, s, p[15]);
    BF_ENC(r, l, s, p[14]);
    BF_ENC(l, r, s, p[13]);
    BF_ENC(r, l, s, p[12]);
    BF_ENC(l, r, s, p[11]);
    BF_ENC(r, l, s, p[10]);
    BF_ENC(l, r, s, p[9]);
    BF_ENC(r, l, s, p[8]);
    BF_ENC(l, r, s, p[7]);
    BF_ENC(r, l, s, p[6]);
    BF_ENC(l, r, s, p[5]);
    BF_ENC(r, l, s, p[4]);
    BF_ENC(l, r, s, p[3]);
    BF_ENC(r, l, s, p[2]);
    BF_ENC(l, r, s, p[1]);
    r  := r xor (p[0]);
    data[1] := l and $ffffffff;
    data[0] := r and $ffffffff;
{$POINTERMATH OFF}
end;


procedure BF_cbc_encrypt(const _in : PByte; _out : PByte; length : long;const schedule : PBF_KEY; ivec : PByte; encrypt : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1 : BF_LONG;
  l : long;
  tin : array[0..1] of BF_LONG;
begin
    l := length;
    if encrypt > 0 then
    begin
        n2l(ivec, tout0);
        n2l(ivec, tout1);
        ivec  := ivec - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            n2l(_in, tin0);
            n2l(_in, tin1);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            BF_encrypt(@tin, schedule);
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
            BF_encrypt(@tin, schedule);
            tout0 := tin[0];
            tout1 := tin[1];
            l2n(tout0, _out);
            l2n(tout1, _out);
        end;
        l2n(tout0, ivec);
        l2n(tout1, ivec);
    end
    else
    begin
        n2l(ivec, xor0);
        n2l(ivec, xor1);
        ivec  := ivec - 8;
        l  := l - 8;
        while l >= 0 do
        begin
            n2l(_in, tin0);
            n2l(_in, tin1);
            tin[0] := tin0;
            tin[1] := tin1;
            BF_decrypt(@tin, schedule);
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
            BF_decrypt(@tin, schedule);
            tout0 := tin[0]  xor  xor0;
            tout1 := tin[1]  xor  xor1;
            l2nn(tout0, tout1, _out, l + 8);
            xor0 := tin0;
            xor1 := tin1;
        end;
        l2n(xor0, ivec);
        l2n(xor1, ivec);
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    tin[0] := 0; tin[1] := 0;
end;


end.
