unit openssl3.crypto.mdc2.mdc2dgst;

interface
uses OpenSSL.Api;

function _MDC2_Update(c : PMDC2_CTX;{const} _in : PByte; len : size_t):integer;

procedure mdc2_body(c : PMDC2_CTX;const _in : PByte; len : size_t);
function _MDC2_Init( c : PMDC2_CTX):integer;
function _MDC2_Final( md : PByte; c : PMDC2_CTX):integer;

implementation

uses openssl3.crypto.des.set_key,            openssl3.crypto.des.des_enc;


function _MDC2_Final( md : PByte; c : PMDC2_CTX):integer;
var
  i : uint32;
  j : integer;
begin
    i := c.num;
    j := c.pad_type;
    if (i > 0)  or  (j = 2) then
    begin
        if j = 2 then
            c.data[PostInc(i)] := $80;
        memset(@(c.data[i]), 0, MDC2_BLOCK - i);
        mdc2_body(c, @c.data, MDC2_BLOCK);
    end;
    memcpy(md, PByte(@c.h), MDC2_BLOCK);
    memcpy(@(md[MDC2_BLOCK]), PByte(@c.hh), MDC2_BLOCK);
    Result := 1;
end;

procedure l2c(l: DES_LONG;c: PByte);
begin
  PostInc(c)^ :=Byte((l     ) and $ff);
  PostInc(c)^ :=Byte((l shr  8) and $ff);
  PostInc(c)^ :=Byte((l shr 16) and $ff);
  PostInc(c)^ :=Byte((l shr 24) and $ff);
end;

procedure c2l(c: PByte;var l: DES_LONG);
begin
  l := (DES_LONG( PostInc(c)^))    ;
 l := l or ((DES_LONG( PostInc(c)^)) shl  8);
 l := l or ((DES_LONG( PostInc(c)^)) shl 16);
 l := l or ((DES_LONG( PostInc(c)^)) shl 24);
end;



function _MDC2_Init( c : PMDC2_CTX):integer;
begin
    c.num := 0;
    c.pad_type := 1;
    memset(@(c.h[0]), $52, MDC2_BLOCK);
    memset(@(c.hh[0]), $25, MDC2_BLOCK);
    Result := 1;
end;

procedure mdc2_body(c : PMDC2_CTX;const _in : PByte; len : size_t);
var
  tin0, tin1, ttin0, ttin1 : DES_LONG;
  d, dd : array[0..1] of DES_LONG;
  k : TDES_key_schedule;
  p : PByte;
  i : size_t;
begin

    i := 0;
    while i < len do
    begin
        c2l(_in, tin0);
        d[0] := tin0; dd[0] := tin0;
        c2l(_in, tin1);
        d[1] := tin1; dd[1] := tin1;
        c.h[0] := (c.h[0] and $9f) or $40;
        c.hh[0] := (c.hh[0] and $9f) or $20;
        DES_set_odd_parity(@c.h);
        DES_set_key_unchecked(@c.h, @k);
        DES_encrypt1(@d, @k, 1);
        DES_set_odd_parity(@c.hh);
        DES_set_key_unchecked(@c.hh, @k);
        DES_encrypt1(@dd, @k, 1);
        ttin0 := tin0  xor  dd[0];
        ttin1 := tin1  xor  dd[1];
        tin0  := tin0 xor (d[0]);
        tin1  := tin1 xor (d[1]);
        p := @c.h;
        l2c(tin0, p);
        l2c(ttin1, p);
        p := @c.hh;
        l2c(ttin0, p);
        l2c(tin1, p);
        i := i + 8;
    end;
end;



function _MDC2_Update(c : PMDC2_CTX;{const} _in : PByte; len : size_t):integer;
var
  i, j : size_t;
begin
    i := c.num;
    if i <> 0 then begin
        if len < MDC2_BLOCK - i then
        begin
            { partial block }
            memcpy(@(c.data[i]), _in, len);
            c.num  := c.num + (int(len));
            Exit(1);
        end
        else
        begin
            { filled one }
            j := MDC2_BLOCK - i;
            memcpy(@(c.data[i]), _in, j);
            len  := len - j;
            _in  := _in + j;
            c.num := 0;
            mdc2_body(c, @(c.data[0]), MDC2_BLOCK);
        end;
    end;
    i := len and not (size_t(MDC2_BLOCK - 1));
    if i > 0 then mdc2_body(c, _in, i);
    j := len - i;
    if j > 0 then
    begin
        memcpy(@(c.data[0]), @(_in[i]), j);
        c.num := int(j);
    end;
    Result := 1;
end;



end.
