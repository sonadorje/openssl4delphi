unit openssl3.crypto.des.ecb_enc;

interface
uses OpenSSL.Api;

 function DES_options:PUTF8Char;
  procedure DES_ecb_encrypt( input : Pconst_DES_cblock; output : PDES_cblock; ks : PDES_key_schedule; enc : integer);
var
  init : integer;
  buf : array[0..11] of UTF8Char;

implementation
uses openssl3.crypto.o_str, openssl3.crypto.des.des_local,
     openssl3.crypto.des.des_enc;

function DES_options:PUTF8Char;
var
  pc: PUTF8Char;
begin
      init := 1;
    if init > 0 then
    begin
        pc := @buf;
        if sizeof(DES_LONG) <> sizeof(long) then
            OPENSSL_strlcpy(pc, 'des(int)', sizeof(buf))
        else
            OPENSSL_strlcpy(pc, 'des(long)', sizeof(buf));
        init := 0;
    end;
    Result := buf;
end;


procedure DES_ecb_encrypt( input : Pconst_DES_cblock; output : PDES_cblock; ks : PDES_key_schedule; enc : integer);
var
  l : DES_LONG;

  ll : array[0..1] of DES_LONG;

  _in, _out : PByte;
begin
     _in := @( input^)[0];
    _out := @( output^)[0];
    c2l(_in, l);
    ll[0] := l;
    c2l(_in, l);
    ll[1] := l;
    DES_encrypt1(@ll, ks, enc);
    l := ll[0];
    l2c(l, _out);
    l := ll[1];
    l2c(l, _out);
    l := 0; ll[0] := 0; ll[1] := 0;
end;


end.
