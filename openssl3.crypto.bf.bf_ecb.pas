unit openssl3.crypto.bf.bf_ecb;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function BF_options:PUTF8Char;
  procedure BF_ecb_encrypt(const _in : PByte; _out : PByte;const key : PBF_KEY; encrypt : integer);

implementation
uses openssl3.crypto.bf.bf_local,    openssl3.crypto.bf.bf_enc;

function BF_options:PUTF8Char;
begin
    Result := 'blowfish(ptr)';
end;


procedure BF_ecb_encrypt(const _in : PByte; _out : PByte;const key : PBF_KEY; encrypt : integer);
var
  l : BF_LONG;
  d : array[0..1] of BF_LONG;
begin
    n2l(_in, l);
    d[0] := l;
    n2l(_in, l);
    d[1] := l;
    if encrypt > 0 then
       BF_encrypt(@d, key)
    else
       BF_decrypt(@d, key);
    l := d[0];
    l2n(l, _out);
    l := d[1];
    l2n(l, _out);
    l := 0; d[0] := 0; d[1] := 0;
end;


end.
