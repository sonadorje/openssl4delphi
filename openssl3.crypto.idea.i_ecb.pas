unit openssl3.crypto.idea.i_ecb;

interface
uses OpenSSL.Api;

function IDEA_options:PUTF8Char;
  procedure IDEA_ecb_encrypt(const _in : PByte; _out : PByte; ks : PIDEA_KEY_SCHEDULE);

implementation
uses openssl3.crypto.idea.idea_local, openssl3.crypto.idea.i_cbc;

function IDEA_options:PUTF8Char;
begin
    Result := 'idea(int)';
end;


procedure IDEA_ecb_encrypt(const _in : PByte; _out : PByte; ks : PIDEA_KEY_SCHEDULE);
var
  l0, l1 : Cardinal;
  d : array[0..1] of Cardinal;
begin
    n2l(_in, l0);
    d[0] := l0;
    n2l(_in, l1);
    d[1] := l1;
    IDEA_encrypt(@d, ks);
    l0 := d[0];
    l2n(l0, _out);
    l1 := d[1];
    l2n(l1, _out);
    l0 := 0; l1 := 0; d[0] := 0; d[1] := 0;
end;


end.
