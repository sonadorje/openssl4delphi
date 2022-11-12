unit openssl3.crypto.asn1.a_print;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ASN1_PRINTABLE_type({const} s : PByte; len : integer):integer;
  function ASN1_UNIVERSALSTRING_to_string(s : PASN1_UNIVERSALSTRING):integer;
  function ASN1_STRING_print(bp : PBIO;const v : PASN1_STRING):integer;

implementation
uses openssl3.crypto.ctype, openssl3.crypto.bio.bio_lib;

function ASN1_PRINTABLE_type({const} s : PByte; len : integer):integer;
var
  c, ia5, t61 : integer;
begin
    ia5 := 0;
    t61 := 0;
    if s = nil then Exit(V_ASN1_PRINTABLESTRING);
    if len < 0 then
       len := Length(PUTF8Char(s));
    while PostDec(len) > 0 do
    begin
        c := (PostInc(s)^);
        if not ossl_isasn1print(c) then
            ia5 := 1;
        if not ossl_isascii(c) then
            t61 := 1;
    end;
    if t61 > 0 then
       Exit(V_ASN1_T61STRING);
    if ia5 > 0 then
       Exit(V_ASN1_IA5STRING);
    Result := V_ASN1_PRINTABLESTRING;
end;


function ASN1_UNIVERSALSTRING_to_string(s : PASN1_UNIVERSALSTRING):integer;
var
  i : integer;

  p : PByte;
begin
    if (s.&type <> V_ASN1_UNIVERSALSTRING) then Exit(0);
    if s.length mod 4  <> 0 then
        Exit(0);
    p := s.data;
    i := 0;
    while i < s.length do
    begin
        if (p[0] <> ord(#0))  or  (p[1] <> Ord(#0))  or  (p[2] <> Ord(#0)) then
            break
        else
            p := p + 4;
        i := i + 4;
    end;
    if i < s.length then
       Exit(0);
    p := s.data;
    i := 3;
    while i < s.length do
    begin
        PostInc(p)^ := s.data[i];
        i := i + 4;
    end;
    (p)^ := Ord(#0);
    s.length  := s.length  div 4;
    s.&type := ASN1_PRINTABLE_type(s.data, s.length);
    Result := 1;
end;


function ASN1_STRING_print(bp : PBIO;const v : PASN1_STRING):integer;
var
  i, n : integer;
  buf : array[0..79] of UTF8Char;
  p: PByte;
begin
    if v = nil then Exit(0);
    n := 0;
    p := v.data;
    for i := 0 to v.length-1 do
    begin
        if (p[i] > ord('~'))  or
           ( (p[i] < ord(' '))   and
             (Chr(p[i]) <> #10)  and  (Chr(p[i]) <> #13)) then
            buf[n] := '.'
        else
            buf[n] := UTF8Char(p[i]);
        Inc(n);
        if n >= 80 then
        begin
            if BIO_write(bp, @buf, n) <= 0 then
                Exit(0);
            n := 0;
        end;
    end;
    if n > 0 then
       if (BIO_write(bp, @buf, n) <= 0) then
            Exit(0);
    Result := 1;
end;

end.
