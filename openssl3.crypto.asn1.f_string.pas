unit openssl3.crypto.asn1.f_string;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function i2a_ASN1_STRING(bp : PBIO;const a : PASN1_STRING; &type : integer):integer;


implementation
uses  openssl3.crypto.bio.bio_print;

function i2a_ASN1_STRING(bp : PBIO;const a : PASN1_STRING; &type : integer):integer;
var
  i, n : integer;
  buf : array[0..1] of UTF8Char;
const
  h : PUTF8Char = '0123456789ABCDEF';
  label _err;
begin
    n := 0;
    if a = nil then Exit(0);
    if a.length = 0 then begin
        if BIO_write(bp, PUTF8Char('0'), 1) <> 1 then
            goto _err;
        n := 1;
    end
    else
    begin
        for i := 0 to a.length-1 do
        begin
            if (i <> 0)  and  (i mod 35 = 0) then
            begin
                if BIO_write(bp, PUTF8Char('\'#10), 2) <> 2 then
                    goto _err;
                n  := n + 2;
            end;
            buf[0] := h[Byte(a.data[i]  shr  4) and $0f];
            buf[1] := h[Byte(a.data[i]) and $0f];
            if BIO_write(bp, @buf, 2) <> 2  then
                goto _err;
            n  := n + 2;
        end;
    end;
    Exit(n);
 _err:
    Result := -1;
end;

end.
