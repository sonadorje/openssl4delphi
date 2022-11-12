unit openssl3.crypto.t_x509;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

procedure OSSL_STACK_OF_X509_free( certs : PSTACK_st_X509);
function X509_signature_dump(bp : PBIO;const sig : PASN1_STRING; indent : integer):integer;

implementation

uses
   openssl3.crypto.x509, openssl3.crypto.bio.bio_lib,
   openssl3.crypto.bio.bio_print, openssl3.crypto.x509.x_x509;






function X509_signature_dump(bp : PBIO;const sig : PASN1_STRING; indent : integer):integer;
var
  s : PByte;

  i, n : integer;
begin
    n := sig.length;
    s := sig.data;
    for i := 0 to n-1 do
    begin
        if i mod 18 = 0 then
        begin
            if (i > 0)  and  (BIO_write(bp, PUTF8Char(#10), 1) <= 0) then
                Exit(0);
            if BIO_indent(bp, indent, indent) <= 0  then
                Exit(0);
        end;
        if BIO_printf(bp, '%02x%s', [s[i], get_result((i + 1) = n , '' , ':')]) <= 0 then
            Exit(0);
    end;
    if BIO_write(bp, PUTF8Char(#10), 1 ) <> 1 then
        Exit(0);
    Result := 1;
end;

procedure OSSL_STACK_OF_X509_free( certs : PSTACK_st_X509);
begin
    sk_X509_pop_free(certs, X509_free);
end;


end.
