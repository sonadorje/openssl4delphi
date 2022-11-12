unit openssl3.crypto.rsa_chk;

interface
uses OpenSSL.Api, openssl3.crypto.rsa_sp800_56b_check;

function ossl_rsa_validate_private(const key : PRSA):Boolean;
 function ossl_rsa_validate_pairwise(const key : PRSA):integer;
function ossl_rsa_validate_public(const key : PRSA):integer;

implementation





function ossl_rsa_validate_public(const key : PRSA):integer;
begin
    Result := ossl_rsa_sp800_56b_check_public(key);
end;



function ossl_rsa_validate_pairwise(const key : PRSA):integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(ossl_rsa_sp800_56b_check_keypair(key, nil, -1, RSA_bits(key)));
{$ELSE Exit(rsa_validate_keypair_multiprime(key, nil));}
{$ENDIF}
end;

function ossl_rsa_validate_private(const key : PRSA):Boolean;
begin
    Result := ossl_rsa_sp800_56b_check_private(key);
end;

end.
