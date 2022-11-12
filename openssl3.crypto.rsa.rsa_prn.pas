unit openssl3.crypto.rsa.rsa_prn;

interface
uses openssl.api;

function RSA_print_fp(fp : PFILE;const x : PRSA; off : integer):integer;
  function RSA_print(bp : PBIO;const x : PRSA; off : integer):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bio.bss_file,    openssl3.crypto.bio.bio_lib,
     openssl3.crypto.evp.p_lib,                     openssl3.crypto.evp.p_legacy ;

function RSA_print_fp(fp : PFILE;const x : PRSA; off : integer):integer;
var
  b : PBIO;
  ret : integer;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then  begin
        ERR_raise(ERR_LIB_RSA, ERR_R_BUF_LIB);
        Exit(0);
    end;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret := RSA_print(b, x, off);
    BIO_free(b);
    Result := ret;
end;


function RSA_print(bp : PBIO;const x : PRSA; off : integer):integer;
var
  pk : PEVP_PKEY;
  ret : integer;
begin
    pk := EVP_PKEY_new;
    if pk = nil then Exit(0);
    ret := EVP_PKEY_set1_RSA(pk, PRSA(x));
    if ret > 0 then
       ret := EVP_PKEY_print_private(bp, pk, off, nil);
    EVP_PKEY_free(pk);
    Result := ret;
end;


end.
