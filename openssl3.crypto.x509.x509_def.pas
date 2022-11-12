unit openssl3.crypto.x509.x509_def;

interface
uses OpenSSL.Api;

function X509_get_default_private_dir:PUTF8Char;
  function X509_get_default_cert_area:PUTF8Char;
  function X509_get_default_cert_dir:PUTF8Char;
  function X509_get_default_cert_file:PUTF8Char;
  function X509_get_default_cert_dir_env:PUTF8Char;
  function X509_get_default_cert_file_env:PUTF8Char;

implementation
uses OpenSSL3.common;

function X509_get_default_private_dir:PUTF8Char;
begin
    Result := X509_PRIVATE_DIR;
end;


function X509_get_default_cert_area:PUTF8Char;
begin
    Result := X509_CERT_AREA;
end;


function X509_get_default_cert_dir:PUTF8Char;
begin
    Result := X509_CERT_DIR;
end;


function X509_get_default_cert_file:PUTF8Char;
begin
    Result := X509_CERT_FILE;
end;


function X509_get_default_cert_dir_env:PUTF8Char;
begin
    Result := X509_CERT_DIR_EVP;
end;


function X509_get_default_cert_file_env:PUTF8Char;
begin
    Result := X509_CERT_FILE_EVP;
end;


end.
