unit openssl3.crypto.pem.pem_x509;

interface
uses openssl.api;

function PEM_read_bio_X509( bp : PBIO; x : PPX509; cb : Tpem_password_cb; u : Pointer):PX509;
  function PEM_read_X509( fp : PFILE; x : PPX509; cb : Tpem_password_cb; u : Pointer):PX509;
  function PEM_write_bio_X509(&out : PBIO;const x : PX509):integer;
  function PEM_write_X509(&out : PFILE;const x : PX509):integer;

implementation
 uses openssl3.crypto.pem.pem_oth,                  openssl3.crypto.x509.x_x509,
      openssl3.crypto.pem.pem_lib;

function PEM_read_bio_X509( bp : PBIO; x : PPX509; cb : Tpem_password_cb; u : Pointer):PX509;
begin
  Result := PEM_ASN1_read_bio(@d2i_X509, 'CERTIFICATE', bp,  PPointer(x), cb, u);
end;


function PEM_read_X509( fp : PFILE; x : PPX509; cb : Tpem_password_cb; u : Pointer):PX509;
begin
  Result := PEM_ASN1_read(@d2i_X509, 'CERTIFICATE', fp,  PPointer(x), cb, u);
end;


function PEM_write_bio_X509(&out : PBIO;const x : PX509):integer;
begin
  Result :=   PEM_ASN1_write_bio(@i2d_X509, 'CERTIFICATE', out, x, Pointer(0) ,Pointer(0) ,0,Pointer(0) ,Pointer(0) );
end;


function PEM_write_X509(&out : PFILE;const x : PX509):integer;
begin
  Result :=   PEM_ASN1_write(@i2d_X509, 'CERTIFICATE', out, x, Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0) );
end;


end.
