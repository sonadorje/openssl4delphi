unit OpenSSL3.include.openssl.bio;

interface
uses OpenSSL.Api;

procedure BIO_set_fp(b: PBIO; fp: PFILE; c: Integer);
procedure BIO_get_mem_ptr(b: PBIO; pp: Pointer);
function BIO_get_mem_data(b: PBIO; pp: Pointer): int;

implementation
uses openssl3.crypto.bio.bio_lib;

//include\openssl\bio.h

function BIO_get_mem_data(b: PBIO; pp: Pointer): int;
begin
   Result := BIO_ctrl(b,BIO_CTRL_INFO,0, PUTF8Char(pp))
end;

procedure BIO_get_mem_ptr(b: PBIO; pp: Pointer);
begin
   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, PUTF8Char(pp))
end;

procedure BIO_set_fp(b: PBIO; fp: PFILE; c: Integer);
begin
   BIO_ctrl(b,BIO_C_SET_FILE_PTR,c, PUTF8Char(fp))
end;

end.
