unit openssl3.crypto.comp.c_zlib;

interface
 uses OpenSSL.Api;

procedure ossl_comp_zlib_cleanup;

implementation


procedure ossl_comp_zlib_cleanup;
begin
{$IFDEF ZLIB_SHARED}
    DSO_free(zlib_dso);
    zlib_dso := nil;
{$ENDIF}
end;

end.
