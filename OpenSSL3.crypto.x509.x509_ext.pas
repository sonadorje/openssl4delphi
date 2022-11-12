unit OpenSSL3.crypto.x509.x509_ext;

interface
uses OpenSSL.Api;

function X509_CRL_get_ext_count(const x : PX509_CRL):integer;
  function X509_CRL_get_ext_by_NID(const x : PX509_CRL; nid, lastpos : integer):integer;
  function X509_CRL_get_ext_by_OBJ(const x : PX509_CRL; obj : PASN1_OBJECT; lastpos : integer):integer;
  function X509_CRL_get_ext_by_critical(const x : PX509_CRL; crit, lastpos : integer):integer;
  function X509_CRL_get_ext(const x : PX509_CRL; loc : integer):PX509_EXTENSION;
  function X509_CRL_delete_ext( x : PX509_CRL; loc : integer):PX509_EXTENSION;
  function X509_CRL_get_ext_d2i(const x : PX509_CRL; nid : integer; crit, idx : PInteger):Pointer;
  function X509_CRL_add1_ext_i2d( x : PX509_CRL; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
  function X509_CRL_add_ext( x : PX509_CRL; ex : PX509_EXTENSION; loc : integer):integer;
  function X509_get_ext_count(const x : PX509):integer;
  function X509_get_ext_by_NID(const x : PX509; nid, lastpos : integer):integer;
  function X509_get_ext_by_OBJ(const x : PX509; obj : PASN1_OBJECT; lastpos : integer):integer;
  function X509_get_ext_by_critical(const x : PX509; crit, lastpos : integer):integer;
  function X509_get_ext(const x : PX509; loc : integer):PX509_EXTENSION;
  function X509_delete_ext( x : PX509; loc : integer):PX509_EXTENSION;
  function X509_add_ext( x : PX509; ex : PX509_EXTENSION; loc : integer):integer;
  function X509_get_ext_d2i(const x : PX509; nid : integer; crit, idx : PInteger):Pointer;
  function X509_add1_ext_i2d( x : PX509; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
  function X509_REVOKED_get_ext_count(const x : PX509_REVOKED):integer;
  function X509_REVOKED_get_ext_by_NID(const x : PX509_REVOKED; nid, lastpos : integer):integer;
  function X509_REVOKED_get_ext_by_OBJ(const x : PX509_REVOKED; obj : PASN1_OBJECT; lastpos : integer):integer;
  function X509_REVOKED_get_ext_by_critical(const x : PX509_REVOKED; crit, lastpos : integer):integer;
  function X509_REVOKED_get_ext(const x : PX509_REVOKED; loc : integer):PX509_EXTENSION;
  function X509_REVOKED_delete_ext( x : PX509_REVOKED; loc : integer):PX509_EXTENSION;
  function X509_REVOKED_add_ext( x : PX509_REVOKED; ex : PX509_EXTENSION; loc : integer):integer;
  function X509_REVOKED_get_ext_d2i(const x : PX509_REVOKED; nid : integer; crit, idx : PInteger):Pointer;
  function X509_REVOKED_add1_ext_i2d( x : PX509_REVOKED; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;

implementation
uses openssl3.crypto.x509.x509_v3, OpenSSL3.crypto.x509.v3_lib;

function X509_CRL_get_ext_count(const x : PX509_CRL):integer;
begin
    Result := X509v3_get_ext_count(x.crl.extensions);
end;


function X509_CRL_get_ext_by_NID(const x : PX509_CRL; nid, lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_NID(x.crl.extensions, nid, lastpos);
end;


function X509_CRL_get_ext_by_OBJ(const x : PX509_CRL; obj : PASN1_OBJECT; lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_OBJ(x.crl.extensions, obj, lastpos);
end;


function X509_CRL_get_ext_by_critical(const x : PX509_CRL; crit, lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_critical(x.crl.extensions, crit, lastpos);
end;


function X509_CRL_get_ext(const x : PX509_CRL; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_get_ext(x.crl.extensions, loc);
end;


function X509_CRL_delete_ext( x : PX509_CRL; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_delete_ext(x.crl.extensions, loc);
end;


function X509_CRL_get_ext_d2i(const x : PX509_CRL; nid : integer; crit, idx : PInteger):Pointer;
begin
    Result := X509V3_get_d2i(x.crl.extensions, nid, crit, idx);
end;


function X509_CRL_add1_ext_i2d( x : PX509_CRL; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
begin
    Result := X509V3_add1_i2d(@x.crl.extensions, nid, value, crit, flags);
end;


function X509_CRL_add_ext( x : PX509_CRL; ex : PX509_EXTENSION; loc : integer):integer;
begin
    Result := int(X509v3_add_ext(@x.crl.extensions, ex, loc) <> nil);
end;


function X509_get_ext_count(const x : PX509):integer;
begin
    Result := X509v3_get_ext_count(x.cert_info.extensions);
end;


function X509_get_ext_by_NID(const x : PX509; nid, lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_NID(x.cert_info.extensions, nid, lastpos);
end;


function X509_get_ext_by_OBJ(const x : PX509; obj : PASN1_OBJECT; lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_OBJ(x.cert_info.extensions, obj, lastpos);
end;


function X509_get_ext_by_critical(const x : PX509; crit, lastpos : integer):integer;
begin
    Exit(X509v3_get_ext_by_critical(x.cert_info.extensions, crit, lastpos));
end;


function X509_get_ext(const x : PX509; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_get_ext(x.cert_info.extensions, loc);
end;


function X509_delete_ext( x : PX509; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_delete_ext(x.cert_info.extensions, loc);
end;


function X509_add_ext( x : PX509; ex : PX509_EXTENSION; loc : integer):integer;
begin
    Result := int(X509v3_add_ext(@(x.cert_info.extensions), ex, loc) <> nil);
end;


function X509_get_ext_d2i(const x : PX509; nid : integer; crit, idx : PInteger):Pointer;
begin
    Result := X509V3_get_d2i(x.cert_info.extensions, nid, crit, idx);
end;


function X509_add1_ext_i2d( x : PX509; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
begin
    Exit(X509V3_add1_i2d(@x.cert_info.extensions, nid, value, crit, flags));
end;


function X509_REVOKED_get_ext_count(const x : PX509_REVOKED):integer;
begin
    Result := X509v3_get_ext_count(x.extensions);
end;


function X509_REVOKED_get_ext_by_NID(const x : PX509_REVOKED; nid, lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_NID(x.extensions, nid, lastpos);
end;


function X509_REVOKED_get_ext_by_OBJ(const x : PX509_REVOKED; obj : PASN1_OBJECT; lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_OBJ(x.extensions, obj, lastpos);
end;


function X509_REVOKED_get_ext_by_critical(const x : PX509_REVOKED; crit, lastpos : integer):integer;
begin
    Result := X509v3_get_ext_by_critical(x.extensions, crit, lastpos);
end;


function X509_REVOKED_get_ext(const x : PX509_REVOKED; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_get_ext(x.extensions, loc);
end;


function X509_REVOKED_delete_ext( x : PX509_REVOKED; loc : integer):PX509_EXTENSION;
begin
    Result := X509v3_delete_ext(x.extensions, loc);
end;


function X509_REVOKED_add_ext( x : PX509_REVOKED; ex : PX509_EXTENSION; loc : integer):integer;
begin
    Result := int(X509v3_add_ext(@(x.extensions), ex, loc) <> nil);
end;


function X509_REVOKED_get_ext_d2i(const x : PX509_REVOKED; nid : integer; crit, idx : PInteger):Pointer;
begin
    Result := X509V3_get_d2i(x.extensions, nid, crit, idx);
end;


function X509_REVOKED_add1_ext_i2d( x : PX509_REVOKED; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
begin
    Result := X509V3_add1_i2d(&x.extensions, nid, value, crit, flags);
end;


end.
