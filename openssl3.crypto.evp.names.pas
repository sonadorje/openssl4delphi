unit openssl3.crypto.evp.names;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

procedure digest_from_name(const name : PUTF8Char; data : Pointer);
function evp_get_digestbyname_ex(libctx : POSSL_LIB_CTX;const name : PUTF8Char):PEVP_MD;
function EVP_get_digestbyname(const name : PUTF8Char):PEVP_MD;
function EVP_get_digestbynid(a: Integer): PEVP_MD;
function EVP_get_cipherbyname(const name : PUTF8Char):PEVP_CIPHER;
 function evp_get_cipherbyname_ex(libctx : POSSL_LIB_CTX;const name : PUTF8Char):PEVP_CIPHER;
 procedure cipher_from_name(const name : PUTF8Char; data : Pointer);
procedure evp_cleanup_int;

function EVP_add_cipher(const c : PEVP_CIPHER):integer;
function EVP_add_digest(const md : PEVP_MD):integer;

implementation

uses openssl3.crypto.core_namemap,      openssl3.crypto.objects.o_names,
     openssl3.crypto.evp.evp_pbe,       openssl3.crypto.objects.obj_xref,
     openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.init,              openssl3.crypto.objects.obj_dat;





function EVP_add_digest(const md : PEVP_MD):integer;
var
  r : integer;
  name : PUTF8Char;
begin
    name := OBJ_nid2sn(md.&type);
    r := OBJ_NAME_add(name, OBJ_NAME_TYPE_MD_METH, PUTF8Char( md));
    if r = 0 then Exit(0);
    r := OBJ_NAME_add(OBJ_nid2ln(md.&type), OBJ_NAME_TYPE_MD_METH, PUTF8Char( md));
    if r = 0 then Exit(0);
    if (md.pkey_type > 0)  and  (md.&type <> md.pkey_type) then
    begin
        r := OBJ_NAME_add(OBJ_nid2sn(md.pkey_type),
                         OBJ_NAME_TYPE_MD_METH or OBJ_NAME_ALIAS, name);
        if r = 0 then Exit(0);
        r := OBJ_NAME_add(OBJ_nid2ln(md.pkey_type),
                         OBJ_NAME_TYPE_MD_METH or OBJ_NAME_ALIAS, name);
    end;
    Result := r;
end;


function EVP_add_cipher(const c : PEVP_CIPHER):integer;
begin
    if c = nil then Exit(0);
    result := OBJ_NAME_add(OBJ_nid2sn(c.nid), OBJ_NAME_TYPE_CIPHER_METH, c);
    if Result = 0 then Exit(0);
    Result := OBJ_NAME_add(OBJ_nid2ln(c.nid), OBJ_NAME_TYPE_CIPHER_METH, c);

end;

procedure evp_cleanup_int;
begin
    OBJ_NAME_cleanup(OBJ_NAME_TYPE_KDF_METH);
    OBJ_NAME_cleanup(OBJ_NAME_TYPE_CIPHER_METH);
    OBJ_NAME_cleanup(OBJ_NAME_TYPE_MD_METH);
    {
     * The above calls will only clean out the contents of the name hash
     * table, but not the hash table itself.  The following line does that
     * part.  -- Richard Levitte
     }
    OBJ_NAME_cleanup(-1);
    EVP_PBE_cleanup();
    OBJ_sigid_free();
    evp_app_cleanup_int();
end;



procedure cipher_from_name(const name : PUTF8Char; data : Pointer);
var
  cipher : PPEVP_CIPHER;
begin
    cipher := data;
    if cipher^ <> nil then Exit;
    cipher^ := PEVP_CIPHER(OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH));
end;

function evp_get_cipherbyname_ex(libctx : POSSL_LIB_CTX;const name : PUTF8Char):PEVP_CIPHER;
var
  cp : PEVP_CIPHER;
  namemap : POSSL_NAMEMAP;
  id : integer;
begin
    if 0>= OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil) then
        Exit(nil);
    cp := PEVP_CIPHER(OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH));
    if cp <> nil then Exit(cp);
    {
     * It's not in the method database, but it might be there under a different
     * name. So we check for aliases in the EVP namemap and try all of those
     * in turn.
     }
    namemap := ossl_namemap_stored(libctx);
    id := ossl_namemap_name2num(namemap, name);
    if id = 0 then Exit(nil);
    if 0>= ossl_namemap_doall_names(namemap, id, cipher_from_name, @cp ) then
        Exit(nil);
    Result := cp;
end;


function EVP_get_cipherbyname(const name : PUTF8Char):PEVP_CIPHER;
begin
    Result := evp_get_cipherbyname_ex(nil, name);
end;

function evp_get_digestbyname_ex(libctx : POSSL_LIB_CTX;const name : PUTF8Char):PEVP_MD;
var
  dp : PEVP_MD;
  namemap : POSSL_NAMEMAP;
  id : integer;
begin
    if  0>= OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, nil) then
        Exit(nil);
    dp := PEVP_MD (OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH));
    if dp <> nil then
       Exit(dp);

    namemap := ossl_namemap_stored(libctx);
    id := ossl_namemap_name2num(namemap, name);
    if id = 0 then Exit(nil);
    if  0>= ossl_namemap_doall_names(namemap, id, digest_from_name, &dp ) then
        Exit(nil);
    Result := dp;
end;

function EVP_get_digestbyname(const name : PUTF8Char):PEVP_MD;
begin
    Result := evp_get_digestbyname_ex(nil, name);
end;

function EVP_get_digestbynid(a: Integer): PEVP_MD;
begin
   Result := EVP_get_digestbyname(OBJ_nid2sn(a));
end;

procedure digest_from_name(const name : PUTF8Char; data : Pointer);
var
  md : PPEVP_MD;
begin
    md := data;
    if md^ <> nil then
      exit;
    md^ := PEVP_MD (OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH));
end;


end.
