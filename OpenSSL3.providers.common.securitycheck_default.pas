unit OpenSSL3.providers.common.securitycheck_default;

interface
uses OpenSSL.Api;

function ossl_securitycheck_enabled( libctx : POSSL_LIB_CTX):Boolean;

 function ossl_digest_rsa_sign_get_md_nid(ctx : POSSL_LIB_CTX;const md : PEVP_MD; sha1_allowed : integer):integer;

const // 1d arrays
  name_to_nid : array[0..5] of TOSSL_ITEM = (
        ( id: NID_md5;       ptr: OSSL_DIGEST_NAME_MD5       ),
        ( id: NID_md5_sha1;  ptr: OSSL_DIGEST_NAME_MD5_SHA1  ),
        ( id: NID_md2;       ptr: OSSL_DIGEST_NAME_MD2       ),
        ( id: NID_md4;       ptr: OSSL_DIGEST_NAME_MD4       ),
        ( id: NID_mdc2;      ptr: OSSL_DIGEST_NAME_MDC2      ),
        ( id: NID_ripemd160; ptr: OSSL_DIGEST_NAME_RIPEMD160 )
    );

implementation
uses OpenSSL3.providers.common.securitycheck, OpenSSL3.providers.common.digest_to_nid;

function ossl_digest_rsa_sign_get_md_nid(ctx : POSSL_LIB_CTX;const md : PEVP_MD; sha1_allowed : integer):integer;
var
  mdnid : integer;
begin
    mdnid := ossl_digest_get_approved_nid_with_sha1(ctx, md, 1);
    if mdnid = NID_undef then
       mdnid := ossl_digest_md_to_nid(md, @name_to_nid, Length(name_to_nid));
    Result := mdnid;
end;


function ossl_securitycheck_enabled( libctx : POSSL_LIB_CTX):Boolean;
begin
    Result := False;
end;


end.
