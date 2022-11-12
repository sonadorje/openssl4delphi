unit OpenSSL3.providers.common.digest_to_nid;

interface
uses OpenSSL.Api;


function ossl_digest_get_approved_nid(const md : PEVP_MD):integer;


function ossl_digest_md_to_nid(const md : PEVP_MD; it : POSSL_ITEM; it_len : size_t):integer;

implementation
uses openssl3.crypto.evp.evp_lib;


function ossl_digest_md_to_nid(const md : PEVP_MD; it : POSSL_ITEM; it_len : size_t):integer;
var
  i : size_t;
begin
{$POINTERMATH ON}
    if md = nil then Exit(NID_undef);
    for i := 0 to it_len-1 do
        if EVP_MD_is_a(md, it[i].ptr)  then
            Exit(int(it[i].id));
    Result := NID_undef;
{$POINTERMATH OFF}
end;



function ossl_digest_get_approved_nid(const md : PEVP_MD):integer;
const  name_to_nid: array[0..10] of TOSSL_ITEM = (
        ( id:NID_sha1;      ptr:OSSL_DIGEST_NAME_SHA1      ),
        ( id:NID_sha224;    ptr:OSSL_DIGEST_NAME_SHA2_224  ),
        ( id:NID_sha256;    ptr:OSSL_DIGEST_NAME_SHA2_256  ),
        ( id:NID_sha384;    ptr:OSSL_DIGEST_NAME_SHA2_384  ),
        ( id:NID_sha512;    ptr:OSSL_DIGEST_NAME_SHA2_512  ),
        ( id:NID_sha512_224; ptr:OSSL_DIGEST_NAME_SHA2_512_224 ),
        ( id:NID_sha512_256; ptr:OSSL_DIGEST_NAME_SHA2_512_256 ),
        ( id:NID_sha3_224;  ptr:OSSL_DIGEST_NAME_SHA3_224  ),
        ( id:NID_sha3_256;  ptr:OSSL_DIGEST_NAME_SHA3_256  ),
        ( id:NID_sha3_384;  ptr:OSSL_DIGEST_NAME_SHA3_384  ),
        ( id:NID_sha3_512;  ptr:OSSL_DIGEST_NAME_SHA3_512  )
    );
begin
   
    Result := ossl_digest_md_to_nid(md, @name_to_nid, Length(name_to_nid));
end;






end.
