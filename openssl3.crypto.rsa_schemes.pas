unit openssl3.crypto.rsa_schemes;

interface
uses OpenSSL.Api;

type
   Tmeth_is_a_func = function (const meth : Pointer; name : PUTF8Char):Boolean;

function ossl_rsa_oaeppss_nid2name( md : integer):PUTF8Char;
function ossl_rsa_mgf_nid2name( mgf : integer):PUTF8Char;
function ossl_rsa_oaeppss_md2nid(const md : PEVP_MD):integer;
 function meth2nid(const meth : Pointer; meth_is_a : Tmeth_is_a_func;const items : POSSL_ITEM; items_n : size_t):integer;
function md_is_a(const md : Pointer; name : PUTF8Char):Boolean;
function nid2name(meth : integer;const items : POSSL_ITEM; items_n : size_t):PUTF8Char;

const oaeppss_name_nid_map: array[0..6] of TOSSL_ITEM  = (
    ( id: NID_sha1;         ptr: OSSL_DIGEST_NAME_SHA1         ),
    ( id: NID_sha224;       ptr: OSSL_DIGEST_NAME_SHA2_224     ),
    ( id: NID_sha256;       ptr: OSSL_DIGEST_NAME_SHA2_256     ),
    ( id: NID_sha384;       ptr: OSSL_DIGEST_NAME_SHA2_384     ),
    ( id: NID_sha512;       ptr: OSSL_DIGEST_NAME_SHA2_512     ),
    ( id: NID_sha512_224;   ptr: OSSL_DIGEST_NAME_SHA2_512_224 ),
    ( id: NID_sha512_256;   ptr: OSSL_DIGEST_NAME_SHA2_512_256 )
);
implementation
uses openssl3.crypto.evp.evp_lib;

function md_is_a(const md : Pointer; name : PUTF8Char):Boolean;
begin
    Result := EVP_MD_is_a(md, name);
end;



function meth2nid(const meth : Pointer; meth_is_a : Tmeth_is_a_func;const items : POSSL_ITEM; items_n : size_t):integer;
var
  i : size_t;
begin
{$POINTERMATH ON}
    if meth <> nil then
       for i := 0 to items_n-1 do
            if meth_is_a(meth, items[i].ptr) then
                Exit(int(items[i].id));
    Result := NID_undef;
{$POINTERMATH OFF}
end;


function ossl_rsa_oaeppss_md2nid(const md : PEVP_MD):integer;
begin
    Result := meth2nid(md, md_is_a,
                    @oaeppss_name_nid_map, Length(oaeppss_name_nid_map));
end;

function ossl_rsa_mgf_nid2name( mgf : integer):PUTF8Char;
begin
    if mgf = NID_mgf1 then Exit(SN_mgf1);
    Result := nil;
end;

function nid2name(meth : integer;const items : POSSL_ITEM; items_n : size_t):PUTF8Char;
var
  i : size_t;
begin
{$POINTERMATH ON}
    for i := 0 to items_n -1 do
        if meth = int(items[i].id)  then
            Exit(items[i].ptr);
    Result := nil;
{$POINTERMATH OFF}
end;



function ossl_rsa_oaeppss_nid2name( md : integer):PUTF8Char;
begin
    Result := nid2name(md, @oaeppss_name_nid_map, Length(oaeppss_name_nid_map));
end;

end.
