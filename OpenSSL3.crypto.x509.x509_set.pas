unit OpenSSL3.crypto.x509.x509_set;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_x509_init_sig_info( x : PX509):integer;
function X509_get_version(const x : PX509):long;
function ossl_x509_set1_time(ptm : PPASN1_TIME;const tm : PASN1_TIME):integer;
function X509_get_X509_PUBKEY(const x : PX509):PX509_PUBKEY;
function X509_up_ref( x : PX509):integer;
function X509_get0_notAfter(const x : PX509):PASN1_TIME;
function X509_get0_extensions(const x : PX509):Pstack_st_X509_EXTENSION;
function X509_get0_notBefore(const x : PX509):PASN1_TIME;
 function X509_get_signature_info( x : PX509; mdnid, pknid, secbits : PInteger; flags : Puint32_t):integer;
function X509_SIG_INFO_get(const siginf : PX509_SIG_INFO; mdnid, pknid, secbits : PInteger; flags : Puint32_t):integer;
procedure X509_SIG_INFO_set( siginf : PX509_SIG_INFO; mdnid, pknid, secbits : integer; flags : uint32);


implementation
uses  OpenSSL3.Err, openssl3.crypto.evp.names, openssl3.crypto.evp.evp_lib,
      openssl3.crypto.objects.obj_xref, openssl3.crypto.objects.obj_dat,
      openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.a_time,
      openssl3.crypto.asn1.ameth_lib, openssl3.crypto.asn1.a_int,
      OpenSSL3.crypto.x509.v3_purp,
      openssl3.include.internal.refcount;





procedure X509_SIG_INFO_set( siginf : PX509_SIG_INFO; mdnid, pknid, secbits : integer; flags : uint32);
begin
    siginf.mdnid := mdnid;
    siginf.pknid := pknid;
    siginf.secbits := secbits;
    siginf.flags := flags;
end;




function X509_SIG_INFO_get(const siginf : PX509_SIG_INFO; mdnid, pknid, secbits : PInteger; flags : Puint32_t):integer;
begin
    if mdnid <> nil then mdnid^ := siginf.mdnid;
    if pknid <> nil then pknid^ := siginf.pknid;
    if secbits <> nil then secbits^ := siginf.secbits;
    if flags <> nil then flags^ := siginf.flags;
    Result := Int(siginf.flags and X509_SIG_INFO_VALID <> 0);
end;

function X509_get_signature_info( x : PX509; mdnid, pknid, secbits : PInteger; flags : Puint32_t):integer;
begin
    X509_check_purpose(x, -1, -1);
    Result := X509_SIG_INFO_get(@x.siginf, mdnid, pknid, secbits, flags);
end;


function X509_get0_notBefore(const x : PX509):PASN1_TIME;
begin
    Result := x.cert_info.validity.notBefore;
end;




function X509_get0_extensions(const x : PX509):Pstack_st_X509_EXTENSION;
begin
    Result := x.cert_info.extensions;
end;




function X509_get0_notAfter(const x : PX509):PASN1_TIME;
begin
    Result := x.cert_info.validity.notAfter;
end;




function X509_up_ref( x : PX509):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(x.references, i, x.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('X509', x);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result(i > 1 , 1 , 0);
end;



function X509_get_X509_PUBKEY(const x : PX509):PX509_PUBKEY;
begin
    Result := x.cert_info.key;
end;




function ossl_x509_set1_time(ptm : PPASN1_TIME;const tm : PASN1_TIME):integer;
var
  _in : PASN1_TIME;
begin
    _in := ptm^;
    if _in <> tm then
    begin
        _in := ASN1_STRING_dup(tm);
        if _in <> nil then
        begin
            ASN1_TIME_free(ptm^);
            ptm^ := _in;
        end;
    end;
    Result := Int( _in <> nil);
end;




function X509_get_version(const x : PX509):long;
begin
    Result := ASN1_INTEGER_get(x.cert_info.version);
end;

function x509_sig_info_init(siginf : PX509_SIG_INFO;const alg : PX509_ALGOR; sig : PASN1_STRING):integer;
var
  pknid, mdnid : integer;
  md : PEVP_MD;
  ameth : PEVP_PKEY_ASN1_METHOD;
begin
    siginf.mdnid := NID_undef;
    siginf.pknid := NID_undef;
    siginf.secbits := -1;
    siginf.flags := 0;
    if  (0>= OBJ_find_sigid_algs(OBJ_obj2nid(alg.algorithm ), @mdnid, @pknid)) or
        ( pknid = NID_undef) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_SIGID_ALGS);
        Exit(0);
    end;
    siginf.mdnid := mdnid;
    siginf.pknid := pknid;
    case mdnid of
        NID_undef:
        begin
            { If we have one, use a custom handler for this algorithm }
            ameth := EVP_PKEY_asn1_find(nil, pknid);
            if (ameth = nil)  or  ( not Assigned(ameth.siginf_set))      or
               (0>= ameth.siginf_set(siginf, alg, sig) )  then
            begin
                ERR_raise(ERR_LIB_X509, X509_R_ERROR_USING_SIGINF_SET);
                Exit(0);
            end;
        end;
            {
             * SHA1 and MD5 are known to be broken. Reduce security bits so that
             * they're no longer accepted at security level 1.
             * The real values don't really matter as long as they're lower than 80,
             * which is our security level 1.
             }
        NID_sha1:
            {
             * https://eprint.iacr.org/2020/014 puts a chosen-prefix attack
             * for SHA1 at2^63.4
             }
            siginf.secbits := 63;

        NID_md5:
            {
             * https://documents.epfl.ch/users/l/le/lenstra/public/papers/lat.pdf
             * puts a chosen-prefix attack for MD5 at 2^39.
             }
            siginf.secbits := 39;

        NID_id_GostR3411_94:
            {
             * There is a collision attack on GOST R 34.11-94 at 2^105, see
             * https://link.springer.com/chapter/10.1007%2F978-3-540-85174-5_10
             }
            siginf.secbits := 105;

        else
        begin
            { Security bits: half number of bits in digest }
            md := EVP_get_digestbynid(mdnid);
            if md = nil then
            begin
                ERR_raise(ERR_LIB_X509, X509_R_ERROR_GETTING_MD_BY_NID);
                Exit(0);
            end;
            siginf.secbits := EVP_MD_get_size(md) * 4;
        end;
    end;

    case mdnid of
      NID_sha1,
      NID_sha256,
      NID_sha384,
      NID_sha512:
          siginf.flags  := siginf.flags  or X509_SIG_INFO_TLS;
    end;
    siginf.flags  := siginf.flags  or X509_SIG_INFO_VALID;
    Result := 1;
end;

function ossl_x509_init_sig_info( x : PX509):integer;
begin
    Result := x509_sig_info_init(@x.siginf, @x.sig_alg, @x.signature);
end;

end.
