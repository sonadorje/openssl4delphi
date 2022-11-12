unit OpenSSL3.crypto.x509.x509_cmp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_x509_add_cert_new( p_sk : PPSTACK_st_X509; cert : PX509; flags : integer):integer;
function X509_add_cert( sk : PSTACK_st_X509; cert : PX509; flags : integer):integer;
function X509_add_certs( sk, certs : PSTACK_st_X509; flags : integer):integer;
function ossl_x509_add_certs_new( p_sk : PPSTACK_st_X509; certs : PSTACK_st_X509; flags : integer):integer;
 function X509_NAME_cmp( a, b : PX509_NAME):integer;
function X509_get_subject_name(const a : PX509):PX509_NAME;
function X509_get_issuer_name(const a : PX509):PX509_NAME;
function X509_get0_serialNumber(const a : PX509): PASN1_INTEGER;
 function X509_get0_pubkey(const x : PX509):PEVP_PKEY;
function X509_check_private_key(const x : PX509; k : PEVP_PKEY):integer;
function X509_cmp(const a, b : PX509):integer;
function X509_chain_check_suiteb( perror_depth : PInteger; x : PX509; chain : Pstack_st_X509; flags : Cardinal):integer;
function X509_CRL_check_suiteb( crl : PX509_CRL; pk : PEVP_PKEY; flags : Cardinal):integer;
function check_suite_b( pkey : PEVP_PKEY; sign_nid : integer; pflags : Pulong):integer;
 function X509_NAME_hash_ex(const x : PX509_NAME; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; ok : PInteger):Cardinal;

function X509_get_pubkey( x : PX509):PEVP_PKEY;

implementation
uses   openssl3.crypto.x509, OpenSSL3.Err, OpenSSL3.crypto.x509.x509_vfy,
       OpenSSL3.crypto.x509.x509_set, openssl3.crypto.x509.x_x509,
       OpenSSL3.crypto.x509.v3_purp,  openssl3.crypto.x509.x_pubkey,
       OpenSSL3.crypto.x509.x_name,   openssl3.crypto.evp.digest,
       openssl3.crypto.objects.obj_dat, openssl3.crypto.evp.p_lib;




function X509_get_pubkey( x : PX509):PEVP_PKEY;
begin
    if x = nil then Exit(nil);
    Result := X509_PUBKEY_get(x.cert_info.key);
end;




function X509_NAME_hash_ex(const x : PX509_NAME; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; ok : PInteger):Cardinal;
var
  ret : Cardinal;
  md : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
  sha1 : PEVP_MD;
begin
    ret := 0;
    sha1 := EVP_MD_fetch(libctx, 'SHA1', propq);
    { Make sure X509_NAME structure contains valid cached encoding }

    i2d_X509_NAME(x, nil);
    if ok <> nil then ok^ := 0;
    if (sha1 <> nil)
         and  (EVP_Digest(x.canon_enc, x.canon_enclen, @md, nil, sha1, nil) > 0 ) then
    begin
        ret := ( (ulong(md[0])) or (ulong(md[1]) shl 8) or
                 (ulong(md[2]) shl 16) or (ulong(md[3]) shl 24)
               ) and $ffffffff;
        if ok <> nil then ok^ := 1;
    end;
    EVP_MD_free(sha1);
    Result := ret;
end;



function check_suite_b( pkey : PEVP_PKEY; sign_nid : integer; pflags : Pulong):integer;
var
    curve_name     : array[0..79] of UTF8Char;
    curve_name_len : size_t;
    curve_nid      : integer;
begin
    if (pkey = nil)  or  (not EVP_PKEY_is_a(pkey, 'EC')) then
        Exit(X509_V_ERR_SUITE_B_INVALID_ALGORITHM);
    if 0>=EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name),
                                 @curve_name_len)  then
        Exit(X509_V_ERR_SUITE_B_INVALID_CURVE);
    curve_nid := OBJ_txt2nid(curve_name);
    { Check curve is consistent with LOS }
    if curve_nid = NID_secp384r1 then begin  { P-384 }
        {
         * Check signature algorithm is consistent with curve.
         }
        if (sign_nid <> -1)  and  (sign_nid <> NID_ecdsa_with_SHA384) then
            Exit(X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM);
        if 0>=( pflags^ and X509_V_FLAG_SUITEB_192_LOS) then
            Exit(X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED);
        { If we encounter P-384 we cannot use P-256 later }
        pflags^ := pflags^ and  not X509_V_FLAG_SUITEB_128_LOS_ONLY;
    end
    else
    if (curve_nid = NID_X9_62_prime256v1) then begin  { P-256 }
        if (sign_nid <> -1)  and  (sign_nid <> NID_ecdsa_with_SHA256) then
           Exit(X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM);
        if 0>=( pflags^ and X509_V_FLAG_SUITEB_128_LOS_ONLY ) then
            Exit(X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED);
    end
    else begin
        Exit(X509_V_ERR_SUITE_B_INVALID_CURVE);
    end;
    Result := X509_V_OK;
end;





function X509_CRL_check_suiteb( crl : PX509_CRL; pk : PEVP_PKEY; flags : Cardinal):integer;
var
  sign_nid : integer;
begin
    if 0>=(flags and X509_V_FLAG_SUITEB_128_LOS) then
        Exit(X509_V_OK);
    sign_nid := OBJ_obj2nid(crl.crl.sig_alg.algorithm);
    Result := check_suite_b(pk, sign_nid, @flags);
end;



function X509_chain_check_suiteb( perror_depth : PInteger; x : PX509; chain : Pstack_st_X509; flags : Cardinal):integer;
var
    rv, i,
    sign_nid : integer;
    pk       : PEVP_PKEY;
    tflags   : Cardinal;
    label _end;
begin
    tflags := flags;
    if 0>=(flags and X509_V_FLAG_SUITEB_128_LOS ) then
        Exit(X509_V_OK);
    { If no EE certificate passed in must be first in chain }
    if x = nil then
    begin
        x := sk_X509_value(chain, 0);
        i := 1;
    end
    else begin
        i := 0;
    end;
    pk := X509_get0_pubkey(x);
    {
     * With DANE-EE(3) success, or DANE-EE(3)/PKIX-EE(1) failure we don't build
     * a chain all, just report trust success or failure, but must also report
     * Suite-B errors if applicable.  This is indicated via a nil chain
     * pointer.  All we need to do is check the leaf key algorithm.
     }
    if chain = nil then Exit(check_suite_b(pk, -1, @tflags));
    if X509_get_version(x) <> X509_VERSION_3  then  begin
        rv := X509_V_ERR_SUITE_B_INVALID_VERSION;
        { Correct error depth }
        i := 0;
        goto _end;
    end;
    { Check EE key only }
    rv := check_suite_b(pk, -1, @tflags);
    if rv <> X509_V_OK then
    begin
        { Correct error depth }
        i := 0;
        goto _end;
    end;
    while i < sk_X509_num(chain) do
    begin
        sign_nid := X509_get_signature_nid(x);
        x := sk_X509_value(chain, i);
        if X509_get_version(x) <> X509_VERSION_3  then  begin
            rv := X509_V_ERR_SUITE_B_INVALID_VERSION;
            goto _end;
        end;
        pk := X509_get0_pubkey(x);
        rv := check_suite_b(pk, sign_nid, @tflags);
        if rv <> X509_V_OK then goto _end;
        inc(i);
    end;
    { Final check: root CA signature }
    rv := check_suite_b(pk, X509_get_signature_nid(x), @tflags);
 _end:
    if rv <> X509_V_OK then
    begin
        { Invalid signature or LOS errors are for previous cert }
        if ( (rv = X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM)    or
             (rv = X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED) )  and  (i > 0) then
            Dec(i);
        {
         * If we have LOS error and flags changed then we are signing P-384
         * with P-256. Use more meaningful error.
         }
        if (rv = X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED)  and  (flags <> tflags) then
           rv := X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256;
        if perror_depth <> nil then perror_depth^ := i;
    end;
    Result := rv;
end;

function X509_cmp(const a, b : PX509):integer;
var
  rv : integer;
begin
    rv := 0;
    if a = b then { for efficiency }
        Exit(0);
    { attempt to compute cert hash }
    X509_check_purpose(PX509(a), -1, 0);
    X509_check_purpose(PX509(b), -1, 0);
    if (a.ex_flags and EXFLAG_NO_FINGERPRINT  = 0)
             and  (b.ex_flags and EXFLAG_NO_FINGERPRINT = 0) then
        rv := memcmp(@a.sha1_hash, @b.sha1_hash, SHA_DIGEST_LENGTH);
    if rv <> 0 then Exit(get_result(rv < 0 , -1 , 1));
    { Check for match against stored encoding too }
    if (0>=a.cert_info.enc.modified)  and  (0>=b.cert_info.enc.modified) then
    begin
        if a.cert_info.enc.len < b.cert_info.enc.len then
            Exit(-1);
        if a.cert_info.enc.len > b.cert_info.enc.len then Exit(1);
        rv := memcmp(a.cert_info.enc.enc,
                    b.cert_info.enc.enc, a.cert_info.enc.len);
    end;
    Result := get_result(rv < 0 , -1 , int(rv > 0));
end;



function X509_check_private_key(const x : PX509; k : PEVP_PKEY):integer;
var
  xk : PEVP_PKEY;
  ret : integer;
begin
    xk := X509_get0_pubkey(x);
    if xk = nil then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY);
        Exit(0);
    end;
    ret := EVP_PKEY_eq(xk, k);
    case ret of
    0:
        ERR_raise(ERR_LIB_X509, X509_R_KEY_VALUES_MISMATCH);
        //break;
    -1:
        ERR_raise(ERR_LIB_X509, X509_R_KEY_TYPE_MISMATCH);
        //break;
    -2:
        ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_KEY_TYPE);
        //break;
    end;
    Result := Int(ret > 0);
end;

function X509_get0_pubkey(const x : PX509):PEVP_PKEY;
begin
    if x = nil then Exit(nil);
    Result := X509_PUBKEY_get0(x.cert_info.key);
end;



function X509_get0_serialNumber(const a : PX509): PASN1_INTEGER;
begin
    Result := @a.cert_info.serialNumber;
end;




function X509_get_issuer_name(const a : PX509):PX509_NAME;
begin
    Result := a.cert_info.issuer;
end;



function X509_get_subject_name(const a : PX509):PX509_NAME;
begin
    Result := a.cert_info.subject;
end;

function X509_NAME_cmp( a, b : PX509_NAME):integer;
var
  ret : integer;
begin
    if b = nil then Exit(int(a <> nil));
    if a = nil then Exit(-1);
    { Ensure canonical encoding is present and up to date }

    if (a.canon_enc = nil)  or  (a.modified > 0) then begin
        ret := i2d_X509_NAME(PX509_NAME(a), nil);
        if ret < 0 then Exit(-2);
    end;

    if (b.canon_enc = nil)  or  (b.modified > 0) then begin
        ret := i2d_X509_NAME(PX509_NAME(b), nil);
        if ret < 0 then Exit(-2);
    end;
    ret := a.canon_enclen - b.canon_enclen;
    if (ret = 0)  and  (a.canon_enclen = 0) then Exit(0);
    if (a.canon_enc = nil)  or  (b.canon_enc = nil) then
       Exit(-2);
    if ret = 0 then
       ret := memcmp(a.canon_enc, b.canon_enc, a.canon_enclen);
    Result := get_result(ret < 0 , -1 , Int(ret > 0));
end;

function ossl_x509_add_certs_new( p_sk : PPSTACK_st_X509; certs : PSTACK_st_X509; flags : integer):integer;
var
  n, i, j : integer;
begin
{ compiler would allow 'const' for the certs, yet they may get up-ref'ed }
    n := sk_X509_num(certs); { may be nil }

    for i := 0 to n-1 do
     begin
        j := get_result( (flags and X509_ADD_FLAG_PREPEND) = 0 , i , n - 1 - i);
        { if prepend, add certs in reverse order to keep original order }
        if  0>= ossl_x509_add_cert_new(p_sk, sk_X509_value(certs, j) , flags) then
            Exit(0);
    end;
    Result := 1;
end;

function X509_add_certs( sk, certs : PSTACK_st_X509; flags : integer):integer;
begin
{ compiler would allow 'const' for the certs, yet they may get up-ref'ed }
    if sk = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := ossl_x509_add_certs_new(&sk, certs, flags);
end;

function X509_add_cert( sk : PSTACK_st_X509; cert : PX509; flags : integer):integer;
var
  i, ret : integer;
begin
    if sk = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (flags and X509_ADD_FLAG_NO_DUP)  <> 0 then
    begin
        (*
         * not using sk_X509_set_cmp_func() and sk_X509_find()
         * because this re-orders the certs on the stack
         *)
        for i := 0 to sk_X509_num(sk)-1 do begin
            if X509_cmp(sk_X509_value(sk, i), cert) = 0 then
                Exit(1);
        end;
    end;
    if (flags and X509_ADD_FLAG_NO_SS) <> 0 then
    begin
        ret := X509_self_signed(cert, 0);
        if ret <> 0 then
        begin
           if ret > 0 then
              Exit( 1)
           else
              Exit(0);
        end;
    end;
    if  0>= sk_X509_insert(sk, cert, get_result( (flags and X509_ADD_FLAG_PREPEND )  <> 0 , 0 , -1)) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if (flags and X509_ADD_FLAG_UP_REF ) <> 0 then
        X509_up_ref(cert);
    Result := 1;
end;

function ossl_x509_add_cert_new( p_sk : PPSTACK_st_X509; cert : PX509; flags : integer):integer;
begin
    if (p_sk^ = nil) then
    begin
      p_sk^ := sk_X509_new_null();
      if p_sk^  = nil then
      begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(0);
      end;
    end;
    Result := X509_add_cert( p_sk^, cert, flags);
end;


end.
