unit openssl3.crypto.x509.x_x509;

interface
uses OpenSSL.Api;

  function x509_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
  function ossl_x509_set0_libctx(x : PX509; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function X509_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509;
  function X509_set_ex_data( r : PX509; idx : integer; arg : Pointer):integer;
  function X509_get_ex_data(const r : PX509; idx : integer):Pointer;
  function d2i_X509_AUX(a : PPX509;const pp : PPByte; length : long):PX509;
  function i2d_x509_aux_internal(const a : PX509; pp : PPByte):integer;
  function i2d_X509_AUX(const a : PX509; pp : PPByte):integer;
  function i2d_re_X509_tbs( x : PX509; pp : PPByte):integer;
  procedure X509_get0_signature(const psig : PPASN1_BIT_STRING; palg : PPX509_ALGOR; x : PX509);
  function X509_get_signature_nid(const x : PX509):integer;
  procedure X509_set0_distinguishing_id( x : PX509; d_id : PASN1_OCTET_STRING);
  function X509_get0_distinguishing_id( x : PX509):PASN1_OCTET_STRING;
   procedure X509_free( a : PX509);
  function X509_it:PASN1_ITEM;
   function d2i_X509(a : PPX509;const &in : PPByte; len : long):PX509;
  function i2d_X509(const a : PX509; &out : PPByte):integer;
  function X509_new:PX509;
  function X509_CINF_it:PASN1_ITEM;
  function d2i_X509_CINF(a : PPX509_CINF;const &in : PPByte; len : long):PX509_CINF;
  function i2d_X509_CINF(const a : PX509_CINF; &out : PPByte):integer;
  function X509_CINF_new:PX509_CINF;
  procedure X509_CINF_free( a : PX509_CINF);

var
   X509_seq_tt: array[0..2] of TASN1_TEMPLATE;
   X509_CINF_seq_tt: array of TASN1_TEMPLATE;
   X509_aux, X509_CINF_aux: TASN1_AUX;

implementation

uses openssl3.crypto.ex_data, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.x509v3, OpenSSL3.crypto.x509.v3_crld,
     OpenSSL3.crypto.x509.v3_asid,  openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_ncons, OpenSSL3.crypto.x509.v3_addr,
     openssl3.crypto.x509.pcy_cache, openssl3.crypto.x509.v3_genn,
     openssl3.crypto.x509.x_x509a, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.x509.x_val,  openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.asn1.x_algor, OpenSSL3.crypto.x509.x_name,
     OpenSSL3.crypto.x509.x_exten,
     openssl3.crypto.o_str,  OpenSSL3.Err, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.tasn_enc,  openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.x509.v3_akeya, openssl3.crypto.asn1.tasn_dec;






function d2i_X509_CINF(a : PPX509_CINF;const &in : PPByte; len : long):PX509_CINF;
begin
 Result := PX509_CINF(ASN1_item_d2i(PPASN1_VALUE(a), &in, len, X509_CINF_it));
end;


function i2d_X509_CINF(const a : PX509_CINF; &out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE (a), &out, X509_CINF_it);
end;


function X509_CINF_new:PX509_CINF;
begin
 Result := PX509_CINF (ASN1_item_new(X509_CINF_it));
end;


procedure X509_CINF_free( a : PX509_CINF);
begin
 ASN1_item_free(PASN1_VALUE(a), X509_CINF_it);
end;




function X509_CINF_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @X509_CINF_seq_tt,
               sizeof(X509_CINF_seq_tt) div sizeof(TASN1_TEMPLATE),
         @X509_CINF_aux, sizeof(TX509_CINF), 'X509_CINF');
    Result := @local_it;
end;


function d2i_X509(a : PPX509;const &in : PPByte; len : long):PX509;
begin
 Result := PX509(ASN1_item_d2i(PPASN1_VALUE(a), &in, len, X509_it));
end;


function i2d_X509(const a : PX509; &out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), &out, X509_it);
end;


function X509_new:PX509;
begin
 Result := PX509(ASN1_item_new(X509_it));
end;


function X509_it:PASN1_ITEM;
const
  local_it : TASN1_ITEM = (
         itype: $1;
         utype:  16;
         templates: @X509_seq_tt;
         tcount: sizeof(X509_seq_tt) div sizeof(TASN1_TEMPLATE);
         funcs: @X509_aux;
         size:  sizeof(TX509);
         sname:  'X509'
         );
begin
 result := @local_it;
end;




procedure X509_free( a : PX509);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_it);
end;


function x509_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  ret, old : PX509;

  libctx : PPOSSL_LIB_CTX;

  propq : PPUTF8Char;
begin
    ret := PX509(pval^);
    case operation of
        ASN1_OP_D2I_PRE,
        ASN1_OP_NEW_POST:
        begin
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, @ret.ex_data);
            X509_CERT_AUX_free(ret.aux);
            ASN1_OCTET_STRING_free(ret.skid);
            AUTHORITY_KEYID_free(ret.akid);
            CRL_DIST_POINTS_free(ret.crldp);
            ossl_policy_cache_free(ret.policy_cache);
            GENERAL_NAMES_free(ret.altname);
            NAME_CONSTRAINTS_free(ret.nc);
    {$IFNDEF OPENSSL_NO_RFC3779}
            sk_IPAddressFamily_pop_free(ret.rfc3779_addr, IPAddressFamily_free);
            ASIdentifiers_free(ret.rfc3779_asid);
    {$ENDIF}
            ASN1_OCTET_STRING_free(ret.distinguishing_id);
            { fall thru }
        //ASN1_OP_NEW_POST:
            ret.ex_cached := 0;
            ret.ex_kusage := 0;
            ret.ex_xkusage := 0;
            ret.ex_nscert := 0;
            ret.ex_flags := 0;
            ret.ex_pathlen := -1;
            ret.ex_pcpathlen := -1;
            ret.skid := nil;
            ret.akid := nil;
            ret.policy_cache := nil;
            ret.altname := nil;
            ret.nc := nil;
    {$IFNDEF OPENSSL_NO_RFC3779}
            ret.rfc3779_addr := nil;
            ret.rfc3779_asid := nil;
    {$ENDIF}
            ret.distinguishing_id := nil;
            ret.aux := nil;
            ret.crldp := nil;
            if 0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, @ret.ex_data) then
                Exit(0);
        end;
        ASN1_OP_FREE_POST:
        begin
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, @ret.ex_data);
            X509_CERT_AUX_free(ret.aux);
            ASN1_OCTET_STRING_free(ret.skid);
            AUTHORITY_KEYID_free(ret.akid);
            CRL_DIST_POINTS_free(ret.crldp);
            ossl_policy_cache_free(ret.policy_cache);
            GENERAL_NAMES_free(ret.altname);
            NAME_CONSTRAINTS_free(ret.nc);
    {$IFNDEF OPENSSL_NO_RFC3779}
            sk_IPAddressFamily_pop_free(ret.rfc3779_addr, IPAddressFamily_free);
            ASIdentifiers_free(ret.rfc3779_asid);
    {$ENDIF}
            ASN1_OCTET_STRING_free(ret.distinguishing_id);
            OPENSSL_free(ret.propq);
        end;
        ASN1_OP_DUP_POST:
            begin
                old := exarg;
                if 0>= ossl_x509_set0_libctx(ret, old.libctx, old.propq) then
                    Exit(0);
            end;
            //break;
        ASN1_OP_GET0_LIBCTX:
            begin
                libctx := exarg;
                libctx^ := ret.libctx;
            end;
            //break;
        ASN1_OP_GET0_PROPQ:
            begin
                propq := exarg;
                propq^ := ret.propq;
            end;
            //break;
        else
        begin
           //
        end;
    end;
    Result := 1;
end;


function ossl_x509_set0_libctx(x : PX509; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    if x <> nil then begin
        x.libctx := libctx;
        OPENSSL_free(x.propq);
        x.propq := nil;
        if propq <> nil then begin
            OPENSSL_strdup(x.propq ,propq);
            if x.propq = nil then Exit(0);
        end;
    end;
    Result := 1;
end;


function X509_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509;
var
  cert : PX509;
begin
    cert := nil;
    cert := PX509( ASN1_item_new_ex(X509_it, libctx, propq));
    if 0>= ossl_x509_set0_libctx(cert, libctx, propq) then  begin
        X509_free(cert);
        cert := nil;
    end;
    Result := cert;
end;


function X509_set_ex_data( r : PX509; idx : integer; arg : Pointer):integer;
begin
    Result := CRYPTO_set_ex_data(@r.ex_data, idx, arg);
end;


function X509_get_ex_data(const r : PX509; idx : integer):Pointer;
begin
    Result := CRYPTO_get_ex_data(@r.ex_data, idx);
end;


function d2i_X509_AUX(a : PPX509;const pp : PPByte; length : long):PX509;
var
  q : PByte;
  ret : PX509;
  freeret : integer;
  label _err;
begin
    freeret := 0;
    { Save start position }
    q := pp^;
    if (a = nil)  or  (a^ = nil) then
       freeret := 1;
    ret := d2i_X509(a, @q, length);
    { If certificate unreadable then forget it }
    if ret = nil then Exit(nil);
    { update length }
    length  := length - (q - pp^);
    if (length > 0)  and  (nil = d2i_X509_CERT_AUX(@ret.aux, @q, length)) then
        goto _err ;
    pp^ := q;
    Exit(ret);
 _err:
    if freeret > 0 then begin
        X509_free(ret);
        if a <> nil then a^ := nil;
    end;
    Result := nil;
end;


function i2d_x509_aux_internal(const a : PX509; pp : PPByte):integer;
var
  length, tmplen : integer;

  start : PByte;
begin
    start := get_result(pp <> nil , pp^ , nil);
    {
     * This might perturb *pp on error, but fixing that belongs in i2d_X509()
     * not here.  It should be that if a = nil length is zero, but we check
     * both just in case.
     }
    length := i2d_X509(a, pp);
    if (length <= 0)  or  (a = nil) then Exit(length);
    tmplen := i2d_X509_CERT_AUX(a.aux, pp);
    if tmplen < 0 then begin
        if start <> nil then
           pp^ := start;
        Exit(tmplen);
    end;
    length  := length + tmplen;
    Result := length;
end;


function i2d_X509_AUX(const a : PX509; pp : PPByte):integer;
var
  length : integer;

  tmp : PByte;
begin
    { Buffer provided by caller }
    if (pp = nil)  or  (pp^ <> nil) then
       Exit(i2d_x509_aux_internal(a, pp));
    { Obtain the combined length }
    length := i2d_x509_aux_internal(a, nil );
    if length  <= 0 then
        Exit(length);
    { Allocate requisite combined storage }
    tmp := OPENSSL_malloc(length);
    pp^ := tmp;
    if tmp = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    { Encode, but keep *pp at the originally malloced pointer }
    length := i2d_x509_aux_internal(a, @tmp);
    if length <= 0 then begin
        OPENSSL_free( pp^);
        pp^ := nil;
    end;
    Result := length;
end;


function i2d_re_X509_tbs( x : PX509; pp : PPByte):integer;
begin
    x.cert_info.enc.modified := 1;
    Result := i2d_X509_CINF(@x.cert_info, pp);
end;


procedure X509_get0_signature(const psig : PPASN1_BIT_STRING; palg : PPX509_ALGOR; x : PX509);
begin
    if psig <> nil then psig^ := @x.signature;
    if palg <> nil then palg^ := @x.sig_alg;
end;


function X509_get_signature_nid(const x : PX509):integer;
begin
    Result := OBJ_obj2nid(x.sig_alg.algorithm);
end;


procedure X509_set0_distinguishing_id( x : PX509; d_id : PASN1_OCTET_STRING);
begin
    ASN1_OCTET_STRING_free(x.distinguishing_id);
    x.distinguishing_id := d_id;
end;


function X509_get0_distinguishing_id( x : PX509):PASN1_OCTET_STRING;
begin
    Result := x.distinguishing_id;
end;

initialization

     X509_seq_tt[0] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX509(0).cert_info), 'cert_info', X509_CINF_it );
     X509_seq_tt[1] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX509(0).sig_alg), 'sig_alg', X509_ALGOR_it );
     X509_seq_tt[2] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX509(0).signature), 'signature', ASN1_BIT_STRING_it );

     X509_aux := get_ASN1_AUX(
      nil,
      1,
      size_t(@PX509(0).references),
      size_t(@PX509(0).lock),
      x509_cb,
       0,
       nil
     );

      X509_CINF_seq_tt := [
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6))  or  (($1))), 0, size_t(@PX509_CINF(0).version), 'version', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CINF(0).serialNumber), 'serialNumber', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CINF(0).signature), 'signature', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_CINF(0).issuer), 'issuer', X509_NAME_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CINF(0).validity), 'validity', X509_VAL_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_CINF(0).subject), 'subject', X509_NAME_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_CINF(0).key), 'key', X509_PUBKEY_it) ,
        get_ASN1_TEMPLATE( ((($1 shl 3) or ($2 shl 6))  or  (($1))), (1), size_t(@PX509_CINF(0).issuerUID), 'issuerUID', ASN1_BIT_STRING_it) ,
        get_ASN1_TEMPLATE( ((($1 shl 3) or ($2 shl 6))  or  (($1))), (2), size_t(@PX509_CINF(0).subjectUID), 'subjectUID', ASN1_BIT_STRING_it) ,
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6))  or  (($2 shl 1) or ($1))), (3), size_t(@PX509_CINF(0).extensions), 'extensions', X509_EXTENSION_it)
    ] ;

    X509_CINF_aux := get_ASN1_AUX(Pointer(0) , 2, 0, 0, nil, size_t(@PX509_CINF(0).enc), Pointer(0) );

end.
