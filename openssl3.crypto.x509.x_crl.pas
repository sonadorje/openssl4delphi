unit openssl3.crypto.x509.x_crl;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function X509_CRL_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_CRL;
function ossl_x509_crl_set0_libctx(x : PX509_CRL; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function X509_CRL_it:PASN1_ITEM;
function d2i_X509_CRL(a : PPX509_CRL;const _in : PPByte; len : long):PX509_CRL;
  function i2d_X509_CRL(const a : PX509_CRL; _out : PPByte):integer;
  function X509_CRL_new:PX509_CRL;
  procedure X509_CRL_free( a : PX509_CRL);
  function X509_CRL_INFO_it:PASN1_ITEM;
  function crl_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
  function def_crl_lookup(crl : PX509_CRL; ret : PPX509_REVOKED;const serial : PASN1_INTEGER; const issuer : PX509_NAME):integer;
  function def_crl_verify( crl : PX509_CRL; r:PEVP_PKEY):integer;
  function crl_revoked_issuer_match(crl : PX509_CRL;{const} nm : PX509_NAME; rev : PX509_REVOKED):integer;
  function setup_idp( crl : PX509_CRL; idp : PISSUING_DIST_POINT):integer;

  function d2i_X509_CRL_INFO(a : PPX509_CRL_INFO;const _in : PPByte; len : long):PX509_CRL_INFO;
  function i2d_X509_CRL_INFO(const a : PX509_CRL_INFO; _out : PPByte):integer;
  function X509_CRL_INFO_new:PX509_CRL_INFO;
  procedure X509_CRL_INFO_free( a : PX509_CRL_INFO);
   function crl_set_issuers( crl : PX509_CRL):integer;
  function crl_inf_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
 function X509_REVOKED_cmp(const a, b : PPX509_REVOKED):integer;
 function X509_REVOKED_it:PASN1_ITEM;
 function X509_CRL_verify( crl : PX509_CRL; r : PEVP_PKEY):integer;
 function X509_CRL_get0_by_cert( crl : PX509_CRL; ret : PPX509_REVOKED; x : PX509):integer;
 function X509_CRL_get0_by_serial(crl : PX509_CRL; ret : PPX509_REVOKED;const serial : PASN1_INTEGER):integer;
 function X509_REVOKED_dup(const x : PX509_REVOKED):PX509_REVOKED;
 function X509_CRL_add0_revoked( crl : PX509_CRL; rev : PX509_REVOKED):integer;
 function d2i_X509_REVOKED(a : PPX509_REVOKED;const _in : PPByte; len : long):PX509_REVOKED;
  function i2d_X509_REVOKED(const a : PX509_REVOKED; _out : PPByte):integer;
  function X509_REVOKED_new:PX509_REVOKED;
  procedure X509_REVOKED_free( a : PX509_REVOKED);


var
  int_crl_meth: TX509_CRL_METHOD  = (
    flags: 0;
    crl_init: nil; crl_free: nil;
    crl_lookup: def_crl_lookup;
    crl_verify: def_crl_verify
  );

  X509_CRL_seq_tt,  X509_CRL_INFO_seq_tt, X509_REVOKED_seq_tt : array of TASN1_TEMPLATE;
  X509_CRL_aux, X509_CRL_INFO_aux :TASN1_AUX;
  default_crl_method: PX509_CRL_METHOD  = @int_crl_meth;

implementation
uses openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.x509v3,
     OpenSSL3.crypto.x509.x509_cmp, OpenSSL3.crypto.x509.x509cset,
     openssl3.crypto.x509,   OpenSSL3.threads_none, openssl3.crypto.asn1.a_int,
     openssl3.crypto.x509.v3_genn,  openssl3.crypto.asn1.a_verify,
     openssl3.crypto.x509.x_all, openssl3.crypto.evp.legacy_sha,
     OpenSSL3.crypto.x509.x509_ext, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.x509.v3_akeya,  OpenSSL3.crypto.x509.v3_crld,
     openssl3.crypto.x509.x509_v3,   openssl3.crypto.asn1.asn1_lib,
     OpenSSL3.crypto.x509.x_name,  openssl3.crypto.asn1.a_time,
     OpenSSL3.crypto.x509.x_exten,  openssl3.crypto.asn1.a_dup,
     OpenSSL3.Err,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.x_algor;





function d2i_X509_REVOKED(a : PPX509_REVOKED;const _in : PPByte; len : long):PX509_REVOKED;
begin
 Result := PX509_REVOKED (ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_REVOKED_it));
end;


function i2d_X509_REVOKED(const a : PX509_REVOKED; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_REVOKED_it);
end;


function X509_REVOKED_new:PX509_REVOKED;
begin
 Result := PX509_REVOKED (ASN1_item_new(X509_REVOKED_it));
end;


procedure X509_REVOKED_free( a : PX509_REVOKED);
begin
 ASN1_item_free(PASN1_VALUE(a), X509_REVOKED_it);
end;

function X509_CRL_add0_revoked( crl : PX509_CRL; rev : PX509_REVOKED):integer;
var
  inf : PX509_CRL_INFO;
begin
    inf := @crl.crl;
    if inf.revoked = nil then
       inf.revoked := sk_X509_REVOKED_new(X509_REVOKED_cmp);
    if (inf.revoked = nil)  or  (0>=sk_X509_REVOKED_push(inf.revoked, rev )) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    inf.enc.modified := 1;
    Result := 1;
end;



function X509_REVOKED_dup(const x : PX509_REVOKED):PX509_REVOKED;
begin
   Result := ASN1_item_dup((X509_REVOKED_it), x);
end;


function X509_CRL_get0_by_serial(crl : PX509_CRL; ret : PPX509_REVOKED;const serial : PASN1_INTEGER):integer;
begin
    if Assigned(crl.meth.crl_lookup) then
       Exit(crl.meth.crl_lookup(crl, ret, serial, nil));
    Result := 0;
end;




function X509_CRL_get0_by_cert( crl : PX509_CRL; ret : PPX509_REVOKED; x : PX509):integer;
begin
    if Assigned(crl.meth.crl_lookup) then
       Exit(crl.meth.crl_lookup(crl, ret,
                                     X509_get0_serialNumber(x),
                                     X509_get_issuer_name(x)));
    Result := 0;
end;



function X509_CRL_verify( crl : PX509_CRL; r : PEVP_PKEY):integer;
begin
    if Assigned(crl.meth.crl_verify) then
       Exit(crl.meth.crl_verify(crl, r));
    Result := 0;
end;




function X509_REVOKED_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @X509_REVOKED_seq_tt,
                        sizeof(X509_REVOKED_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                        sizeof(TX509_REVOKED), 'X509_REVOKED');
    Result := @local_it;
end;





function X509_REVOKED_cmp(const a, b : PPX509_REVOKED):integer;
begin
    Result := ASN1_STRING_cmp(PASN1_STRING(@a^.serialNumber),
                              PASN1_STRING(@b^.serialNumber));
end;




function crl_inf_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  a : PX509_CRL_INFO;
begin
    a := PX509_CRL_INFO(pval^);
    if (nil =a)  or  (nil = a.revoked) then Exit(1);
    case operation of
        {
         * Just set cmp function here. We don't sort because that would
         * affect the output of X509_CRL_print.
         }
    ASN1_OP_D2I_POST:
        sk_X509_REVOKED_set_cmp_func(a.revoked, X509_REVOKED_cmp);
        //break;
    end;
    Result := 1;
end;




function crl_set_issuers( crl : PX509_CRL):integer;
var
  i, j : integer;
  gens, gtmp : PGENERAL_NAMES;
  revoked : Pstack_st_X509_REVOKED;
  rev : PX509_REVOKED;
  exts : Pstack_st_X509_EXTENSION;
  reason : PASN1_ENUMERATED;
  ext : PX509_EXTENSION;
begin
    revoked := X509_CRL_get_REVOKED(crl);
    gens := nil;
    for i := 0 to sk_X509_REVOKED_num(revoked)-1 do
    begin
        rev := sk_X509_REVOKED_value(revoked, i);
        gtmp := X509_REVOKED_get_ext_d2i(rev,
                                        NID_certificate_issuer, @j, nil);
        if (nil = gtmp)  and  (j <> -1) then
        begin
            crl.flags  := crl.flags  or EXFLAG_INVALID;
            Exit(1);
        end;
        if gtmp <> nil then
        begin
            gens := gtmp;
            if nil =crl.issuers then
            begin
                crl.issuers := sk_GENERAL_NAMES_new_null;
                if nil =crl.issuers then
                   Exit(0);
            end;
            if 0>=sk_GENERAL_NAMES_push(crl.issuers, gtmp ) then
                Exit(0);
        end;
        rev.issuer := gens;
        reason := X509_REVOKED_get_ext_d2i(rev, NID_crl_reason, @j, nil);
        if (nil = reason)  and  (j <> -1) then
        begin
            crl.flags  := crl.flags  or EXFLAG_INVALID;
            Exit(1);
        end;
        if reason <> nil then
        begin
            rev.reason := ASN1_ENUMERATED_get(reason);
            ASN1_ENUMERATED_free(reason);
        end
        else
            rev.reason := CRL_REASON_NONE;
        { Check for critical CRL entry extensions }
        exts := rev.extensions;
        for j := 0 to sk_X509_EXTENSION_num(exts)-1 do
        begin
            ext := sk_X509_EXTENSION_value(exts, j);
            if X509_EXTENSION_get_critical(ext) > 0 then
            begin
                if OBJ_obj2nid(X509_EXTENSION_get_object(ext)) = NID_certificate_issuer then
                    continue;
                crl.flags  := crl.flags  or EXFLAG_CRITICAL;
                break;
            end;
        end;
    end;
    Exit(1);
end;



function setup_idp( crl : PX509_CRL; idp : PISSUING_DIST_POINT):integer;
var
  idp_only : integer;
begin
    idp_only := 0;
    { Set various flags according to IDP }
    crl.idp_flags  := crl.idp_flags  or IDP_PRESENT;
    if idp.onlyuser > 0 then
    begin
        PostInc(idp_only);
        crl.idp_flags  := crl.idp_flags  or IDP_ONLYUSER;
    end;
    if idp.onlyCA > 0 then begin
        PostInc(idp_only);
        crl.idp_flags  := crl.idp_flags  or IDP_ONLYCA;
    end;
    if idp.onlyattr > 0 then begin
        PostInc(idp_only);
        crl.idp_flags  := crl.idp_flags  or IDP_ONLYATTR;
    end;
    if idp_only > 1 then crl.idp_flags  := crl.idp_flags  or IDP_INVALID;
    if idp.indirectCRL > 0 then crl.idp_flags  := crl.idp_flags  or IDP_INDIRECT;
    if idp.onlysomereasons <> nil then
    begin
        crl.idp_flags  := crl.idp_flags  or IDP_REASONS;
        if idp.onlysomereasons.length > 0 then
           crl.idp_reasons := idp.onlysomereasons.data[0];
        if idp.onlysomereasons.length > 1 then
           crl.idp_reasons  := crl.idp_reasons  or ((idp.onlysomereasons.data[1] shl 8));
        crl.idp_reasons := crl.idp_reasons and CRLDP_ALL_REASONS;
    end;
    Result := DIST_POINT_set_dpname(idp.distpoint, X509_CRL_get_issuer(crl));
end;




function d2i_X509_CRL_INFO(a : PPX509_CRL_INFO;const _in : PPByte; len : long):PX509_CRL_INFO;
begin
 Result := PX509_CRL_INFO(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_CRL_INFO_it));
end;


function i2d_X509_CRL_INFO(const a : PX509_CRL_INFO; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_CRL_INFO_it);
end;


function X509_CRL_INFO_new:PX509_CRL_INFO;
begin
 Result := PX509_CRL_INFO (ASN1_item_new(X509_CRL_INFO_it));
end;


procedure X509_CRL_INFO_free( a : PX509_CRL_INFO);
begin
 ASN1_item_free(PASN1_VALUE(a), X509_CRL_INFO_it);
end;



function crl_revoked_issuer_match(crl : PX509_CRL;{const} nm : PX509_NAME; rev : PX509_REVOKED):integer;
var
  i : integer;

  gen : PGENERAL_NAME;
begin
    if nil =rev.issuer then
    begin
        if nil =nm then
            Exit(1);
        if 0>=X509_NAME_cmp(nm, X509_CRL_get_issuer(crl)) then
            Exit(1);
        Exit(0);
    end;
    if nil = nm then
       nm := X509_CRL_get_issuer(crl);
    for i := 0 to sk_GENERAL_NAME_num(rev.issuer)-1 do
    begin
        gen := sk_GENERAL_NAME_value(rev.issuer, i);
        if gen.&type <> GEN_DIRNAME then
           continue;
        if 0>=X509_NAME_cmp(nm, gen.d.directoryName) then
            Exit(1);
    end;
    Exit(0);
end;



function def_crl_verify( crl : PX509_CRL; r: PEVP_PKEY):integer;
begin
    Exit(ASN1_item_verify_ex(X509_CRL_INFO_it,
                               @crl.sig_alg, @crl.signature, @crl.crl, nil,
                               r, crl.libctx, crl.propq));
end;




function def_crl_lookup(crl : PX509_CRL; ret : PPX509_REVOKED;const serial : PASN1_INTEGER; const issuer : PX509_NAME):integer;
var
  rtmp : TX509_REVOKED;

  rev : PX509_REVOKED;

  idx, num : integer;
begin
    if crl.crl.revoked = nil then Exit(0);
    {
     * Sort revoked into serial number order if not already sorted. Do this
     * under a lock to avoid race condition.
     }
    if 0>=sk_X509_REVOKED_is_sorted(crl.crl.revoked) then
    begin
        if 0>=CRYPTO_THREAD_write_lock(crl.lock) then
            Exit(0);
        sk_X509_REVOKED_sort(crl.crl.revoked);
        CRYPTO_THREAD_unlock(crl.lock);
    end;
    rtmp.serialNumber := serial^;
    idx := sk_X509_REVOKED_find(crl.crl.revoked, @rtmp);
    if idx < 0 then Exit(0);
    { Need to look for matching name }
    for num := sk_X509_REVOKED_num(crl.crl.revoked) to num-1 do
    begin
        rev := sk_X509_REVOKED_value(crl.crl.revoked, idx);
        if ASN1_INTEGER_cmp(@rev.serialNumber, serial) > 0 then
            Exit(0);
        if crl_revoked_issuer_match(crl, issuer, rev ) > 0 then
        begin
            if ret <> nil then
               ret^ := rev;
            if rev.reason = CRL_REASON_REMOVE_FROM_CRL then
               Exit(2);
            Exit(1);
        end;
    end;
    Result := 0;
end;



function crl_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  crl : PX509_CRL;
  exts : Pstack_st_X509_EXTENSION;
  ext : PX509_EXTENSION;
  idx, i, nid : integer;
  old : PX509_CRL;
  label _NEXT;
begin
    crl := PX509_CRL(pval^);
    case operation of
    ASN1_OP_D2I_PRE:
    begin
      if Assigned(crl.meth.crl_free) then
        begin
            if 0>=crl.meth.crl_free(crl) then
                Exit(0);
        end;
        AUTHORITY_KEYID_free(crl.akid);
        ISSUING_DIST_POINT_free(crl.idp);
        ASN1_INTEGER_free(crl.crl_number);
        ASN1_INTEGER_free(crl.base_crl_number);
        sk_GENERAL_NAMES_pop_free(crl.issuers, GENERAL_NAMES_free);
        { fall thru }
        goto _NEXT;
    end;

    ASN1_OP_NEW_POST:
    begin
_NEXT:
        crl.idp := nil;
        crl.akid := nil;
        crl.flags := 0;
        crl.idp_flags := 0;
        crl.idp_reasons := CRLDP_ALL_REASONS;
        crl.meth := default_crl_method;
        crl.meth_data := nil;
        crl.issuers := nil;
        crl.crl_number := nil;
        crl.base_crl_number := nil;
    end;
    ASN1_OP_D2I_POST:
    begin
        if 0>=X509_CRL_digest(crl, EVP_sha1, @crl.sha1_hash, nil) then
            crl.flags  := crl.flags  or EXFLAG_NO_FINGERPRINT;
        crl.idp := X509_CRL_get_ext_d2i(crl,
                                        NID_issuing_distribution_point, @i,
                                        nil);
        if crl.idp <> nil then
        begin
            if 0>=setup_idp(crl, crl.idp) then
                crl.flags  := crl.flags  or EXFLAG_INVALID;
        end
        else if (i <> -1) then
        begin
            crl.flags  := crl.flags  or EXFLAG_INVALID;
        end;
        crl.akid := X509_CRL_get_ext_d2i(crl,
                                         NID_authority_key_identifier, @i,
                                         nil);
        if (crl.akid = nil)  and  (i <> -1) then
            crl.flags  := crl.flags  or EXFLAG_INVALID;
        crl.crl_number := X509_CRL_get_ext_d2i(crl,
                                               NID_crl_number, @i, nil);
        if (crl.crl_number = nil)  and  (i <> -1) then
           crl.flags := crl.flags  or EXFLAG_INVALID;
        crl.base_crl_number := X509_CRL_get_ext_d2i(crl,
                                                    NID_delta_crl, @i,
                                                    nil);
        if (crl.base_crl_number = nil)  and  (i <> -1) then
           crl.flags  := crl.flags  or EXFLAG_INVALID;
        { Delta CRLs must have CRL number }
        if (crl.base_crl_number <> nil)  and  (nil =crl.crl_number) then
           crl.flags  := crl.flags  or EXFLAG_INVALID;
        {
         * See if we have any unhandled critical CRL extensions and indicate
         * this in a flag. We only currently handle IDP so anything else
         * critical sets the flag. This code accesses the X509_CRL structure
         * directly: applications shouldn't do this.
         }
        exts := crl.crl.extensions;
        for idx := 0 to sk_X509_EXTENSION_num(exts)-1 do
        begin
            ext := sk_X509_EXTENSION_value(exts, idx);
            nid := OBJ_obj2nid(X509_EXTENSION_get_object(ext));
            if nid = NID_freshest_crl then
               crl.flags  := crl.flags  or EXFLAG_FRESHEST;
            if X509_EXTENSION_get_critical(ext)>0 then
            begin
                { We handle IDP and deltas }
                if (nid = NID_issuing_distribution_point)
                     or  (nid = NID_authority_key_identifier)
                     or  (nid = NID_delta_crl)  then
                    continue;
                crl.flags  := crl.flags  or EXFLAG_CRITICAL;
                break;
            end;
        end;
        if 0>=crl_set_issuers(crl) then
            Exit(0);
        if Assigned(crl.meth.crl_init) then
        begin
            if crl.meth.crl_init(crl) = 0 then
                Exit(0);
        end;
        crl.flags  := crl.flags  or EXFLAG_SET;
    end;
    ASN1_OP_FREE_POST:
    begin
        if Assigned(crl.meth.crl_free) then
        begin
            if 0>=crl.meth.crl_free(crl) then
                Exit(0);
        end;
        AUTHORITY_KEYID_free(crl.akid);
        ISSUING_DIST_POINT_free(crl.idp);
        ASN1_INTEGER_free(crl.crl_number);
        ASN1_INTEGER_free(crl.base_crl_number);
        sk_GENERAL_NAMES_pop_free(crl.issuers, GENERAL_NAMES_free);
        OPENSSL_free(crl.propq);
    end;
    ASN1_OP_DUP_POST:
    begin
        old := exarg;
        if 0>=ossl_x509_crl_set0_libctx(crl, old.libctx, old.propq ) then
            Exit(0);
    end;

    end;
    Result := 1;
end;


function X509_CRL_INFO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @X509_CRL_INFO_seq_tt,
              sizeof(X509_CRL_INFO_seq_tt) div sizeof(TASN1_TEMPLATE), @X509_CRL_INFO_aux,
              sizeof(TX509_CRL_INFO), 'X509_CRL_INFO');
   Result := @local_it;
end;





function d2i_X509_CRL(a : PPX509_CRL;const _in : PPByte; len : long):PX509_CRL;
begin
 Result := PX509_CRL(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_CRL_it));
end;


function i2d_X509_CRL(const a : PX509_CRL; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_CRL_it);
end;


function X509_CRL_new:PX509_CRL;
begin
 Result := PX509_CRL (ASN1_item_new(X509_CRL_it));
end;


procedure X509_CRL_free( a : PX509_CRL);
begin
   ASN1_item_free(PASN1_VALUE(a), X509_CRL_it);
end;

function X509_CRL_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @X509_CRL_seq_tt,
                    sizeof(X509_CRL_seq_tt) div sizeof(TASN1_TEMPLATE), @X509_CRL_aux,
                    sizeof(TX509_CRL), 'X509_CRL');

    Result := @local_it;
end;

function ossl_x509_crl_set0_libctx(x : PX509_CRL; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    if x <> nil then
    begin
        x.libctx := libctx;
        OPENSSL_free(x.propq);
        x.propq := nil;
        if propq <> nil then
        begin
            OPENSSL_strdup(x.propq ,propq);
            if x.propq = nil then
               Exit(0);
        end;
    end;
    Result := 1;
end;


function X509_CRL_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_CRL;
var
  crl : PX509_CRL;
begin
    crl := nil;
    crl := PX509_CRL (ASN1_item_new(X509_CRL_it));
    if  0>= ossl_x509_crl_set0_libctx(crl, libctx, propq ) then
    begin
        X509_CRL_free(crl);
        crl := nil;
    end;
    Result := crl;
end;

initialization
   X509_CRL_seq_tt := [
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CRL(0).crl), 'crl', X509_CRL_INFO_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CRL(0).sig_alg), 'sig_alg', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CRL(0).signature), 'signature', ASN1_BIT_STRING_it)
   ] ;

   X509_CRL_aux := get_ASN1_AUX(Pointer(0) , 1, size_t(@PX509_CRL(0).references), size_t(@PX509_CRL(0).lock), crl_cb, 0, Pointer(0));
   X509_CRL_INFO_aux := get_ASN1_AUX(Pointer(0) , 2, 0, 0, crl_inf_cb, size_t(@PX509_CRL_INFO(0).enc), Pointer(0));

   X509_CRL_INFO_seq_tt := [
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@PX509_CRL_INFO(0).version), 'version', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_CRL_INFO(0).sig_alg), 'sig_alg', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_CRL_INFO(0).issuer), 'issuer', X509_NAME_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_CRL_INFO(0).lastUpdate), 'lastUpdate', ASN1_TIME_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@PX509_CRL_INFO(0).nextUpdate), 'nextUpdate', ASN1_TIME_it) ,
        get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), 0, size_t(@PX509_CRL_INFO(0).revoked), 'revoked', X509_REVOKED_it) ,
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6)) or (($2 shl 1) or ($1))), 0, size_t(@PX509_CRL_INFO(0).extensions), 'extensions', X509_EXTENSION_it)
  ] ;

   X509_REVOKED_seq_tt := [
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PX509_REVOKED(0).serialNumber), 'serialNumber', ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_REVOKED(0).revocationDate), 'revocationDate', ASN1_TIME_it) ,
        get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), 0, size_t(@PX509_REVOKED(0).extensions), 'extensions', X509_EXTENSION_it)
  ];

end.
