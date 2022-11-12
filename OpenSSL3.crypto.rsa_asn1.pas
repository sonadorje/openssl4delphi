unit OpenSSL3.crypto.rsa_asn1;

interface
uses OpenSSL.Api;

function RSA_PSS_PARAMS_it():PASN1_ITEM;
function RSA_PSS_PARAMS_dup(const x : PRSA_PSS_PARAMS):PRSA_PSS_PARAMS;
function rsa_pss_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
function i2d_RSAPrivateKey(const a : Pointer; &out : PPByte):integer;
function RSAPrivateKey_it():PASN1_ITEM;
function rsa_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
function RSA_PRIME_INFO_it:PASN1_ITEM;
function i2d_RSAPublicKey(const a : Pointer; &out : PPByte):integer;
const
    RSA_PSS_PARAMS_aux: TASN1_AUX  =
    (app_data:nil; flags:0; ref_offset:0; ref_lock:0; asn1_cb:rsa_pss_cb; enc_offset:0; asn1_const_cb:nil);
    RSAPrivateKey_aux: TASN1_AUX =
    (app_data:nil; flags:0; ref_offset:0; ref_lock:0; asn1_cb:rsa_cb; enc_offset:0; asn1_const_cb:nil);
var
   RSA_PSS_PARAMS_seq_tt: array[0..3] of TASN1_TEMPLATE;
   RSA_PRIME_INFO_seq_tt: array[0..2] of TASN1_TEMPLATE;
   RSAPrivateKey_seq_tt: array[0..9] of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.rsa.rsa_lib, openssl3.crypto.rsa.rsa_local,
     openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.crypto.rsa_mp,
     OpenSSL3.openssl.asn1t, openssl3.crypto.asn1.tasn_enc;



function i2d_RSAPublicKey(const a : Pointer; &out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), &out, (RSAPublicKey_it()));
end;


function RSA_PRIME_INFO_it:PASN1_ITEM;
const local_it: TASN1_ITEM  = (
   itype:$1;
   utype: 16;
   templates:@RSA_PRIME_INFO_seq_tt;
   tcount: sizeof(RSA_PRIME_INFO_seq_tt) div sizeof(TASN1_TEMPLATE);
   funcs: nil;
   size: sizeof(TRSA_PRIME_INFO);
   sname: 'RSA_PRIME_INFO' );
begin
   Result := @local_it;
end;


function rsa_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
begin
    if operation = ASN1_OP_NEW_PRE then
    begin
        pval^ := PASN1_VALUE ( RSA_new);
        if pval^ <> nil then Exit(2);
        Exit(0);
    end
    else
    if (operation = ASN1_OP_FREE_PRE) then
    begin
        RSA_free(PRSA(pval^));
        pval^ := nil;
        Exit(2);
    end
    else
    if (operation = ASN1_OP_D2I_POST) then
    begin
        if PRSA(pval^).version <> RSA_ASN1_VERSION_MULTI then
        begin
            { not a multi-prime key, skip }
            Exit(1);
        end;
        Exit(get_result( ossl_rsa_multip_calc_product(PRSA(pval^)) = 1 , 2 , 0));
    end;
    Result := 1;
end;

function RSAPrivateKey_it():PASN1_ITEM;

 const  local_it: TASN1_ITEM = (
    itype: $1;
    utype: 16;
    templates:@RSAPrivateKey_seq_tt;
    tcount: sizeof(RSAPrivateKey_seq_tt) div sizeof(TASN1_TEMPLATE);
    funcs:@RSAPrivateKey_aux;
    size: sizeof(TRSA);
    sname:'RSAPrivateKey');
begin
  RESULT := @local_it;
end;



function i2d_RSAPrivateKey(const a : Pointer; &out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), &out, (RSAPrivateKey_it()));
end;

function RSA_PSS_PARAMS_it():PASN1_ITEM;
const
   local_it: TASN1_ITEM = (
                itype:ASN1_ITYPE_SEQUENCE;
                utype:V_ASN1_SEQUENCE;
                templates:@RSA_PSS_PARAMS_seq_tt;
                tcount:sizeof(RSA_PSS_PARAMS_seq_tt) div sizeof(TASN1_TEMPLATE);
                funcs:@RSA_PSS_PARAMS_aux;
                size:sizeof(TRSA_PSS_PARAMS);
                sname:'RSA_PSS_PARAMS'
                );

begin

   Result := @local_it;
end;



function rsa_pss_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  pss : PRSA_PSS_PARAMS;
begin
    if operation = ASN1_OP_FREE_PRE then
    begin
        pss := PRSA_PSS_PARAMS(pval^);
        X509_ALGOR_free(pss.maskHash);
    end;
    Result := 1;
end;

function RSA_PSS_PARAMS_dup(const x : PRSA_PSS_PARAMS):PRSA_PSS_PARAMS;
begin
   Result := ASN1_item_dup(RSA_PSS_PARAMS_it(), x);
end;

initialization
  RSA_PSS_PARAMS_seq_tt[0] := ASN1_EXP_OPT(TypeInfo(TRSA_PSS_PARAMS), 'hashAlgorithm',    TypeInfo(TX509_ALGOR), 0);
  RSA_PSS_PARAMS_seq_tt[1] := ASN1_EXP_OPT(TypeInfo(TRSA_PSS_PARAMS), 'maskGenAlgorithm', TypeInfo(TX509_ALGOR), 1);
  RSA_PSS_PARAMS_seq_tt[2] := ASN1_EXP_OPT(TypeInfo(TRSA_PSS_PARAMS), 'saltLength',       TypeInfo(TASN1_INTEGER), 2);
  RSA_PSS_PARAMS_seq_tt[3] := ASN1_EXP_OPT(TypeInfo(TRSA_PSS_PARAMS), 'trailerField',     TypeInfo(TASN1_INTEGER), 3);

  RSAPrivateKey_seq_tt[0] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PRSA(0).version), 'version', INT32_it );
  RSAPrivateKey_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).n)), 'n', BIGNUM_it );
  RSAPrivateKey_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).e)), 'e', BIGNUM_it );
  RSAPrivateKey_seq_tt[3] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).d)), 'd', CBIGNUM_it );
  RSAPrivateKey_seq_tt[4] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).p)), 'p', CBIGNUM_it );
  RSAPrivateKey_seq_tt[5] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).q)), 'q', CBIGNUM_it );
  RSAPrivateKey_seq_tt[6] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).dmp1)), 'dmp1', CBIGNUM_it );
  RSAPrivateKey_seq_tt[7] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).dmq1)), 'dmq1', CBIGNUM_it );
  RSAPrivateKey_seq_tt[8] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA(0).iqmp)), 'iqmp', CBIGNUM_it );
  RSAPrivateKey_seq_tt[9] := get_ASN1_TEMPLATE( ($2 shl 1) or ($1), 0, size_t(@(PRSA(0).prime_infos)), 'prime_infos', RSA_PRIME_INFO_it );


  RSA_PRIME_INFO_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA_PRIME_INFO(0).r)), 'r', CBIGNUM_it );
  RSA_PRIME_INFO_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA_PRIME_INFO(0).d)), 'd', CBIGNUM_it );
  RSA_PRIME_INFO_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, size_t(@(PRSA_PRIME_INFO(0).t)), 't', CBIGNUM_it );
end.
