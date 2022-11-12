unit openssl3.crypto.objects.obj_xref;

interface
uses OpenSSL.Api;
type
  Tnid_triple = record

    sign_id, hash_id, pkey_id : integer;
  end;
  Pnid_triple = ^Tnid_triple;
  PPnid_triple = ^Pnid_triple;
  sk_nid_triple_compfunc = function (const a, b : PPnid_triple):integer;
  sk_nid_triple_freefunc = procedure ( a : Pnid_triple);
  sk_nid_triple_copyfunc = function (const a : Pnid_triple):Pnid_triple;

  function get_nid_triple(sign_id, hash_id, pkey_id : integer): Tnid_triple;
  function sig_cmp(const a, b : Pnid_triple):integer;
  function sig_sk_cmp(const a, b : PPnid_triple):integer;
  function sigx_cmp(const a, b : PPnid_triple):integer;
  function obj_sig_init:integer;
  function ossl_obj_find_sigid_algs( signid : integer; pdig_nid, ppkey_nid : PInteger; lock : integer):integer;
  function OBJ_find_sigid_algs( signid : integer; pdig_nid, ppkey_nid : PInteger):integer;
  function OBJ_find_sigid_by_algs( psignid : PInteger; dig_nid, pkey_nid : integer):integer;
  function OBJ_add_sigid( signid, dig_id, pkey_id : integer):integer;
  procedure sid_free( tt : Pnid_triple);
  procedure OBJ_sigid_free;
  procedure o_sig_init_ossl_;
  function o_sig_init:integer;
  function sig_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_sig( key : Pnid_triple; const base: Pnid_triple; num : integer):Pnid_triple;

   function sk_nid_triple_num(const sk : Pstack_st_nid_triple):integer;
  function sk_nid_triple_value(const sk : Pstack_st_nid_triple; idx : integer):Pnid_triple;
  function sk_nid_triple_new( compare : sk_nid_triple_compfunc):Pstack_st_nid_triple;
  function sk_nid_triple_new_null:Pstack_st_nid_triple;
  function sk_nid_triple_new_reserve( compare : sk_nid_triple_compfunc; n : integer):Pstack_st_nid_triple;
  function sk_nid_triple_reserve( sk : Pstack_st_nid_triple; n : integer):integer;
  procedure sk_nid_triple_free( sk : Pstack_st_nid_triple);
  procedure sk_nid_triple_zero( sk : Pstack_st_nid_triple);
  function sk_nid_triple_delete( sk : Pstack_st_nid_triple; i : integer):Pnid_triple;
  function sk_nid_triple_delete_ptr( sk : Pstack_st_nid_triple; ptr : Pnid_triple):Pnid_triple;
  function sk_nid_triple_push( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
  function sk_nid_triple_unshift( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
  function sk_nid_triple_pop( sk : Pstack_st_nid_triple):Pnid_triple;
  function sk_nid_triple_shift( sk : Pstack_st_nid_triple):Pnid_triple;
  procedure sk_nid_triple_pop_free( sk : Pstack_st_nid_triple; freefunc : sk_nid_triple_freefunc);
  function sk_nid_triple_insert( sk : Pstack_st_nid_triple; ptr : Pnid_triple; idx : integer):integer;
  function sk_nid_triple_set( sk : Pstack_st_nid_triple; idx : integer; ptr : Pnid_triple):Pnid_triple;
  function sk_nid_triple_find( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
  function sk_nid_triple_find_ex( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
  function sk_nid_triple_find_all( sk : Pstack_st_nid_triple; ptr : Pnid_triple; pnum : PInteger):integer;
  procedure sk_nid_triple_sort( sk : Pstack_st_nid_triple);
  function sk_nid_triple_is_sorted(const sk : Pstack_st_nid_triple):integer;
  function sk_nid_triple_dup(const sk : Pstack_st_nid_triple):Pstack_st_nid_triple;
  function sk_nid_triple_deep_copy(const sk : Pstack_st_nid_triple; copyfunc : sk_nid_triple_copyfunc; freefunc : sk_nid_triple_freefunc):Pstack_st_nid_triple;
  function sk_nid_triple_set_cmp_func( sk : Pstack_st_nid_triple; compare : sk_nid_triple_compfunc):sk_nid_triple_compfunc;
  function sigx_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_sigx(const key, base : PPnid_triple; num : integer):PPnid_triple;

var
    sig_init: CRYPTO_ONCE = 0;
    o_sig_init_ossl_ret_: int = 0;
    sig_lock: PCRYPTO_RWLOCK;
    sigoid_srt: array of Tnid_triple ;
    sig_app, sigx_app: Pstack_st_nid_triple;
    sigoid_srt_xref: array of Pnid_triple ;

implementation

uses OpenSSL3.threads_none, openssl3.crypto.objects.obj_dat,
     OpenSSL3.Err, openssl3.crypto.stack, openssl3.crypto.mem;

function get_nid_triple(sign_id, hash_id, pkey_id : integer): Tnid_triple;
begin
   result.sign_id := sign_id;
   result.hash_id := hash_id;
   result.pkey_id := pkey_id;
end;



function sigx_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PPnid_triple;
begin
   a := a_;
   b := b_;
   result := sigx_cmp(a,b);
end;


function OBJ_bsearch_sigx(const key, base : PPnid_triple; num : integer):PPnid_triple;
begin
   Result := PPnid_triple(OBJ_bsearch_(key, base, num,
                        sizeof(Pnid_triple) , sigx_cmp_BSEARCH_CMP_FN));
end;




function sk_nid_triple_num(const sk : Pstack_st_nid_triple):integer;
begin
  result := OPENSSL_sk_num(POPENSSL_STACK( sk));
end;


function sk_nid_triple_value(const sk : Pstack_st_nid_triple; idx : integer):Pnid_triple;
begin
   Result := Pnid_triple( OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;


function sk_nid_triple_new( compare : sk_nid_triple_compfunc):Pstack_st_nid_triple;
begin
   result := Pstack_st_nid_triple( OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_nid_triple_new_null:Pstack_st_nid_triple;
begin
   Result := Pstack_st_nid_triple( OPENSSL_sk_new_null);
end;


function sk_nid_triple_new_reserve( compare : sk_nid_triple_compfunc; n : integer):Pstack_st_nid_triple;
begin
   Result := Pstack_st_nid_triple( OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_nid_triple_reserve( sk : Pstack_st_nid_triple; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK( sk), n);
end;


procedure sk_nid_triple_free( sk : Pstack_st_nid_triple);
begin
   OPENSSL_sk_free(POPENSSL_STACK( sk));
end;


procedure sk_nid_triple_zero( sk : Pstack_st_nid_triple);
begin
   OPENSSL_sk_zero(POPENSSL_STACK( sk));
end;


function sk_nid_triple_delete( sk : Pstack_st_nid_triple; i : integer):Pnid_triple;
begin
   Result :=  Pnid_triple( OPENSSL_sk_delete(POPENSSL_STACK( sk), i));
end;


function sk_nid_triple_delete_ptr( sk : Pstack_st_nid_triple; ptr : Pnid_triple):Pnid_triple;
begin
   Result :=  Pnid_triple( OPENSSL_sk_delete_ptr(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_nid_triple_push( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr));
end;


function sk_nid_triple_unshift( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK( sk), Pointer( ptr));
end;


function sk_nid_triple_pop( sk : Pstack_st_nid_triple):Pnid_triple;
begin
   Result := Pnid_triple( OPENSSL_sk_pop(POPENSSL_STACK( sk)));
end;


function sk_nid_triple_shift( sk : Pstack_st_nid_triple):Pnid_triple;
begin
   Result := Pnid_triple( OPENSSL_sk_shift(POPENSSL_STACK( sk)));
end;


procedure sk_nid_triple_pop_free( sk : Pstack_st_nid_triple; freefunc : sk_nid_triple_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_nid_triple_insert( sk : Pstack_st_nid_triple; ptr : Pnid_triple; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK( sk), Pointer( ptr), idx);
end;


function sk_nid_triple_set( sk : Pstack_st_nid_triple; idx : integer; ptr : Pnid_triple):Pnid_triple;
begin
   Result := Pnid_triple( OPENSSL_sk_set(POPENSSL_STACK( sk), idx, Pointer( ptr)));
end;


function sk_nid_triple_find( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK( sk), Pointer( ptr));
end;


function sk_nid_triple_find_ex( sk : Pstack_st_nid_triple; ptr : Pnid_triple):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK( sk), Pointer( ptr));
end;


function sk_nid_triple_find_all( sk : Pstack_st_nid_triple; ptr : Pnid_triple; pnum : PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK( sk), Pointer( ptr), pnum);
end;


procedure sk_nid_triple_sort( sk : Pstack_st_nid_triple);
begin
 OPENSSL_sk_sort(POPENSSL_STACK( sk));
end;


function sk_nid_triple_is_sorted(const sk : Pstack_st_nid_triple):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK( sk));
end;


function sk_nid_triple_dup(const sk : Pstack_st_nid_triple):Pstack_st_nid_triple;
begin
   Result := Pstack_st_nid_triple( OPENSSL_sk_dup(POPENSSL_STACK( sk)));
end;


function sk_nid_triple_deep_copy(const sk : Pstack_st_nid_triple; copyfunc : sk_nid_triple_copyfunc; freefunc : sk_nid_triple_freefunc):Pstack_st_nid_triple;
begin
   Result := Pstack_st_nid_triple( OPENSSL_sk_deep_copy(POPENSSL_STACK( sk), OPENSSL_sk_copyfunc(copyfunc),
                                   OPENSSL_sk_freefunc(freefunc)));
end;


function sk_nid_triple_set_cmp_func( sk : Pstack_st_nid_triple; compare : sk_nid_triple_compfunc):sk_nid_triple_compfunc;
begin
   Result := sk_nid_triple_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK( sk), OPENSSL_sk_compfunc(compare)));
end;




function sig_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : Pnid_triple;
begin
  a := a_;
  b := b_;
  result := sig_cmp(a,b);
end;


function OBJ_bsearch_sig( key : Pnid_triple; const base: Pnid_triple; num : integer):Pnid_triple;
begin
   result := Pnid_triple(OBJ_bsearch_(key, base, num, sizeof(Tnid_triple), sig_cmp_BSEARCH_CMP_FN));
end;


procedure o_sig_init_ossl_;
begin
   o_sig_init_ossl_ret_ := o_sig_init();
end;


function o_sig_init:integer;
begin
    sig_lock := CRYPTO_THREAD_lock_new();
    Result := Int(sig_lock <> nil) ;
end;

function sig_cmp(const a, b : Pnid_triple):integer;
begin
    Result := a.sign_id - b.sign_id;
end;


function sig_sk_cmp(const a, b : PPnid_triple):integer;
begin
    Result := ( a^).sign_id - ( b^).sign_id;
end;


function sigx_cmp(const a, b : PPnid_triple):integer;
var
  ret : integer;
begin
    ret := ( a^).hash_id - ( b^).hash_id;
    if ret <> 0 then
       Exit(ret);
    Result := (a^).pkey_id - (b^).pkey_id;
end;


function obj_sig_init:integer;
begin
    Result := get_result(CRYPTO_THREAD_run_once(@sig_init, o_sig_init_ossl_)>0, o_sig_init_ossl_ret_ , 0);
end;


function ossl_obj_find_sigid_algs( signid : integer; pdig_nid, ppkey_nid : PInteger; lock : integer):integer;
var
  tmp : Tnid_triple;

  rv : Pnid_triple;

  idx : integer;
begin
    if signid = NID_undef then Exit(0);
    tmp.sign_id := signid;
    rv := OBJ_bsearch_sig(@tmp, @sigoid_srt, Length(sigoid_srt));
    if rv = nil then begin
        if 0>= obj_sig_init() then
            Exit(0);
        if (lock > 0)  and  (0>= CRYPTO_THREAD_read_lock(sig_lock)) then
        begin
            ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
            Exit(0);
        end;
        if sig_app <> nil then
        begin
            idx := sk_nid_triple_find(sig_app, @tmp);
            if idx >= 0 then
               rv := sk_nid_triple_value(sig_app, idx);
        end;
        if lock > 0 then
           CRYPTO_THREAD_unlock(sig_lock);
        if rv = nil then Exit(0);
    end;
    if pdig_nid <> nil then
       pdig_nid^ := rv.hash_id;
    if ppkey_nid <> nil then
       ppkey_nid^ := rv.pkey_id;
    Result := 1;
end;


function OBJ_find_sigid_algs( signid : integer; pdig_nid, ppkey_nid : PInteger):integer;
begin
    Result := ossl_obj_find_sigid_algs(signid, pdig_nid, ppkey_nid, 1);
end;


function OBJ_find_sigid_by_algs( psignid : PInteger; dig_nid, pkey_nid : integer):integer;
var
  tmp : Tnid_triple;
  t : Pnid_triple;
  rv : PPnid_triple;
  idx : integer;
begin
     t := @tmp;
    if (dig_nid = NID_undef)  or  (pkey_nid = NID_undef) then
       Exit(0);
    tmp.hash_id := dig_nid;
    tmp.pkey_id := pkey_nid;
    rv := OBJ_bsearch_sigx(@t, @sigoid_srt_xref, Length(sigoid_srt_xref));
    if rv = nil then
    begin
        if 0>= obj_sig_init() then
            Exit(0);
        if 0>= CRYPTO_THREAD_read_lock(sig_lock) then
        begin
            ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
            Exit(0);
        end;
        if sigx_app <> nil then
        begin
            idx := sk_nid_triple_find(sigx_app, @tmp);
            if idx >= 0 then
            begin
                t := sk_nid_triple_value(sigx_app, idx);
                rv := @t;
            end;
        end;
        CRYPTO_THREAD_unlock(sig_lock);
        if rv = nil then Exit(0);
    end;
    if psignid <> nil then
       psignid^ := (rv^).sign_id;
    Result := 1;
end;


function OBJ_add_sigid( signid, dig_id, pkey_id : integer):integer;
var
  ntr : Pnid_triple;

  dnid, pnid, ret : integer;
  label _err;
begin
    dnid := NID_undef; pnid := NID_undef; ret := 0;
    if (signid = NID_undef)  or  (pkey_id = NID_undef) then Exit(0);
    if 0>= obj_sig_init() then
        Exit(0);
    ntr := OPENSSL_malloc(sizeof(ntr^));
    if ntr = nil then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ntr.sign_id := signid;
    ntr.hash_id := dig_id;
    ntr.pkey_id := pkey_id;
    if 0>= CRYPTO_THREAD_write_lock(sig_lock) then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_WRITE_LOCK);
        OPENSSL_free(Pointer(ntr));
        Exit(0);
    end;
    { Check that the entry doesn't exist or exists as desired }
    if ossl_obj_find_sigid_algs(signid, @dnid, @pnid, 0) > 0 then
    begin
        ret := Int((dnid = dig_id)  and  (pnid = pkey_id));
        goto _err ;
    end;
    if sig_app = nil then
    begin
        sig_app := sk_nid_triple_new(sig_sk_cmp);
        if sig_app = nil then
           goto _err ;
    end;
    if sigx_app = nil then
    begin
        sigx_app := sk_nid_triple_new(sigx_cmp);
        if sigx_app = nil then
           goto _err ;
    end;
    {
     * Better might be to find where to insert the element and insert it there.
     * This would avoid the sorting steps below.
     }
    if 0>= sk_nid_triple_push(sig_app, ntr) then
        goto _err ;
    if 0>= sk_nid_triple_push(sigx_app, ntr) then
    begin
        ntr := nil;             { This is referenced by sig_app still }
        goto _err ;
    end;
    sk_nid_triple_sort(sig_app);
    sk_nid_triple_sort(sigx_app);
    ntr := nil;
    ret := 1;
 _err:
    OPENSSL_free(Pointer(ntr));
    CRYPTO_THREAD_unlock(sig_lock);
    Result := ret;
end;


procedure sid_free( tt : Pnid_triple);
begin
    OPENSSL_free(Pointer(tt));
end;


procedure OBJ_sigid_free;
begin
    sk_nid_triple_pop_free(sig_app, sid_free);
    sk_nid_triple_free(sigx_app);
    CRYPTO_THREAD_lock_free(sig_lock);
    sig_app := nil;
    sigx_app := nil;
    sig_lock := nil;
end;

initialization


   sigoid_srt := [
    get_nid_triple(NID_md2WithRSAEncryption, NID_md2, NID_rsaEncryption),
    get_nid_triple(NID_md5WithRSAEncryption, NID_md5, NID_rsaEncryption),
    get_nid_triple(NID_shaWithRSAEncryption, NID_sha, NID_rsaEncryption),
    get_nid_triple(NID_sha1WithRSAEncryption, NID_sha1, NID_rsaEncryption),
    get_nid_triple(NID_dsaWithSHA, NID_sha, NID_dsa),
    get_nid_triple(NID_dsaWithSHA1_2, NID_sha1, NID_dsa_2),
    get_nid_triple(NID_mdc2WithRSA, NID_mdc2, NID_rsaEncryption),
    get_nid_triple(NID_md5WithRSA, NID_md5, NID_rsa),
    get_nid_triple(NID_dsaWithSHA1, NID_sha1, NID_dsa),
    get_nid_triple(NID_sha1WithRSA, NID_sha1, NID_rsa),
    get_nid_triple(NID_ripemd160WithRSA, NID_ripemd160, NID_rsaEncryption),
    get_nid_triple(NID_md4WithRSAEncryption, NID_md4, NID_rsaEncryption),
    get_nid_triple(NID_ecdsa_with_SHA1, NID_sha1, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_sha256WithRSAEncryption, NID_sha256, NID_rsaEncryption),
    get_nid_triple(NID_sha384WithRSAEncryption, NID_sha384, NID_rsaEncryption),
    get_nid_triple(NID_sha512WithRSAEncryption, NID_sha512, NID_rsaEncryption),
    get_nid_triple(NID_sha224WithRSAEncryption, NID_sha224, NID_rsaEncryption),
    get_nid_triple(NID_ecdsa_with_Recommended, NID_undef, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_ecdsa_with_Specified, NID_undef, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_ecdsa_with_SHA224, NID_sha224, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_ecdsa_with_SHA256, NID_sha256, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_ecdsa_with_SHA384, NID_sha384, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_ecdsa_with_SHA512, NID_sha512, NID_X9_62_id_ecPublicKey),
    get_nid_triple(NID_dsa_with_SHA224, NID_sha224, NID_dsa),
    get_nid_triple(NID_dsa_with_SHA256, NID_sha256, NID_dsa),
    get_nid_triple(NID_id_GostR3411_94_with_GostR3410_2001, NID_id_GostR3411_94,
     NID_id_GostR3410_2001),
    get_nid_triple(NID_id_GostR3411_94_with_GostR3410_94, NID_id_GostR3411_94,
     NID_id_GostR3410_94),
    get_nid_triple(NID_id_GostR3411_94_with_GostR3410_94_cc, NID_id_GostR3411_94,
     NID_id_GostR3410_94_cc),
    get_nid_triple(NID_id_GostR3411_94_with_GostR3410_2001_cc, NID_id_GostR3411_94,
     NID_id_GostR3410_2001_cc),
    get_nid_triple(NID_rsassaPss, NID_undef, NID_rsassaPss),
    get_nid_triple(NID_dhSinglePass_stdDH_sha1kdf_scheme, NID_sha1, NID_dh_std_kdf),
    get_nid_triple(NID_dhSinglePass_stdDH_sha224kdf_scheme, NID_sha224, NID_dh_std_kdf),
    get_nid_triple(NID_dhSinglePass_stdDH_sha256kdf_scheme, NID_sha256, NID_dh_std_kdf),
    get_nid_triple(NID_dhSinglePass_stdDH_sha384kdf_scheme, NID_sha384, NID_dh_std_kdf),
    get_nid_triple(NID_dhSinglePass_stdDH_sha512kdf_scheme, NID_sha512, NID_dh_std_kdf),
    get_nid_triple(NID_dhSinglePass_cofactorDH_sha1kdf_scheme, NID_sha1,
     NID_dh_cofactor_kdf),
    get_nid_triple(NID_dhSinglePass_cofactorDH_sha224kdf_scheme, NID_sha224,
     NID_dh_cofactor_kdf),
    get_nid_triple(NID_dhSinglePass_cofactorDH_sha256kdf_scheme, NID_sha256,
     NID_dh_cofactor_kdf),
    get_nid_triple(NID_dhSinglePass_cofactorDH_sha384kdf_scheme, NID_sha384,
     NID_dh_cofactor_kdf),
    get_nid_triple(NID_dhSinglePass_cofactorDH_sha512kdf_scheme, NID_sha512,
     NID_dh_cofactor_kdf),
    get_nid_triple(NID_id_tc26_signwithdigest_gost3410_2012_256, NID_id_GostR3411_2012_256,
     NID_id_GostR3410_2012_256),
    get_nid_triple(NID_id_tc26_signwithdigest_gost3410_2012_512, NID_id_GostR3411_2012_512,
     NID_id_GostR3410_2012_512),
    get_nid_triple(NID_ED25519, NID_undef, NID_ED25519),
    get_nid_triple(NID_ED448, NID_undef, NID_ED448),
    get_nid_triple(NID_RSA_SHA3_224, NID_sha3_224, NID_rsaEncryption),
    get_nid_triple(NID_RSA_SHA3_256, NID_sha3_256, NID_rsaEncryption),
    get_nid_triple(NID_RSA_SHA3_384, NID_sha3_384, NID_rsaEncryption),
    get_nid_triple(NID_RSA_SHA3_512, NID_sha3_512, NID_rsaEncryption),
    get_nid_triple(NID_SM2_with_SM3, NID_sm3, NID_sm2)
];
   sigoid_srt_xref := [
    @sigoid_srt[0],
    @sigoid_srt[1],
    @sigoid_srt[7],
    @sigoid_srt[2],
    @sigoid_srt[4],
    @sigoid_srt[3],
    @sigoid_srt[9],
    @sigoid_srt[5],
    @sigoid_srt[8],
    @sigoid_srt[12],
    @sigoid_srt[30],
    @sigoid_srt[35],
    @sigoid_srt[6],
    @sigoid_srt[10],
    @sigoid_srt[11],
    @sigoid_srt[13],
    @sigoid_srt[24],
    @sigoid_srt[20],
    @sigoid_srt[32],
    @sigoid_srt[37],
    @sigoid_srt[14],
    @sigoid_srt[21],
    @sigoid_srt[33],
    @sigoid_srt[38],
    @sigoid_srt[15],
    @sigoid_srt[22],
    @sigoid_srt[34],
    @sigoid_srt[39],
    @sigoid_srt[16],
    @sigoid_srt[23],
    @sigoid_srt[19],
    @sigoid_srt[31],
    @sigoid_srt[36],
    @sigoid_srt[25],
    @sigoid_srt[26],
    @sigoid_srt[27],
    @sigoid_srt[28],
    @sigoid_srt[40],
    @sigoid_srt[41],
    @sigoid_srt[44],
    @sigoid_srt[45],
    @sigoid_srt[46],
    @sigoid_srt[47],
    @sigoid_srt[48]
];

end.
