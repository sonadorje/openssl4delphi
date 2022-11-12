unit OpenSSL3.crypto.rsa_backend;

interface
uses OpenSSL.Api;

type
  sk_BIGNUM_const_compfunc = function (const  a, b: PBIGNUM_const):integer;
  sk_BIGNUM_const_freefunc = procedure(a: PBIGNUM_const);
  sk_BIGNUM_const_copyfunc = function(const a: PBIGNUM_const): PBIGNUM_const;

  sk_BIGNUM_compfunc = function (const  a, b: PBIGNUM):integer;
  sk_BIGNUM_freefunc = procedure(a: PBIGNUM);
  sk_BIGNUM_copyfunc = function(const a: PBIGNUM): PBIGNUM;

  function sk_BIGNUM_const_num(const sk : Pstack_st_BIGNUM_const):integer;
  function sk_BIGNUM_const_value(const sk : Pstack_st_BIGNUM_const; idx : integer):PBIGNUM;
  function sk_BIGNUM_const_new( compare : sk_BIGNUM_const_compfunc):Pstack_st_BIGNUM_const;
  function sk_BIGNUM_const_new_null:Pstack_st_BIGNUM_const;
  function sk_BIGNUM_const_new_reserve( compare : sk_BIGNUM_const_compfunc; n : integer):Pstack_st_BIGNUM_const;
  function sk_BIGNUM_const_reserve( sk : Pstack_st_BIGNUM_const; n : integer):integer;
  procedure sk_BIGNUM_const_free( sk : Pstack_st_BIGNUM_const);
  procedure sk_BIGNUM_const_zero( sk : Pstack_st_BIGNUM_const);
  function sk_BIGNUM_const_delete( sk : Pstack_st_BIGNUM_const; i : integer):PBIGNUM;
  function sk_BIGNUM_const_delete_ptr( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):PBIGNUM;
  function sk_BIGNUM_const_push( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
  function sk_BIGNUM_const_unshift( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
  function sk_BIGNUM_const_pop( sk : Pstack_st_BIGNUM_const):PBIGNUM;
  function sk_BIGNUM_const_shift( sk : Pstack_st_BIGNUM_const):PBIGNUM;
  procedure sk_BIGNUM_const_pop_free( sk : Pstack_st_BIGNUM_const; freefunc : sk_BIGNUM_const_freefunc);
  function sk_BIGNUM_const_insert( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM; idx : integer):integer;
  function sk_BIGNUM_const_set( sk : Pstack_st_BIGNUM_const; idx : integer; ptr : PBIGNUM):PBIGNUM;
  function sk_BIGNUM_const_find( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
  function sk_BIGNUM_const_find_ex( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
  function sk_BIGNUM_const_find_all( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM; pnum : PInteger):integer;
  procedure sk_BIGNUM_const_sort( sk : Pstack_st_BIGNUM_const);
  function sk_BIGNUM_const_is_sorted(const sk : Pstack_st_BIGNUM_const):integer;
  function sk_BIGNUM_const_dup(const sk : Pstack_st_BIGNUM_const):Pstack_st_BIGNUM_const;
  function sk_BIGNUM_const_deep_copy(const sk : Pstack_st_BIGNUM_const; copyfunc : sk_BIGNUM_const_copyfunc; freefunc : sk_BIGNUM_const_freefunc):Pstack_st_BIGNUM_const;
  function sk_BIGNUM_const_set_cmp_func( sk : Pstack_st_BIGNUM_const; compare : sk_BIGNUM_const_compfunc):sk_BIGNUM_const_compfunc;
  function ossl_rsa_pss_params_30_fromdata(pss_params : PRSA_PSS_PARAMS_30; defaults_set : PInteger;const params : POSSL_PARAM; libctx : POSSL_LIB_CTX):integer;
  function ossl_rsa_fromdata(rsa : PRSA;const params : POSSL_PARAM):integer;

   function sk_BIGNUM_num( sk : Pointer):integer;
  function sk_BIGNUM_value( sk : Pointer;idx: integer):PBIGNUM;
  function sk_BIGNUM_new( cmp : sk_BIGNUM_compfunc):PSTACK_st_BIGNUM;
  function sk_BIGNUM_new_null:PSTACK_st_BIGNUM;
  function sk_BIGNUM_new_reserve( cmp : sk_BIGNUM_compfunc; n : integer):PSTACK_st_BIGNUM;
  function sk_BIGNUM_reserve( sk : Pointer; n : integer):integer;
  procedure sk_BIGNUM_free( sk : Pointer);
  procedure sk_BIGNUM_zero( sk : Pointer);
  function sk_BIGNUM_delete( sk : Pointer; i : integer):PBIGNUM;
  function sk_BIGNUM_delete_ptr( sk, ptr : Pointer):PBIGNUM;
  function sk_BIGNUM_push( sk, ptr : Pointer):integer;
  function sk_BIGNUM_unshift( sk, ptr : Pointer):integer;
  function sk_BIGNUM_pop( sk : Pointer):PBIGNUM;
  function sk_BIGNUM_shift( sk : Pointer):PBIGNUM;
  procedure sk_BIGNUM_pop_free( sk : Pointer; freefunc : sk_BIGNUM_freefunc);
  function sk_BIGNUM_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_BIGNUM_set( sk : Pointer; idx : integer; ptr : Pointer):PBIGNUM;
  function sk_BIGNUM_find( sk, ptr : Pointer):integer;
  function sk_BIGNUM_find_ex( sk, ptr : Pointer):integer;
  function sk_BIGNUM_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_BIGNUM_sort( sk : Pointer);
  function sk_BIGNUM_is_sorted( sk : Pointer):integer;
  function sk_BIGNUM_dup( sk : Pointer):PSTACK_st_BIGNUM;
  function sk_BIGNUM_deep_copy( sk : Pointer; copyfunc : sk_BIGNUM_copyfunc; freefunc : sk_BIGNUM_freefunc):PSTACK_st_BIGNUM;
  function sk_BIGNUM_set_cmp_func( sk : Pointer; cmp : sk_BIGNUM_compfunc):sk_BIGNUM_compfunc;

function ossl_rsa_dup(const rsa : PRSA; selection : integer):PRSA;
function ossl_rsa_is_foreign(const rsa : PRSA):Boolean;
function rsa_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
function ossl_rsa_pss_params_30_todata(const pss : PRSA_PSS_PARAMS_30; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
function ossl_rsa_todata( rsa : PRSA; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
function collect_numbers(numbers : Pstack_st_BIGNUM;const params : POSSL_PARAM; names : PPUTF8Char):int;

implementation
uses openssl3.crypto.rsa.rsa_lib, openssl3.crypto.rsa.rsa_local, OpenSSL3.crypto.rsa.rsa_asn1,
     openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.crypto.rsa.rsa_mp,
     openssl3.crypto.asn1.x_algor, openssl3.crypto.rsa.rsa_pss,
     openssl3.crypto.rsa.rsa_schemes, openssl3.crypto.param_build_set,
     openssl3.crypto.stack, openssl3.crypto.rsa.rsa_mp_names,
     openssl3.crypto.params, openssl3.crypto.evp.digest,
     openssl3.crypto.ex_data,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.rsa.rsa_ossl;




function sk_BIGNUM_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_BIGNUM_value( sk : Pointer; idx: integer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_BIGNUM_new( cmp : sk_BIGNUM_compfunc):PSTACK_st_BIGNUM;
begin
   Result := PSTACK_st_BIGNUM (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_BIGNUM_new_null:PSTACK_st_BIGNUM;
begin
   Result := PSTACK_st_BIGNUM (OPENSSL_sk_new_null())
end;


function sk_BIGNUM_new_reserve( cmp : sk_BIGNUM_compfunc; n : integer):PSTACK_st_BIGNUM;
begin
   Result := PSTACK_st_BIGNUM (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_BIGNUM_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_BIGNUM_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_BIGNUM_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_BIGNUM_delete( sk : Pointer; i : integer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_BIGNUM_delete_ptr( sk, ptr : Pointer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_BIGNUM_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_BIGNUM_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_BIGNUM_pop( sk : Pointer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_BIGNUM_shift( sk : Pointer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_BIGNUM_pop_free( sk : Pointer; freefunc : sk_BIGNUM_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_BIGNUM_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_BIGNUM_set( sk : Pointer; idx : integer; ptr : Pointer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_BIGNUM_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_BIGNUM_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_BIGNUM_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_BIGNUM_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_BIGNUM_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_BIGNUM_dup( sk : Pointer):PSTACK_st_BIGNUM;
begin
   Result := PSTACK_st_BIGNUM (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_BIGNUM_deep_copy( sk : Pointer; copyfunc : sk_BIGNUM_copyfunc; freefunc : sk_BIGNUM_freefunc):PSTACK_st_BIGNUM;
begin
   Result := PSTACK_st_BIGNUM (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_BIGNUM_set_cmp_func( sk : Pointer; cmp : sk_BIGNUM_compfunc):sk_BIGNUM_compfunc;
begin
   Result := sk_BIGNUM_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;


function collect_numbers(numbers : Pstack_st_BIGNUM;const params : POSSL_PARAM; names : PPUTF8Char):int;
var
  p : POSSL_PARAM;

  i : integer;

  tmp : PBIGNUM;
begin
{$POINTERMATH ON}
    p := nil;
    if numbers = nil then Exit(0);
    i := 0;
    while ( names[i] <> nil) do
    begin
        p := OSSL_PARAM_locate_const(params, names[i]);
        if p <> nil then
        begin
            tmp := nil;
            if  (0>= OSSL_PARAM_get_BN(p, @tmp) ) or
                (sk_BIGNUM_push(numbers, tmp) = 0) then
                Exit(0);
        end;
        Inc(i);
    end;
    Result := 1;
{$POINTERMATH OFF}
end;



function ossl_rsa_fromdata(rsa : PRSA;const params : POSSL_PARAM):integer;
var
  param_n,
  param_e,
  param_d    : POSSL_PARAM;
  n,
  e,
  d          : PBIGNUM;

  factors,
  exps,
  coeffs     : Pstack_st_BIGNUM;
  is_private : integer;
  label _err;
begin
    n := nil;
    e := nil;
    d := nil;
    factors := nil;
    exps := nil;
    coeffs := nil;
    is_private := 0;
    if rsa = nil then Exit(0);
    param_n := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    param_d := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
    if (param_n <> nil)  and   (0>= OSSL_PARAM_get_BN(param_n, @n ) )
         or ( (param_e <> nil)  and   (0>= OSSL_PARAM_get_BN(param_e, @e)) )
         or ( (param_d <> nil)  and   (0>= OSSL_PARAM_get_BN(param_d, @d)) ) then
        goto _err ;
    is_private := int(d <> nil);
    if  0>= RSA_set0_key(rsa, n, e, d)   then
        goto _err ;
    n := nil;e := nil; d := nil;
    if is_private>0 then
    begin
        factors := sk_BIGNUM_new_null();
        exps    := sk_BIGNUM_new_null();
        coeffs  := sk_BIGNUM_new_null();
        if  (0>= collect_numbers(factors, params,
                             @ossl_rsa_mp_factor_names) )
             or  (0>= collect_numbers(exps, params,
                                @ossl_rsa_mp_exp_names) )
             or  (0>= collect_numbers(coeffs, params,
                                @ossl_rsa_mp_coeff_names)) then
            goto _err ;
        { It's ok if this private key just has n, e and d }
        if (sk_BIGNUM_num(factors) <> 0)
             and  (0>= ossl_rsa_set0_all_params(rsa, factors, exps, coeffs))  then
            goto _err ;
    end;
    sk_BIGNUM_free(factors);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    Exit(1);
 _err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    sk_BIGNUM_pop_free(factors, BN_free);
    sk_BIGNUM_pop_free(exps, BN_free);
    sk_BIGNUM_pop_free(coeffs, BN_free);
    Result := 0;
end;

function ossl_rsa_pss_params_30_fromdata(pss_params : PRSA_PSS_PARAMS_30; defaults_set : PInteger;const params : POSSL_PARAM; libctx : POSSL_LIB_CTX):integer;
var
  param_md,
 param_mgf,
  param_mgf1md           : POSSL_PARAM;
  param_saltlen          : POSSL_PARAM;
  param_propq            : POSSL_PARAM;
  propq                  : PUTF8Char;
  md,
  mgf1md                 : PEVP_MD;
  saltlen,
  ret,
  default_maskgenalg_nid : integer;
  mgfname,
  mdname,
  mgf1mdname             : PUTF8Char;
  label _err;
begin
    propq := nil;
    md := nil;
mgf1md := nil;
    ret := 0;
    if pss_params = nil then Exit(0);
    param_propq := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
    param_md := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    param_mgf := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
    param_mgf1md := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
    param_saltlen := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
    if param_propq <> nil then
    begin
        if param_propq.data_type = OSSL_PARAM_UTF8_STRING then
            propq := param_propq.data;
    end;
    {
     * If we get any of the parameters, we know we have at least some
     * restrictions, so we start by setting default values, and let each
     * parameter override their specific restriction data.
     }
    if  (0>= defaults_set^)
         and  ( (param_md <> nil)  or  (param_mgf <> nil)  or  (param_mgf1md <> nil)
             or  (param_saltlen <> nil) )then
    begin
        if  0>= ossl_rsa_pss_params_30_set_defaults(pss_params) then
            Exit(0);
        defaults_set^ := 1;
    end;
    if param_mgf <> nil then
    begin
        default_maskgenalg_nid := ossl_rsa_pss_params_30_maskgenalg(nil);
         mgfname := nil;
        if param_mgf.data_type = OSSL_PARAM_UTF8_STRING then
           mgfname := param_mgf.data
        else
        if ( 0>= OSSL_PARAM_get_utf8_ptr(param_mgf, @mgfname)) then
            Exit(0);
        if strcasecmp(param_mgf.data,
                       ossl_rsa_mgf_nid2name(default_maskgenalg_nid ) ) <> 0 then
            Exit(0);
    end;
    {
     * We're only interested in the NIDs that correspond to the MDs, so the
     * exact propquery is unimportant in the EVP_MD_fetch() calls below.
     }
    if param_md <> nil then
    begin
         mdname := nil;
        if param_md.data_type = OSSL_PARAM_UTF8_STRING then
           mdname := param_md.data
        else
        if ( 0>= OSSL_PARAM_get_utf8_ptr(param_mgf, @mdname)) then
            goto _err ;
        md := EVP_MD_fetch(libctx, mdname, propq) ;
        if  (md = nil)
             or   (0>= ossl_rsa_pss_params_30_set_hashalg(pss_params,
                                                   ossl_rsa_oaeppss_md2nid(md)))  then
            goto _err ;
    end;
    if param_mgf1md <> nil then
    begin
         mgf1mdname := nil;
        if param_mgf1md.data_type = OSSL_PARAM_UTF8_STRING then
           mgf1mdname := param_mgf1md.data
        else
        if (0>= OSSL_PARAM_get_utf8_ptr(param_mgf, @mgf1mdname)) then
            goto _err ;
        mgf1md := EVP_MD_fetch(libctx, mgf1mdname, propq );
        if  (mgf1md = nil)
             or  (0>= ossl_rsa_pss_params_30_set_maskgenhashalg(
                    pss_params, ossl_rsa_oaeppss_md2nid(mgf1md))) then
            goto _err ;
    end;
    if param_saltlen <> nil then
    begin
        if  (0>= OSSL_PARAM_get_int(param_saltlen, @saltlen) )
             or  (0>= ossl_rsa_pss_params_30_set_saltlen(pss_params, saltlen)) then
            goto _err ;
    end;
    ret := 1;
 _err:
    EVP_MD_free(md);
    EVP_MD_free(mgf1md);
    Result := ret;
end;




function sk_BIGNUM_const_num(const sk : Pstack_st_BIGNUM_const):integer;
begin
   Result :=  OPENSSL_sk_num(POPENSSL_STACK ( sk));
end;


function sk_BIGNUM_const_value(const sk : Pstack_st_BIGNUM_const; idx : integer):PBIGNUM;
begin
   Result :=  PBIGNUM(OPENSSL_sk_value(POPENSSL_STACK ( sk), idx)) ;
end;


function sk_BIGNUM_const_new( compare : sk_BIGNUM_const_compfunc):Pstack_st_BIGNUM_const;
begin
   Result :=  Pstack_st_BIGNUM_const (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_BIGNUM_const_new_null:Pstack_st_BIGNUM_const;
begin
   Result :=  Pstack_st_BIGNUM_const (OPENSSL_sk_new_null);
end;


function sk_BIGNUM_const_new_reserve( compare : sk_BIGNUM_const_compfunc; n : integer):Pstack_st_BIGNUM_const;
begin
   Result :=  Pstack_st_BIGNUM_const (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_BIGNUM_const_reserve( sk : Pstack_st_BIGNUM_const; n : integer):integer;
begin
   Result :=  OPENSSL_sk_reserve(POPENSSL_STACK (sk), n);
end;


procedure sk_BIGNUM_const_free( sk : Pstack_st_BIGNUM_const);
begin
        OPENSSL_sk_free(POPENSSL_STACK (sk));
end;


procedure sk_BIGNUM_const_zero( sk : Pstack_st_BIGNUM_const);
begin
        OPENSSL_sk_zero(POPENSSL_STACK (sk));
end;


function sk_BIGNUM_const_delete( sk : Pstack_st_BIGNUM_const; i : integer):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_delete(POPENSSL_STACK (sk), i));
end;


function sk_BIGNUM_const_delete_ptr( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk),
                                           Pointer (ptr)));
end;


function sk_BIGNUM_const_push( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
begin
   Result :=  OPENSSL_sk_push(POPENSSL_STACK (sk), Pointer(ptr) );
end;


function sk_BIGNUM_const_unshift( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
begin
   Result :=  OPENSSL_sk_unshift(POPENSSL_STACK (sk), Pointer (ptr));
end;


function sk_BIGNUM_const_pop( sk : Pstack_st_BIGNUM_const):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_pop(POPENSSL_STACK (sk)));
end;


function sk_BIGNUM_const_shift( sk : Pstack_st_BIGNUM_const):PBIGNUM;
begin
   Result :=  PBIGNUM  (OPENSSL_sk_shift(POPENSSL_STACK (sk)));
end;


procedure sk_BIGNUM_const_pop_free( sk : Pstack_st_BIGNUM_const; freefunc : sk_BIGNUM_const_freefunc);
begin
        OPENSSL_sk_pop_free(POPENSSL_STACK (sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_BIGNUM_const_insert( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM; idx : integer):integer;
begin
   Result :=  OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer (ptr), idx);
end;


function sk_BIGNUM_const_set( sk : Pstack_st_BIGNUM_const; idx : integer; ptr : PBIGNUM):PBIGNUM;
begin
   Result := PBIGNUM(OPENSSL_sk_set(POPENSSL_STACK (sk), idx, Pointer(ptr)));
end;


function sk_BIGNUM_const_find( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
begin
   Result :=  OPENSSL_sk_find(POPENSSL_STACK (sk), Pointer (ptr));
end;


function sk_BIGNUM_const_find_ex( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM):integer;
begin
   Result :=  OPENSSL_sk_find_ex(POPENSSL_STACK (sk), Pointer (ptr));
end;


function sk_BIGNUM_const_find_all( sk : Pstack_st_BIGNUM_const; ptr : PBIGNUM; pnum : PInteger):integer;
begin
   Result :=  OPENSSL_sk_find_all(POPENSSL_STACK (sk), Pointer (ptr), pnum);
end;


procedure sk_BIGNUM_const_sort( sk : Pstack_st_BIGNUM_const);
begin
        OPENSSL_sk_sort(POPENSSL_STACK (sk));
end;


function sk_BIGNUM_const_is_sorted(const sk : Pstack_st_BIGNUM_const):integer;
begin
   Result :=  OPENSSL_sk_is_sorted(POPENSSL_STACK ( sk));
end;


function sk_BIGNUM_const_dup(const sk : Pstack_st_BIGNUM_const):Pstack_st_BIGNUM_const;
begin
   Result :=  Pstack_st_BIGNUM_const (OPENSSL_sk_dup(POPENSSL_STACK ( sk)));
end;


function sk_BIGNUM_const_deep_copy(const sk : Pstack_st_BIGNUM_const; copyfunc : sk_BIGNUM_const_copyfunc; freefunc : sk_BIGNUM_const_freefunc):Pstack_st_BIGNUM_const;
begin
   Result := Pstack_st_BIGNUM_const (OPENSSL_sk_deep_copy(POPENSSL_STACK ( sk),
                                            OPENSSL_sk_copyfunc(copyfunc),
                                            OPENSSL_sk_freefunc(freefunc)));
end;


function sk_BIGNUM_const_set_cmp_func( sk : Pstack_st_BIGNUM_const; compare : sk_BIGNUM_const_compfunc):sk_BIGNUM_const_compfunc;
begin
   Result :=  sk_BIGNUM_const_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK (sk), OPENSSL_sk_compfunc(compare)));
end;


function ossl_rsa_todata( rsa : PRSA; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
  ret       : integer;
  rsa_d,
  rsa_n,
  rsa_e     : PBIGNUM;
  factors,
  exps,
  coeffs    : Pstack_st_BIGNUM_const;
  numprimes,
  numexps,
  numcoeffs : integer;
  label _err;
begin
    ret := 0;
    rsa_d := nil;
    rsa_n := nil;
    rsa_e := nil;
    factors := sk_BIGNUM_const_new_null();
    exps := sk_BIGNUM_const_new_null();
    coeffs := sk_BIGNUM_const_new_null();
    if (rsa = nil)  or  (factors = nil)  or  (exps = nil)  or  (coeffs = nil) then
       goto _err ;
    RSA_get0_key(rsa, @rsa_n, @rsa_e, @rsa_d);
    ossl_rsa_get0_all_params(rsa, factors, exps, coeffs);
    if  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n) )
         or (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e))  then
        goto _err ;
    { Check private key data integrity }
    if rsa_d <> nil then
    begin
        numprimes := sk_BIGNUM_const_num(factors);
        numexps := sk_BIGNUM_const_num(exps);
        numcoeffs := sk_BIGNUM_const_num(coeffs);
        {
         * It's permissible to have zero primes, i.e. no CRT params.
         * Otherwise, there must be at least two, as many exponents,
         * and one coefficient less.
         }
        if (numprimes <> 0)
             and  ( (numprimes < 2)  or  (numexps < 2)  or  (numcoeffs < 1) ) then
            goto _err ;
        if  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D, rsa_d ))  or
            (0>= ossl_param_build_set_multi_key_bn(bld, params,
                                                  @ossl_rsa_mp_factor_names,
                                                  factors) )
             or   (0>= ossl_param_build_set_multi_key_bn(bld, params,
                                                  @ossl_rsa_mp_exp_names, exps))
             or   (0>= ossl_param_build_set_multi_key_bn(bld, params,
                                                  @ossl_rsa_mp_coeff_names,
                                                  coeffs)) then
        goto _err ;
    end;
{$IF defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ACVP_TESTS)}
    { The acvp test results are not meant for export so check for bld = nil }
    if bld = nil then ossl_rsa_acvp_test_get_params(rsa, params);
{$ENDIF}
    ret := 1;
 _err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    Result := ret;
end;


function ossl_rsa_pss_params_30_todata(const pss : PRSA_PSS_PARAMS_30; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
  hashalg_nid,
  maskgenalg_nid,
  maskgenhashalg_nid,
  saltlen,
  default_hashalg_nid,
  default_maskgenalg_nid,
  default_maskgenhashalg_nid : integer;
  mdname,
  mgfname,
  mgf1mdname,
  key_md,
  key_mgf,
  key_mgf1_md,
  key_saltlen                : PUTF8Char;
begin
    if  0>= ossl_rsa_pss_params_30_is_unrestricted(pss)  then
    begin
        hashalg_nid := ossl_rsa_pss_params_30_hashalg(pss);
        maskgenalg_nid := ossl_rsa_pss_params_30_maskgenalg(pss);
        maskgenhashalg_nid := ossl_rsa_pss_params_30_maskgenhashalg(pss);
        saltlen := ossl_rsa_pss_params_30_saltlen(pss);
        default_hashalg_nid := ossl_rsa_pss_params_30_hashalg(nil);
        default_maskgenalg_nid := ossl_rsa_pss_params_30_maskgenalg(nil);
        default_maskgenhashalg_nid :=
                ossl_rsa_pss_params_30_maskgenhashalg(nil);
         mdname := get_result
            (hashalg_nid = default_hashalg_nid
             , nil , ossl_rsa_oaeppss_nid2name(hashalg_nid));
         mgfname := get_result
            (maskgenalg_nid = default_maskgenalg_nid
             , nil , ossl_rsa_oaeppss_nid2name(maskgenalg_nid));
          mgf1mdname := get_result
            (maskgenhashalg_nid = default_maskgenhashalg_nid
             , nil , ossl_rsa_oaeppss_nid2name(maskgenhashalg_nid));
        key_md := OSSL_PKEY_PARAM_RSA_DIGEST;
         key_mgf := OSSL_PKEY_PARAM_RSA_MASKGENFUNC;
        key_mgf1_md := OSSL_PKEY_PARAM_RSA_MGF1_DIGEST;
        key_saltlen := OSSL_PKEY_PARAM_RSA_PSS_SALTLEN;
        {
         * To ensure that the key isn't seen as unrestricted by the recipient,
         * we make sure that at least one PSS-related parameter is passed, even
         }
        if ( (mdname <> nil)
              and (0>= ossl_param_build_set_utf8_string(bld, params, key_md, mdname)) )
             or ( (mgfname <> nil)
                 and (0>= ossl_param_build_set_utf8_string(bld, params,
                                                     key_mgf, mgfname)) )
             or ( (mgf1mdname <> nil)
                 and (0>= ossl_param_build_set_utf8_string(bld, params,
                                                     key_mgf1_md, mgf1mdname)) )
             or  ( 0>= ossl_param_build_set_int(bld, params, key_saltlen, saltlen))  then
            Exit(0);
    end;
    Result := 1;
end;


function rsa_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
begin
    &out^ := BN_dup(f);
    if (f <> nil)  and  (&out^  = nil) then
        Exit(0);
    Result := 1;
end;

function ossl_rsa_is_foreign(const rsa : PRSA):Boolean;
begin
{$IFNDEF FIPS_MODULE}
    if (rsa.engine <> nil)  or
       (RSA_get_method(rsa) <> RSA_PKCS1_OpenSSL()) then
        Exit(true);
{$ENDIF}
    Result := False;
end;

function ossl_rsa_dup(const rsa : PRSA; selection : integer):PRSA;
var
  dupkey : PRSA;
  pinfo, duppinfo: PRSA_PRIME_INFO;
  pnum, i : integer;
  label _err;
begin
    dupkey := nil;
{$IFNDEF FIPS_MODULE}
{$ENDIF}
    { Do not try to duplicate foreign RSA keys }
    if ossl_rsa_is_foreign(rsa)  then
        Exit(nil);
    dupkey := ossl_rsa_new_with_ctx(rsa.libctx);
    if dupkey = nil then
        Exit(nil);
    { public key }
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        if  0>= rsa_bn_dup_check(@dupkey.n, rsa.n) then
            goto _err ;
        if  0>= rsa_bn_dup_check(@dupkey.e, rsa.e) then
            goto _err ;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        { private key }
        if  0>= rsa_bn_dup_check(@dupkey.d, rsa.d) then
            goto _err ;
        { factors and crt params }
        if  (0>= rsa_bn_dup_check(@dupkey.p, rsa.p) ) then
            goto _err ;
        if  (0>= rsa_bn_dup_check(@dupkey.q, rsa.q) ) then
            goto _err ;
        if  (0>= rsa_bn_dup_check(@dupkey.dmp1, rsa.dmp1) ) then
            goto _err ;
        if  (0>= rsa_bn_dup_check(@dupkey.dmq1, rsa.dmq1) ) then
            goto _err ;
        if  (0>= rsa_bn_dup_check(@dupkey.iqmp, rsa.iqmp) ) then
            goto _err ;
    end;
    dupkey.version := rsa.version;
    dupkey.flags := rsa.flags;
    { we always copy the PSS parameters regardless of selection }
    dupkey.pss_params := rsa.pss_params;
{$IFNDEF FIPS_MODULE}
    { multiprime }
    pnum := sk_RSA_PRIME_INFO_num(rsa.prime_infos);
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 )
         and  (pnum > 0)  then
    begin
        dupkey.prime_infos := sk_RSA_PRIME_INFO_new_reserve(nil, pnum);
        if dupkey.prime_infos = nil then goto _err ;
        for i := 0 to pnum-1 do
        begin
            pinfo := nil;
            duppinfo := nil;
            duppinfo := OPENSSL_zalloc(sizeof(duppinfo^ ));
            if duppinfo  = nil then
            begin
                ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            { push first so cleanup in error case works }
            sk_RSA_PRIME_INFO_push(dupkey.prime_infos, duppinfo);
            pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
            if 0>= rsa_bn_dup_check(@duppinfo.r, pinfo.r)  then
                goto _err ;
            if  0>= rsa_bn_dup_check(@duppinfo.d, pinfo.d ) then
                goto _err ;
            if  0>= rsa_bn_dup_check(@duppinfo.t, pinfo.t ) then
                goto _err ;
        end;
        if  0>= ossl_rsa_multip_calc_product(dupkey) then
            goto _err ;
    end;

    if rsa.pss <> nil then
    begin
        dupkey.pss := RSA_PSS_PARAMS_dup(rsa.pss);
        if (rsa.pss.maskGenAlgorithm <> nil )   and
           (dupkey.pss.maskGenAlgorithm = nil) then
        begin
            dupkey.pss.maskHash := ossl_x509_algor_mgf1_decode(rsa.pss.maskGenAlgorithm);
            if dupkey.pss.maskHash = nil then
               goto _err ;
        end;
    end;
    if  0>= CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_RSA,
                            @dupkey.ex_data, @rsa.ex_data ) then
        goto _err ;
{$ENDIF}
    Exit(dupkey);
 _err:
    RSA_free(dupkey);
    Result := nil;
end;

end.
