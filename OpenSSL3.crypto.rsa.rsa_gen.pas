unit OpenSSL3.crypto.rsa.rsa_gen;

interface
uses OpenSSL.Api, SysUtils;

function RSA_generate_multi_prime_key( rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;
function rsa_keygen( libctx : POSSL_LIB_CTX; rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB; pairwise_test : integer):integer;
function rsa_multiprime_keygen( rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;
function rsa_keygen_pairwise_test( rsa : PRSA; cb : POSSL_CALLBACK; cbarg : Pointer):integer;

function RSA_generate_key_ex( rsa : PRSA; bits : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;

implementation

uses OpenSSL3.Err,                             OpenSSL3.crypto.rsa.rsa_sp800_56b_gen,
     openssl3.crypto.rsa.rsa_sp800_56b_check,  openssl3.providers.fips.fipsprov,
     openssl3.crypto.bn.bn_shift,              openssl3.crypto.self_test_core,
     openssl3.providers.fips.self_test,        openssl3.crypto.bn.bn_gcd,
     openssl3.crypto.bn.bn_mul,                openssl3.crypto.bn.bn_prime,
     openssl3.crypto.bn.bn_add,                openssl3.crypto.bn.bn_lib,
     openssl3.crypto.rsa.rsa_local,            OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.mem,                      openssl3.crypto.rsa.rsa_mp,
     openssl3.crypto.bn.bn_ctx;

function RSA_generate_key_ex( rsa : PRSA; bits : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;
begin
    if Assigned(rsa.meth.rsa_keygen) then
        Exit(rsa.meth.rsa_keygen(rsa, bits, e_value, cb));
    Exit(RSA_generate_multi_prime_key(rsa, bits, RSA_DEFAULT_PRIME_NUM, e_value, cb));
end;

function rsa_keygen_pairwise_test( rsa : PRSA; cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
    ret           : integer;
    ciphertxt_len : uint32;
    ciphertxt     : PByte;
    plaintxt      : array[0..15] of Byte;
    decoded       : PByte;
    decoded_len,
    plaintxt_len  : uint32;
    padding       : integer;
    st            : POSSL_SELF_TEST;
    label _err;
begin
    ret := 0;
    ciphertxt := nil;
    FillChar(plaintxt, 16, 0);

    decoded := nil;
    plaintxt_len := uint32( sizeof(plaintxt_len));
    padding := RSA_PKCS1_PADDING;
    st := nil;
    st := OSSL_SELF_TEST_new(cb, cbarg);
    if st = nil then goto _err ;
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_PCT,
                           OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1);
    ciphertxt_len := RSA_size(rsa);
    {
     * RSA_private_encrypt() and RSA_private_decrypt() requires the 'to'
     * parameter to be a maximum of RSA_size() - allocate space for both.
     }
    ciphertxt := OPENSSL_zalloc(ciphertxt_len * 2);
    if ciphertxt = nil then goto _err ;
    decoded := ciphertxt + ciphertxt_len;
    ciphertxt_len := RSA_public_encrypt(plaintxt_len, @plaintxt, ciphertxt, rsa,
                                       padding);
    if ciphertxt_len <= 0 then goto _err ;
    if (ciphertxt_len = plaintxt_len)
         and  (memcmp(ciphertxt, @plaintxt, plaintxt_len) = 0) then
        goto _err ;
    OSSL_SELF_TEST_oncorrupt_byte(st, ciphertxt);
    decoded_len := RSA_private_decrypt(ciphertxt_len, ciphertxt, decoded, rsa,
                                      padding);
    if (decoded_len <> plaintxt_len)
         or ( memcmp(decoded, @plaintxt,  decoded_len) <> 0) then
        goto _err ;
    ret := 1;
_err:
    OSSL_SELF_TEST_onend(st, ret);
    OSSL_SELF_TEST_free(st);
    OPENSSL_free(ciphertxt);
    Result := ret;
end;


{$ifndef FIPS_MODULE}
function rsa_multiprime_keygen( rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;
var
    r0, r1,
    r2, tmp,
    prime       : PBIGNUM;
    n           : integer;
    bitsr       : array[0..RSA_MAX_PRIME_NUM-1] of integer;
    bitse, i,
    quo, rmd,
    adj, retries: integer;
    pinfo       : PRSA_PRIME_INFO;
    prime_infos : Pstack_st_RSA_PRIME_INFO;
    ctx         : PBN_CTX;
    bitst       : BN_ULONG;
    error       : Cardinal;
    ok, j       : integer;
    prev_prime,
    pr0, d, p   : PBIGNUM;
    label _err,_redo;
begin
    r0 := nil;
    r1 := nil;
    r2 := nil;
    n := 0;
    bitse := 0;
    i := 0;
    quo := 0;
    rmd := 0;
    adj := 0;
    retries := 0;
    pinfo := nil;
    prime_infos := nil;
    ctx := nil;
    bitst := 0;
    error := 0;
    ok := -1;
    if bits < RSA_MIN_MODULUS_BITS then
    begin
        ok := 0;             { we set our own err }
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        goto _err ;
    end;
    { A bad value for e can cause infinite loops }
    if (e_value <> nil)  and  (0>= ossl_rsa_check_public_exponent(e_value)) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        Exit(0);
    end;
    if (primes < RSA_DEFAULT_PRIME_NUM)  or  (primes > ossl_rsa_multip_cap(bits)) then
    begin
        ok := 0;             { we set our own err }
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_PRIME_NUM_INVALID);
        goto _err ;
    end;
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx = nil then goto _err ;
    BN_CTX_start(ctx);
    r0 := BN_CTX_get(ctx);
    r1 := BN_CTX_get(ctx);
    r2 := BN_CTX_get(ctx);
    if r2 = nil then goto _err ;
    { divide bits into 'primes' pieces evenly }
    quo := bits div primes;
    rmd := bits mod primes;
    for i := 0 to primes-1 do
        bitsr[i] := get_result((i < rmd) , quo + 1 , quo);
    Inc(rsa.dirty_cnt);
    { We need the RSA components non-nil }
    if (nil= rsa.n ) then
    begin
       rsa.n := BN_new();
       if rsa.n = nil then
          goto _err ;
    end;
    if nil = rsa.d  then
    begin
         rsa.d := BN_secure_new;
        if rsa.d = nil then
          goto _err ;
    end;
    BN_set_flags(rsa.d, BN_FLG_CONSTTIME);
    if nil = rsa.e  then
    begin
       rsa.e := BN_new() ;
       if rsa.e = nil then
        goto _err ;
    end;
    if nil = rsa.p  then
    begin
        rsa.p := BN_secure_new();
        if (rsa.p = nil) then
           goto _err ;
    end;
    BN_set_flags(rsa.p, BN_FLG_CONSTTIME);
    if nil = rsa.q  then
    begin
       rsa.q := BN_secure_new();
       if rsa.q = nil  then
          goto _err ;
    end;
    BN_set_flags(rsa.q, BN_FLG_CONSTTIME);
    if nil = rsa.dmp1 then
    begin
        rsa.dmp1 := BN_secure_new() ;
        if rsa.dmp1 = nil then
           goto _err ;
    end;
    BN_set_flags(rsa.dmp1, BN_FLG_CONSTTIME);
    if nil = rsa.dmq1  then
    begin
       rsa.dmq1 := BN_secure_new();
       if rsa.dmq1 = nil then
        goto _err ;
    end;
    BN_set_flags(rsa.dmq1, BN_FLG_CONSTTIME);
    if nil = rsa.iqmp  then
    Begin
       rsa.iqmp := BN_secure_new();
       if rsa.iqmp = nil then
        goto _err ;
    End;
    BN_set_flags(rsa.iqmp, BN_FLG_CONSTTIME);
    { initialize multi-prime components }
    if primes > RSA_DEFAULT_PRIME_NUM then
    begin
        rsa.version := RSA_ASN1_VERSION_MULTI;
        prime_infos := sk_RSA_PRIME_INFO_new_reserve(nil, primes - 2);
        if prime_infos = nil then
           goto _err ;
        if rsa.prime_infos <> nil then
        begin
            { could this happen? }
            sk_RSA_PRIME_INFO_pop_free(rsa.prime_infos,
                                       ossl_rsa_multip_info_free);
        end;
        rsa.prime_infos := prime_infos;
        { prime_info from 2 to |primes| -1 }
        for i := 2 to primes-1 do
        begin
            pinfo := ossl_rsa_multip_info_new();
            if pinfo = nil then
               goto _err ;

            sk_RSA_PRIME_INFO_push(prime_infos, pinfo);
        end;
    end;
    if BN_copy(rsa.e, e_value) = nil  then
        goto _err ;
    { generate p, q and other primes (if any) }
    i := 0;
    while i < primes  do
    begin
        adj := 0;
        retries := 0;
        if i = 0 then
        begin
            prime := rsa.p;
        end
        else if (i = 1) then
        begin
            prime := rsa.q;
        end
        else
        begin
            pinfo := sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
            prime := pinfo.r;
        end;
        BN_set_flags(prime, BN_FLG_CONSTTIME);
        while true do
        begin
 _redo:
            if 0>= BN_generate_prime_ex2(prime, bitsr[i] + adj, 0, nil, nil, cb, ctx) then
                goto _err ;
            {
             * prime should not be equal to p, q, r_3...
             * (those primes prior to this one)
             }
            begin
                for j := 0 to i-1 do
                begin
                    if j = 0 then
                       prev_prime := rsa.p
                    else if (j = 1) then
                        prev_prime := rsa.q
                    else
                        prev_prime := sk_RSA_PRIME_INFO_value(prime_infos, j - 2).r;
                    if 0>= BN_cmp(prime, prev_prime) then
                    begin
                        goto _redo ;
                    end;
                end;
            end;
            if 0>= BN_sub(r2, prime, BN_value_one)  then
                goto _err ;
            ERR_set_mark();
            BN_set_flags(r2, BN_FLG_CONSTTIME);
            if BN_mod_inverse(r1, r2, rsa.e, ctx)  <> nil then
            begin
               { GCD = 1 since inverse exists }
                break;
            end;
            error := ERR_peek_last_error();
            if (ERR_GET_LIB(error)    = ERR_LIB_BN )   and
               (ERR_GET_REASON(error) = BN_R_NO_INVERSE)  then
            begin
                { GCD <> 1 }
                ERR_pop_to_mark();
            end
            else
                goto _err ;

            if 0>= BN_GENCB_call(cb, 2, PostInc(n)) then
                goto _err ;
        end;
        bitse  := bitse + (bitsr[i]);
        { calculate n immediately to see if it's sufficient }
        if i = 1 then
        begin
            { we get at least 2 primes }
            if 0>= BN_mul(r1, rsa.p, rsa.q, ctx) then
                goto _err ;
        end
        else if (i <> 0) then
        begin
            { modulus n = p * q * r_3 * r_4 ... }
            if 0>= BN_mul(r1, rsa.n, prime, ctx ) then
                goto _err ;
        end
        else
        begin
            { i = 0, do nothing }
            if 0>= BN_GENCB_call(cb, 3, i) then
                goto _err ;
            continue;
        end;
        {
         * if |r1|, product of factors so far, is not as long as expected
         * (by checking the first 4 bits are less than $9 or greater than
         * $F). If so, re-generate the last prime.
         *
         * NOTE: This actually can't happen in two-prime case, because of
         * the way factors are generated.
         *
         * Besides, another consideration is, for multi-prime case, even the
         * length modulus is as long as expected, the modulus could start at
         * $8, which could be utilized to distinguish a multi-prime private
         * key by using the modulus in a certificate. This is also covered
         * by checking the length should not be less than $9.
         }
        if 0>= BN_rshift(r2, r1, bitse - 4) then
            goto _err ;
        bitst := BN_get_word(r2);
        if (bitst < $9)  or  (bitst > $F) then
        begin
            {
             * For keys with more than 4 primes, we attempt longer factor to
             * meet length requirement.
             *
             * Otherwise, we just re-generate the prime with the same length.
             *
             * This strategy has the following goals:
             *
             * 1. 1024-bit factors are efficient when using 3072 and 4096-bit key
             * 2. stay the same logic with normal 2-prime key
             }
            bitse  := bitse - (bitsr[i]);
            if 0>= BN_GENCB_call(cb, 2, PostInc(n))  then
                goto _err ;
            if primes > 4 then
            begin
                if bitst < $9 then
                   Inc(adj)
                else
                   Dec(adj);
            end
            else
            if (retries = 4) then
            begin
                {
                 * re-generate all primes from scratch, mainly used
                 * in 4 prime case to avoid long loop. Max retry times
                 * is set to 4.
                 }
                i := -1;
                bitse := 0;
                continue;
            end;
            Inc(retries);
            goto _redo ;
        end;
        { save product of primes for further use, for multi-prime only }
        if (i > 1)  and  (BN_copy(pinfo.pp, rsa.n) = nil)  then
            goto _err ;
        if BN_copy(rsa.n, r1)  = nil then
            goto _err ;
        if 0>= BN_GENCB_call(cb, 3, i ) then
            goto _err ;
        Inc(i);
    end;{while i < primes}

    if BN_cmp(rsa.p, rsa.q) < 0  then
    begin
        tmp := rsa.p;
        rsa.p := rsa.q;
        rsa.q := tmp;
    end;
    { calculate d }
    { p - 1 }
    if 0>= BN_sub(r1, rsa.p, BN_value_one) then
        goto _err ;
    { q - 1 }
    if 0>= BN_sub(r2, rsa.q, BN_value_one)  then
        goto _err ;
    { (p - 1)(q - 1) }
    if 0>= BN_mul(r0, r1, r2, ctx) then
        goto _err ;
    { multi-prime }
    for i := 2 to primes-1 do
    begin
        pinfo := sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
        { save r_i - 1 to pinfo.d temporarily }
        if 0>= BN_sub(pinfo.d, pinfo.r, BN_value_one)   then
            goto _err ;
        if 0>= BN_mul(r0, r0, pinfo.d, ctx) then
            goto _err ;
    end;
    begin
        pr0 := BN_new();
        if pr0 = nil then goto _err ;
        BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
        if nil = BN_mod_inverse(rsa.d, rsa.e, pr0, ctx) then
        begin
            BN_free(pr0);
            goto _err ;               { d }
        end;
        { We MUST free pr0 before any further use of r0 }
        BN_free(pr0);
    end;
    begin
        d := BN_new();
        if d = nil then goto _err ;
        BN_with_flags(d, rsa.d, BN_FLG_CONSTTIME);
        { calculate d mod (p-1) and d mod (q - 1) }
        if (0>= BN_mod(rsa.dmp1, d, r1, ctx)) or
           (0>= BN_mod(rsa.dmq1, d, r2, ctx))  then
        begin
            BN_free(d);
            goto _err ;
        end;
        { calculate CRT exponents }
        for i := 2 to primes-1 do
        begin
            pinfo := sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
            { pinfo.d = r_i - 1 }
            if 0>= BN_mod(pinfo.d, d, pinfo.d, ctx) then
            begin
                BN_free(d);
                goto _err ;
            end;
        end;
        { We MUST free d before any further use of rsa.d }
        BN_free(d);
    end;
    begin
        p := BN_new();
        if p = nil then goto _err ;
        BN_with_flags(p, rsa.p, BN_FLG_CONSTTIME);
        { calculate inverse of q mod p }
        if nil = BN_mod_inverse(rsa.iqmp, rsa.q, p, ctx) then
        begin
            BN_free(p);
            goto _err ;
        end;
        { calculate CRT coefficient for other primes }
        for i := 2 to primes-1 do begin
            pinfo := sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
            BN_with_flags(p, pinfo.r, BN_FLG_CONSTTIME);
            if nil = BN_mod_inverse(pinfo.t, pinfo.pp, p, ctx) then
            begin
                BN_free(p);
                goto _err ;
            end;
        end;
        { We MUST free p before any further use of rsa.p }
        BN_free(p);
    end;
    ok := 1;

 _err:
    if ok = -1 then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        ok := 0;
    end;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ok;
end;
{$endif} (* FIPS_MODULE *)

function rsa_keygen( libctx : POSSL_LIB_CTX; rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB; pairwise_test : integer):integer;
var
  ok : integer;
  stcb : POSSL_CALLBACK;
  stcbarg : Pointer;
begin
    ok := 0;
    {
     * Only multi-prime keys or insecure keys with a small key length will use
     * the older rsa_multiprime_keygen().
     }
    if (primes = 2)  and  (bits >= 2048) then
       ok := ossl_rsa_sp800_56b_generate_key(rsa, bits, e_value, cb)
{$IFNDEF FIPS_MODULE}
    else
       ok := rsa_multiprime_keygen(rsa, bits, primes, e_value, cb);
{$endif} { FIPS_MODULE }
{$IFDEF FIPS_MODULE}
    pairwise_test := 1; { FIPS MODE needs to always run the pairwise test }
{$ENDIF}
    if (pairwise_test > 0)  and  (ok > 0) then
    begin
        stcb := nil;
        stcbarg := nil;
        OSSL_SELF_TEST_get_callback(libctx, @stcb, @stcbarg);
        ok := rsa_keygen_pairwise_test(rsa, stcb, stcbarg);
        if 0>= ok then
        begin
            ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT);
            { Clear intermediate results }
            BN_clear_free(rsa.d);
            BN_clear_free(rsa.p);
            BN_clear_free(rsa.q);
            BN_clear_free(rsa.dmp1);
            BN_clear_free(rsa.dmq1);
            BN_clear_free(rsa.iqmp);
            rsa.d := nil;
            rsa.p := nil;
            rsa.q := nil;
            rsa.dmp1 := nil;
            rsa.dmq1 := nil;
            rsa.iqmp := nil;
        end;
    end;
    Result := ok;
end;



function RSA_generate_multi_prime_key( rsa : PRSA; bits, primes : integer; e_value : PBIGNUM; cb : PBN_GENCB):integer;
begin
{$IFNDEF FIPS_MODULE}
    { multi-prime is only supported with the builtin key generation }
    if Assigned(rsa.meth.rsa_multi_prime_keygen) then
    begin
        Exit(rsa.meth.rsa_multi_prime_keygen(rsa, bits, primes, e_value, cb));
    end
    else
    if Assigned(rsa.meth.rsa_keygen) then
    begin
        {
         * However, if rsa.meth implements only rsa_keygen, then we
         * have to honour it in 2-prime case and assume that it wouldn't
         * know what to do with multi-prime key generated by builtin
         * subroutine...
         }
        if primes = 2 then
           Exit(rsa.meth.rsa_keygen(rsa, bits, e_value, cb))
        else
            Exit(0);
    end;
{$endif} { FIPS_MODULE }
    Result := rsa_keygen(rsa.libctx, rsa, bits, primes, e_value, cb, 0);
end;

end.
