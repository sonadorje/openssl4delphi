unit openssl3.crypto.ffc.ffc_key_generate;

interface
uses OpenSSL.Api;

function ossl_ffc_generate_private_key(ctx : PBN_CTX;const params : PFFC_PARAMS; N, s : integer; priv : PBIGNUM):integer;


implementation
uses
  openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_dh, openssl3.crypto.bn.bn_lib,
  openssl3.crypto.bn.bn_word,
  openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_rand;


function ossl_ffc_generate_private_key(ctx : PBN_CTX;const params : PFFC_PARAMS; N, s : integer; priv : PBIGNUM):integer;
var
  ret, qbits : integer;
  m,
  two_powN : PBIGNUM;
  label _err;
begin
    ret := 0;
    qbits := BN_num_bits(params.q);
    two_powN := nil;
    { Deal with the edge case where the value of N is not set }
    if N = 0 then N := qbits;
    if s = 0 then s := N div 2;
    { Step (2) : check range of N }
    if (N < 2 * s)  or ( N > qbits) then Exit(0);
    two_powN := BN_new();
    { 2^N }
    if (two_powN = nil)  or  (0>= BN_lshift(two_powN, BN_value_one , N)) then
        goto _err ;
    { Step (5) : M = min(2 ^ N, q) }
    if BN_cmp(two_powN, params.q) > 0 then
       m :=  params.q
    else
       m := two_powN;

    while Boolean(1) do
    begin
        { Steps (3, 4 and 7) :  c + 1 = 1 + random[0..2^N - 1] }
        if (0>= BN_priv_rand_range_ex(priv, two_powN, 0, ctx) )  or
           (0>= BN_add_word(priv, 1)) then
            goto _err ;
        { Step (6) : loop if c > M - 2 (i.e. c + 1 >= M) }
        if BN_cmp(priv, m) < 0  then
            break;
    end;

    ret := 1;
_err:
    BN_free(two_powN);
    Result := ret;
end;






end.
