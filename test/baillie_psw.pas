unit baillie_psw;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api, Variants;

function bn_strong_lucas_test(const n, D : PBIGNUM; ctx : PBN_CTX):integer;
function bn_strong_lucas_selfridge(const n : PBIGNUM; ctx : PBN_CTX):integer;
function bn_is_prime_bpsw(const n : PBIGNUM; in_ctx : PBN_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.test.testutil.tests,
     OpenSSL3.crypto.rsa.rsa_sp800_56b_check, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_add,               openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.rsa.rsa_lib,             OpenSSL3.crypto.rsa.rsa_sp800_56b_gen,
     openssl3.crypto.bn.bn_word,              openssl3.crypto.bn.bn_mul,
     openssl3.test.testutil.driver,           crypto_utils,
     openssl3.crypto.bn.bn_kron,              bpsw_test;


function bn_strong_lucas_test(const n, D : PBIGNUM; ctx : PBN_CTX):integer;
var
  k, U, V : PBIGNUM;
  r, s, ret : integer;
  label _done;
begin
  ret := -1;
  BN_CTX_start(ctx);
  k := BN_CTX_get(ctx);
  if k = nil then
    goto _done;
  U := BN_CTX_get(ctx);
  if U = nil then
    goto _done;
  V := BN_CTX_get(ctx);
  if V = nil then
    goto _done;
  {
   * Factorize n + 1 = k * 2^s with odd k: shift away the s trailing ones
   * of n and set the lowest bit of the resulting number k.
   }
  s := 0;
  while BN_is_bit_set(n, s) > 0 do
    PostInc(s);
  if 0>=BN_rshift(k, n, s) then
    goto _done;
  if 0>=BN_set_bit(k, 0) then
    goto _done;
  {
   * Calculate the Lucas terms U_k and V_k. If either of them is zero,
   * then n is a strong Lucas pseudoprime.
   }
  if 0 >= bn_lucas(U, V, k, D, n, ctx) then
    goto _done;
  if (BN_is_zero(U)) or  (BN_is_zero(V))  then
  begin
    ret := 1;
    goto _done;
  end;
  // Check if any V_{k * d^r} is zero for 1 <= r < s.

  for r := 1 to s-1 do begin
    if 0>=bn_lucas_step(U, V, 0, D, n, ctx) then
      goto _done;
    if BN_is_zero(V) then begin
      ret := 1;
      goto _done;
    end;
  end;
  { If we got here, n is definitely composite. }
  ret := 0;
 _done:
  BN_CTX_end(ctx);
  Result := ret;
end;


function bn_strong_lucas_selfridge(const n : PBIGNUM; ctx : PBN_CTX):integer;
var
  D,
  two            : PBIGNUM;
  jacobi_symbol,
  perfect_square,
  sign,
  ret            : integer;
  label _done;
begin
  ret := -1;
  BN_CTX_start(ctx);
  { If n is a perfect square, it is composite. }
  //if (0>=bn_is_square(&perfect_square, n, ctx))
  //  goto_done;
  //if (perfect_square) {
  //  ret = 0;
  //  goto_done;
  //}
  perfect_square := Unassigned;
  {
   * Find the first element D in the sequence 5, -7, 9, -11, 13, ...
   * such that Jacobi(D, n) = -1 (Selfridge's algorithm).
   }
   D := BN_CTX_get(ctx);
  if D = nil then
    goto _done;
  two := BN_CTX_get(ctx);
  if two = nil then
    goto _done;
  sign := 1;
  if 0>=BN_set_word(D, 5) then
    goto _done;
  if 0>=BN_set_word(two, 2) then
    goto _done;
  while true do
  begin
    { For odd n the Kronecker symbol computes the Jacobi symbol. }
    jacobi_symbol := BN_kronecker(D, n, ctx);
    if jacobi_symbol = -2 then
      goto _done;
    { We found the value for D. }
    if jacobi_symbol = -1 then break;
    { n and D have prime factors in common. }
    if jacobi_symbol = 0 then begin
      ret := 0;
      goto _done;
    end;
    { Subtract or add 2 to follow the sequence described above. }
    sign := -sign;
    if 0>=BN_uadd(D, D, two) then
      goto _done;
    BN_set_negative(D, Int(sign = -1));
  end;
  ret := bn_strong_lucas_test(n, D, ctx);
 _done:
  BN_CTX_end(ctx);
  Result := ret;
end;

const _NUMPRIMES_ = 669;
function bn_is_prime_bpsw(const n : PBIGNUM; in_ctx : PBN_CTX):integer;
var
  ctx : PBN_CTX;
  _mod : BN_ULONG;
  i, ret : integer;
  label _done;
begin
  ctx := in_ctx;
  ret := -1;
  if BN_is_word(n, 2) then  begin
    ret := 1;
    goto _done;
  end;
  if (BN_cmp(n, BN_value_one) <= 0)  or  (not BN_is_odd(n)) then
  begin
    ret := 0;
    goto _done;
  end;
  { Trial divisions with the first 2048 primes. }
  for i := 0 to _NUMPRIMES_ -1 do
  begin
    _mod := BN_mod_word(n, primes[i]);
    if _mod = BN_ULONG(-1) then
      goto _done;
    if _mod = 0 then begin
      ret := Int(BN_is_word(n, primes[i]));
      goto _done;
    end;
  end;
  if ctx = nil then ctx := BN_CTX_new;
  if ctx = nil then goto _done;
  ret := bn_miller_rabin_base_2(n, ctx);
  if ret <= 0 then
    goto _done;
  { XXX - Miller-Rabin for random bases? - see FIPS 186-4, Table C.1. }
  ret := bn_strong_lucas_selfridge(n, ctx);

 _done:
  if ctx <> in_ctx then
     BN_CTX_free(ctx);
  Result := ret;
end;


end.
