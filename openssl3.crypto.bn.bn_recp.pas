unit openssl3.crypto.bn.bn_recp;

interface
uses OpenSSL.Api;

function BN_RECP_CTX_new:PBN_RECP_CTX;
procedure BN_RECP_CTX_free( recp : PBN_RECP_CTX);
function BN_RECP_CTX_set(recp : PBN_RECP_CTX;const d : PBIGNUM; ctx : PBN_CTX):integer;
function BN_mod_mul_reciprocal(r : PBIGNUM;const x, y : PBIGNUM; recp : PBN_RECP_CTX; ctx : PBN_CTX):integer;
function BN_div_recp(dv, rem : PBIGNUM;const m : PBIGNUM; recp : PBN_RECP_CTX; ctx : PBN_CTX):integer;
function BN_reciprocal(r : PBIGNUM;const m : PBIGNUM; len : integer; ctx : PBN_CTX):integer;
procedure BN_RECP_CTX_init(recp : PBN_RECP_CTX);

implementation
uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.bn.bn_div,
     openssl3.crypto.bn.bn_mul,  openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_word, openssl3.crypto.bn.bn_sqr,
     openssl3.crypto.evp.evp_rand, openssl3.crypto.bn.bn_add;


function BN_RECP_CTX_new:PBN_RECP_CTX;
var
  ret : PBN_RECP_CTX;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    bn_init(@(ret.N));
    bn_init(@(ret.Nr));
    ret.flags := BN_FLG_MALLOCED;
    Result := ret;
end;


procedure BN_RECP_CTX_free( recp : PBN_RECP_CTX);
begin
    if recp = nil then exit;
    BN_free(@recp.N);
    BN_free(@recp.Nr);
    if (recp.flags and BN_FLG_MALLOCED)>0 then
       OPENSSL_free(Pointer(recp));
end;


function BN_RECP_CTX_set(recp : PBN_RECP_CTX;const d : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if nil = BN_copy(@recp.N , d) then
        Exit(0);
    BN_zero(@(recp.Nr));
    recp.num_bits := BN_num_bits(d);
    recp.shift := 0;
    Result := 1;
end;


function BN_mod_mul_reciprocal(r : PBIGNUM;const x, y : PBIGNUM; recp : PBN_RECP_CTX; ctx : PBN_CTX):integer;
var
  ret : integer;
  a, ca : PBIGNUM;
  label _err;
begin
    ret := 0;
    BN_CTX_start(ctx);
    a := BN_CTX_get(ctx);
    if a = nil then
        goto _err ;
    if y <> nil then
    begin
        if x = y then
        begin
            if 0>= BN_sqr(a, x, ctx) then
                goto _err ;
        end
        else
        begin
            if 0>= BN_mul(a, x, y, ctx) then
                goto _err ;
        end;
        ca := a;
    end
    else
        ca := x;                 { Just do the mod }
    ret := BN_div_recp(nil, r, ca, recp, ctx);
 _err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    Result := ret;
end;


function BN_div_recp(dv, rem : PBIGNUM;const m : PBIGNUM; recp : PBN_RECP_CTX; ctx : PBN_CTX):integer;
var
  i, j, ret : integer;
  a, b, d, r : PBIGNUM;
  label _err;
begin
    ret := 0;
    BN_CTX_start(ctx);
    if (dv <> nil) then
       d := dv
    else
       d := BN_CTX_get(ctx);
    if (rem <> nil) then
       r :=  rem
    else
       r := BN_CTX_get(ctx);

    a := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    if b = nil then goto _err ;
    if BN_ucmp(m, @recp.N) < 0  then
    begin
        BN_zero(d);
        if nil = BN_copy(r, m) then
        begin
            BN_CTX_end(ctx);
            Exit(0);
        end;
        BN_CTX_end(ctx);
        Exit(1);
    end;
    {
     * We want the remainder Given input of ABCDEF / ab we need multiply
     * ABCDEF by 3 digests of the reciprocal of ab
     }
    { i := max(BN_num_bits(m), 2*BN_num_bits(N)) }
    i := BN_num_bits(m);
    j := recp.num_bits  shl  1;
    if j > i then i := j;
    { Nr := round(2^i / N) }
    if i <> recp.shift then
       recp.shift := BN_reciprocal(@(recp.Nr), @(recp.N), i, ctx);
    { BN_reciprocal could have returned -1 for an error }
    if recp.shift = -1 then
       goto _err ;
    {-
     * d := |round(round(m / 2^BN_num_bits(N)) * recp.Nr / 2^(i - BN_num_bits(N)))|
     *    = |round(round(m / 2^BN_num_bits(N)) * round(2^i / N) / 2^(i - BN_num_bits(N)))|
     *   <= |(m / 2^BN_num_bits(N)) * (2^i / N) * (2^BN_num_bits(N) / 2^i)|
     *    = |m/N|
     }
    if 0>= BN_rshift(a, m, recp.num_bits) then
        goto _err ;
    if 0>= BN_mul(b, a, @recp.Nr , ctx) then
        goto _err ;
    if 0>= BN_rshift(d, b, i - recp.num_bits ) then
        goto _err ;
    d.neg := 0;
    if 0>= BN_mul(b, @recp.N , d, ctx)   then
        goto _err ;
    if 0>= BN_usub(r, m, b  )then
        goto _err ;
    r.neg := 0;
    j := 0;
    while BN_ucmp(r, @(recp.N)) >= 0 do
    begin
        if PostInc(j) > 2  then
        begin
            ERR_raise(ERR_LIB_BN, BN_R_BAD_RECIPROCAL);
            goto _err ;
        end;
        if 0>= BN_usub(r, r, @(recp.N))  then
            goto _err ;
        if 0>= BN_add_word(d, 1) then
            goto _err ;
    end;
    r.neg := get_result(BN_is_zero(r) , 0 , m.neg);
    d.neg := m.neg  xor  recp.N.neg;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    bn_check_top(dv);
    bn_check_top(rem);
    Result := ret;
end;


function BN_reciprocal(r : PBIGNUM;const m : PBIGNUM; len : integer; ctx : PBN_CTX):integer;
var
  ret : integer;
  t : PBIGNUM;
  label _err;
begin
    ret := -1;
    BN_CTX_start(ctx);
    t := BN_CTX_get(ctx);
    if t = nil then
        goto _err ;
    if 0>= BN_set_bit(t, len ) then
        goto _err ;
    if 0>= BN_div(r, nil, t, m, ctx ) then
        goto _err ;
    ret := len;
 _err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    Result := ret;
end;


procedure BN_RECP_CTX_init( recp : PBN_RECP_CTX);
begin
    memset(recp, 0, sizeof( recp^));
    bn_init(@(recp.N));
    bn_init(@(recp.Nr));
end;

end.
