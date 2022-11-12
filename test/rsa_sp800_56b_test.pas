unit rsa_sp800_56b_test;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api;

const
    _P            = 15;
    _Q            = 17;
    _E            = 5;
    _N            = _P*_Q;
    DP           = 3;
    DQ           = 13;
    QINV         = 8;

var
    keygen_size : array of integer;

const // 1d arrays
  cav_e : array[0..2] of Byte = (
    $01, $00, $01 );

  cav_p : array[0..127] of Byte = (
    $cf, $72, $1b, $9a, $fd, $0d, $22, $1a, $74, $50, $97, $22, $76, $d8,
    $c0, $c2, $fd, $08, $81, $05, $dd, $18, $21, $99, $96, $d6, $5c, $79,
    $e3, $02, $81, $d7, $0e, $3f, $3b, $34, $da, $61, $c9, $2d, $84, $86,
    $62, $1e, $3d, $5d, $bf, $92, $2e, $cd, $35, $3d, $6e, $b9, $59, $16,
    $c9, $82, $50, $41, $30, $45, $67, $aa, $b7, $be, $ec, $ea, $4b, $9e,
    $a0, $c3, $05, $bc, $4c, $01, $a5, $4b, $bd, $a4, $20, $b5, $20, $d5,
    $59, $6f, $82, $5c, $8f, $4f, $e0, $3a, $4e, $7e, $fe, $44, $f3, $3c,
    $c0, $0e, $14, $2b, $32, $e6, $28, $8b, $63, $87, $00, $c3, $53, $4a,
    $5b, $71, $7a, $5b, $28, $40, $c4, $18, $b6, $77, $0b, $ab, $59, $a4,
    $96, $7d );

  cav_q : array[0..127] of Byte = (
    $fe, $ab, $f2, $7c, $16, $4a, $f0, $8d, $31, $c6, $0a, $82, $e2, $ae,
    $bb, $03, $7e, $7b, $20, $4e, $64, $b0, $16, $ad, $3c, $01, $1a, $d3,
    $54, $bf, $2b, $a4, $02, $9e, $c3, $0d, $60, $3d, $1f, $b9, $c0, $0d,
    $e6, $97, $68, $bb, $8c, $81, $d5, $c1, $54, $96, $0f, $99, $f0, $a8,
    $a2, $f3, $c6, $8e, $ec, $bc, $31, $17, $70, $98, $24, $a3, $36, $51,
    $a8, $54, $c4, $44, $dd, $f7, $7e, $da, $47, $4a, $67, $44, $5d, $4e,
    $75, $f0, $4d, $00, $68, $e1, $4a, $ec, $1f, $45, $f9, $e6, $ca, $38,
    $95, $48, $6f, $dc, $9d, $1b, $a3, $4b, $fd, $08, $4b, $54, $cd, $eb,
    $3d, $ef, $33, $11, $6e, $ce, $e4, $5d, $ef, $a9, $58, $5c, $87, $4d,
    $c8, $cf );

  cav_n : array[0..255] of Byte = (
    $ce, $5e, $8d, $1a, $a3, $08, $7a, $2d, $b4, $49, $48, $f0, $06, $b6,
    $fe, $ba, $2f, $39, $7c, $7b, $e0, $5d, $09, $2d, $57, $4e, $54, $60,
    $9c, $e5, $08, $4b, $e1, $1a, $73, $c1, $5e, $2f, $b6, $46, $d7, $81,
    $ca, $bc, $98, $d2, $f9, $ef, $1c, $92, $8c, $8d, $99, $85, $28, $52,
    $d6, $d5, $ab, $70, $7e, $9e, $a9, $87, $82, $c8, $95, $64, $eb, $f0,
    $6c, $0f, $3f, $e9, $02, $29, $2e, $6d, $a1, $ec, $bf, $dc, $23, $df,
    $82, $4f, $ab, $39, $8d, $cc, $ac, $21, $51, $14, $f8, $ef, $ec, $73,
    $80, $86, $a3, $cf, $8f, $d5, $cf, $22, $1f, $cc, $23, $2f, $ba, $cb,
    $f6, $17, $cd, $3a, $1f, $d9, $84, $b9, $88, $a7, $78, $0f, $aa, $c9,
    $04, $01, $20, $72, $5d, $2a, $fe, $5b, $dd, $16, $5a, $ed, $83, $02,
    $96, $39, $46, $37, $30, $c1, $0d, $87, $c2, $c8, $33, $38, $ed, $35,
    $72, $e5, $29, $f8, $1f, $23, $60, $e1, $2a, $5b, $1d, $6b, $53, $3f,
    $07, $c4, $d9, $bb, $04, $0c, $5c, $3f, $0b, $c4, $d4, $61, $96, $94,
    $f1, $0f, $4a, $49, $ac, $de, $d2, $e8, $42, $b3, $4a, $0b, $64, $7a,
    $32, $5f, $2b, $5b, $0f, $8b, $8b, $e0, $33, $23, $34, $64, $f8, $b5,
    $7f, $69, $60, $b8, $71, $e9, $ff, $92, $42, $b1, $f7, $23, $a8, $a7,
    $92, $04, $3d, $6b, $ff, $f7, $ab, $bb, $14, $1f, $4c, $10, $97, $d5,
    $6b, $71, $12, $fd, $93, $a0, $4a, $3b, $75, $72, $40, $96, $1c, $5f,
    $40, $40, $57, $13 );

  cav_d : array[0..255] of Byte = (
    $47, $47, $49, $1d, $66, $2a, $4b, $68, $f5, $d8, $4a, $24, $fd, $6c,
    $bf, $56, $b7, $70, $f7, $9a, $21, $c8, $80, $9e, $f4, $84, $cd, $88,
    $01, $28, $ea, $50, $ab, $13, $63, $df, $ea, $14, $38, $b5, $07, $42,
    $81, $2f, $da, $e9, $24, $02, $7e, $af, $ef, $74, $09, $0e, $80, $fa,
    $fb, $d1, $19, $41, $e5, $ba, $0f, $7c, $0a, $a4, $15, $55, $a2, $58,
    $8c, $3a, $48, $2c, $c6, $de, $4a, $76, $fb, $72, $b6, $61, $e6, $d2,
    $10, $44, $4c, $33, $b8, $d2, $74, $b1, $9d, $3b, $cd, $2f, $b1, $4f,
    $c3, $98, $bd, $83, $b7, $7e, $75, $e8, $a7, $6a, $ee, $cc, $51, $8c,
    $99, $17, $67, $7f, $27, $f9, $0d, $6a, $b7, $d4, $80, $17, $89, $39,
    $9c, $f3, $d7, $0f, $df, $b0, $55, $80, $1d, $af, $57, $2e, $d0, $f0,
    $4f, $42, $69, $55, $bc, $83, $d6, $97, $83, $7a, $e6, $c6, $30, $6d,
    $3d, $b5, $21, $a7, $c4, $62, $0a, $20, $ce, $5e, $5a, $17, $98, $b3,
    $6f, $6b, $9a, $eb, $6b, $a3, $c4, $75, $d8, $2b, $dc, $5c, $6f, $ec,
    $5d, $49, $ac, $a8, $a4, $2f, $b8, $8c, $4f, $2e, $46, $21, $ee, $72,
    $6a, $0e, $22, $80, $71, $c8, $76, $40, $44, $61, $16, $bf, $a5, $f8,
    $89, $c7, $e9, $87, $df, $bd, $2e, $4b, $4e, $c2, $97, $53, $e9, $49,
    $1c, $05, $b0, $0b, $9b, $9f, $21, $19, $41, $e9, $f5, $61, $d7, $33,
    $2e, $2c, $94, $b8, $a8, $9a, $3a, $cc, $6a, $24, $8d, $19, $13, $ee,
    $b9, $b0, $48, $61 );


function setup_tests:integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.test.testutil.tests,
     OpenSSL3.crypto.rsa.rsa_sp800_56b_check, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_add,               openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.rsa.rsa_lib,             OpenSSL3.crypto.rsa.rsa_sp800_56b_gen,
     openssl3.crypto.bn.bn_word,              openssl3.crypto.bn.bn_mul,
     openssl3.test.testutil.driver;

function bn_load_new(const data : PByte; sz : integer):PBIGNUM;
begin
    result := BN_new;
    if result <> nil then
       BN_bin2bn(data, sz, result);

end;


function test_check_public_exponent:integer;
var
  ret : Boolean;
  e : PBIGNUM;
begin
    ret := Boolean(0);
    e := nil;
    e := BN_new();
    ret := (TEST_ptr('e = BN_new', e) > 0)
          { e is too small will fail }
           and  (TEST_true('BN_set_word(e, 1)', BN_set_word(e, 1)) > 0)
           and  (TEST_false('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e)) > 0)
          { e is even will fail }
           and  (TEST_true('BN_set_word(e, 65536)', BN_set_word(e, 65536)) > 0)
           and  (TEST_false('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e))  > 0)
          { e is ok }
           and  (TEST_true('BN_set_word(e, 3)', BN_set_word(e, 3)) > 0)
           and  (TEST_true('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e)) > 0)
           and  (TEST_true('BN_set_word(e, 17)', BN_set_word(e, 17)) > 0)
           and  (TEST_true('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e)) > 0)
           and  (TEST_true('BN_set_word(e, 65537)', BN_set_word(e, 65537)) > 0)
           and  (TEST_true('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e)) > 0)
          { e = 2^256 + 1 is ok }
           and  (TEST_true('BN_lshift(e, BN_value_one, 256)', BN_lshift(e, BN_value_one, 256)) > 0)
           and  (TEST_true('BN_add(e, e, BN_value_one)', BN_add(e, e, BN_value_one)) > 0)
           and  (TEST_true('ossl_rsa_check_public_exponent(e)', ossl_rsa_check_public_exponent(e)) > 0);
    BN_free(e);
    Result := Int(ret);
end;


function test_check_prime_factor_range:integer;
const
  p1 : array[0..4] of Byte = ($0B, $50, $4F, $33, $3F );
  p2 : array[0..4] of Byte = ($10, $00, $00, $00, $00 );
  p3 : array[0..4] of Byte = ($0B, $50, $4F, $33, $40 );
  p4 : array[0..4] of Byte = ($0F, $FF, $FF, $FF, $FF );
var
  ret : Boolean;
  ctx : PBN_CTX;
  p, bn_p1, bn_p2, bn_p3, bn_p4 : PBIGNUM;

begin
    ret := Boolean(0);
    ctx := nil;
    p := nil;
    bn_p1 := nil; bn_p2 := nil; bn_p3 := nil; bn_p4 := nil;
    { Some range checks that are larger than 32 bits }
     
    { (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   $B.504F <= p <= $F
     * for 72 bits:  $B504F333F. <= p <= $F_FFFF_FFFF
     }
    p := BN_new();
    bn_p1 := bn_load_new(@p1, sizeof(p1));
    bn_p2 := bn_load_new(@p2, sizeof(p2));
    bn_p3 := bn_load_new(@p3, sizeof(p3));
    bn_p4 := bn_load_new(@p4, sizeof(p4));
    ctx := BN_CTX_new();
    ret := (TEST_ptr('p = BN_new', p) > 0)
           and  (TEST_ptr('bn_p1 = bn_load_new(p1, sizeof(p1))', bn_p1) > 0)
           and  (TEST_ptr('bn_p2 = bn_load_new(p2, sizeof(p2))', bn_p2) > 0)
           and  (TEST_ptr('bn_p3 = bn_load_new(p3, sizeof(p3))', bn_p3) > 0)
           and  (TEST_ptr('bn_p4 = bn_load_new(p4, sizeof(p4))', bn_p4) > 0)
           and  (TEST_ptr('ctx = BN_CTX_new', ctx) > 0)
           and  (TEST_true('BN_set_word(p, $A)', BN_set_word(p, $A)) > 0)
           and  (TEST_false('1-ossl_rsa_check_prime_factor_range', ossl_rsa_check_prime_factor_range(p, 8, ctx)) > 0)
           and  (TEST_true('BN_set_word(p, $10)', BN_set_word(p, $10)) > 0)
           and  (TEST_false('2-ossl_rsa_check_prime_factor_range', ossl_rsa_check_prime_factor_range(p, 8, ctx)) > 0)
           and  (TEST_true('BN_set_word(p, $B)', BN_set_word(p, $B)) > 0)
           and  (TEST_false('3-ossl_rsa_check_prime_factor_range', ossl_rsa_check_prime_factor_range(p, 8, ctx)) > 0)
           and  (TEST_true('BN_set_word(p, $C)', BN_set_word(p, $C)) > 0)
           and  (TEST_true('4-ossl_rsa_check_prime_factor_range', ossl_rsa_check_prime_factor_range(p, 8, ctx)) > 0)
           and  (TEST_true('BN_set_word(p, $F)', BN_set_word(p, $F)) > 0)
           and  (TEST_true('5-ossl_rsa_check_prime_factor_range',ossl_rsa_check_prime_factor_range(p, 8, ctx)) > 0)
           and  (TEST_false('6-ossl_rsa_check_prime_factor_range',ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx)) > 0)
           and  (TEST_false('7-ossl_rsa_check_prime_factor_range',ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx)) > 0)
           and  (TEST_true('8-ossl_rsa_check_prime_factor_range',ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx)) > 0)
           and  (TEST_true('9-ossl_rsa_check_prime_factor_range',ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx)) > 0);
    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;


function test_check_prime_factor:integer;
const
  p1 : array[0..4] of Byte = ($0B, $50, $4f, $33, $73 );
  p2 : array[0..4] of Byte = ($0B, $50, $4f, $33, $75 );
  p3 : array[0..4] of Byte = ($0F, $50, $00, $03, $75 );
var
  ret : Boolean;
  ctx : PBN_CTX;
  p, bn_p1, bn_p2, bn_p3, e : PBIGNUM;
begin
    ret := Boolean(0);
    ctx := nil;
    p := nil; e := nil;
    bn_p1 := nil; bn_p2 := nil; bn_p3 := nil;
    { Some range checks that are larger than 32 bits }
    p := BN_new();
    bn_p1 := bn_load_new(@p1, sizeof(p1));
    bn_p2 := bn_load_new(@p2, sizeof(p2));
    bn_p3 := bn_load_new(@p3, sizeof(p3));
    e := BN_new();
    ctx := BN_CTX_new();
    ret := (TEST_ptr('p = BN_new', p) > 0)
           and  (TEST_ptr('bn_p1 = bn_load_new(p1, sizeof(p1))', bn_p1)> 0)
           and  (TEST_ptr('bn_p2 = bn_load_new(p2, sizeof(p2))', bn_p2)> 0)
           and  (TEST_ptr('bn_p3 = bn_load_new(p3, sizeof(p3))', bn_p3)> 0)
           and  (TEST_ptr('e = BN_new', e) > 0)
           and  (TEST_ptr('ctx = BN_CTX_new', ctx)> 0)
          { Fails the prime (TEST }
           and  (TEST_true('BN_set_word(e, $1)', BN_set_word(e, $1)) > 0)
           //and  (TEST_false('1-ossl_rsa_check_prime_factor', ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))> 0)
          { p is prime and in range and gcd(p-1, e) = 1 }
           and  (TEST_true('2-ossl_rsa_check_prime_factor', ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx)) > 0)
          { gcd(p-1,e) = 1 (TEST fails }
           and  (TEST_true('BN_set_word(e, $2)', BN_set_word(e, $2))> 0)
           and  (TEST_false('3-ossl_rsa_check_prime_factor', ossl_rsa_check_prime_factor(p, e, 72, ctx))> 0)
          { p fails the range check }
           and  (TEST_true('BN_set_word(e, $1)', BN_set_word(e, $1)) > 0)
           and  (TEST_false('4-ossl_rsa_check_prime_factor', ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx)) > 0);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;


function test_check_private_exponent:integer;
var
  ret : Boolean;
  key : PRSA;
  ctx : PBN_CTX;
  p, q, e, d, n : PBIGNUM;
  label _end;
begin
    ret := Boolean(0);
    key := nil;
    ctx := nil;
    p := nil; q := nil; e := nil; d := nil; n := nil;
    key := RSA_new();
    ctx := BN_CTX_new();
    p := BN_new();
    q := BN_new();
    ret := (TEST_ptr('key = RSA_new', key) > 0)
           and  (TEST_ptr('ctx = BN_CTX_new', ctx) > 0)
           and  (TEST_ptr('p = BN_new', p) > 0)
           and  (TEST_ptr('q = BN_new', q) > 0)
          { lcm(15-1,17-1) = 14*16 / 2 = 112 }
           and  (TEST_true('BN_set_word(p, 15)', BN_set_word(p, 15))> 0)
           and  (TEST_true('BN_set_word(q, 17)', BN_set_word(q, 17))> 0)
           and  (TEST_true('RSA_set0_factors(key, p, q)', RSA_set0_factors(key, p, q))> 0);
    if not ret then
    begin
        BN_free(p);
        BN_free(q);
        goto _end;
    end;
    e := BN_new();
    d := BN_new();
    n := BN_new();
    ret := (TEST_ptr('e = BN_new', e) > 0)
           and  (TEST_ptr('d = BN_new', d) > 0)
           and  (TEST_ptr('n = BN_new', n) > 0)
           and  (TEST_true('BN_set_word(e, 5)', BN_set_word(e, 5)) > 0)
           and  (TEST_true('BN_set_word(d, 157)', BN_set_word(d, 157)) > 0)
           and  (TEST_true('BN_set_word(n, 15*17)', BN_set_word(n, 15*17))> 0)
           and  (TEST_true('RSA_set0_key(key, n, e, d)', RSA_set0_key(key, n, e, d))> 0);
    if not ret then
    begin
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto _end;
    end;
    { fails since d >= lcm(p-1, q-1) }
    ret := (TEST_false('ossl_rsa_check_private_exponent', ossl_rsa_check_private_exponent(key, 8, ctx))> 0)
           and  (TEST_true('BN_set_word(d, 45)', BN_set_word(d, 45)) > 0)
          { d is correct size and 1 = e.d mod lcm(p-1, q-1) }
           and  (TEST_true('ossl_rsa_check_private_exponent', ossl_rsa_check_private_exponent(key, 8, ctx))> 0)
          { d is too small compared to nbits }
           and  (TEST_false('ossl_rsa_check_private_exponent', ossl_rsa_check_private_exponent(key, 16, ctx))> 0)
          { d is too small compared to nbits }
           and  (TEST_true('BN_set_word(d, 16)', BN_set_word(d, 16)) > 0)
           and  (TEST_false('ossl_rsa_check_private_exponent', ossl_rsa_check_private_exponent(key, 8, ctx))> 0)
          { fail if 1 <> e.d mod lcm(p-1, q-1) }
           and  (TEST_true('BN_set_word(d, 46)', BN_set_word(d, 46))> 0)
           and  (TEST_false('ossl_rsa_check_private_exponent', ossl_rsa_check_private_exponent(key, 8, ctx))> 0);
_end:
    RSA_free(key);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;


function test_check_crt_components:integer;
var
  ret : Boolean;
  key : PRSA;
  ctx : PBN_CTX;
  p, q, e : PBIGNUM;
  label _end;
begin
    ret := Boolean(0);
    key := nil;
    ctx := nil;
    p := nil; q := nil; e := nil;
    key := RSA_new();
    ctx := BN_CTX_new();
    p := BN_new();
    q := BN_new();
    e := BN_new();
    ret := (TEST_ptr('key = RSA_new', key) > 0)
           and  (TEST_ptr('ctx = BN_CTX_new', ctx)> 0)
           and  (TEST_ptr('p = BN_new', p) > 0)
           and  (TEST_ptr('q = BN_new', q) > 0)
           and  (TEST_ptr('e = BN_new', e) > 0)
           and  (TEST_true('BN_set_word(p, P)', BN_set_word(p, _P)) > 0)
           and  (TEST_true('BN_set_word(q, Q)', BN_set_word(q, _Q)) > 0)
           and  (TEST_true('BN_set_word(e, E)', BN_set_word(e, _E)) > 0)
           and  (TEST_true('RSA_set0_factors(key, p, q)', RSA_set0_factors(key, p, q)) > 0);
    if not ret then begin
        BN_free(p);
        BN_free(q);
        goto _end;
    end;
    ret := (TEST_true('ossl_rsa_sp800_56b_derive_params_from_pq', ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx))> 0)
           and  (TEST_BN_eq_word('key.n', 'N', key.n, _N) > 0)
           and  (TEST_BN_eq_word('key.dmp1', 'DP', key.dmp1, DP) > 0)
           and  (TEST_BN_eq_word('key.dmq1', 'DQ', key.dmq1, DQ) > 0)
           and  (TEST_BN_eq_word('key.iqmp', 'QINV', key.iqmp, QINV)> 0)
           and  (TEST_true('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
          { (a) 1 < dP < (p – 1). }
           and  (TEST_true('BN_set_word(key.dmp1, 1)', BN_set_word(key.dmp1, 1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmp1, P-1)', BN_set_word(key.dmp1, _P-1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmp1, DP)', BN_set_word(key.dmp1, DP))> 0)
          { (b) 1 < dQ < (q - 1). }
           and  (TEST_true('BN_set_word(key.dmq1, 1)', BN_set_word(key.dmq1, 1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmq1, Q-1)', BN_set_word(key.dmq1, _Q-1))> 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmq1, DQ)', BN_set_word(key.dmq1, DQ))> 0)
          { (c) 1 < qInv < p }
           and  (TEST_true('BN_set_word(key.iqmp, 1)', BN_set_word(key.iqmp, 1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx))> 0)
           and  (TEST_true('BN_set_word(key.iqmp, _P)', BN_set_word(key.iqmp, _P)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.iqmp, QINV)', BN_set_word(key.iqmp, QINV)) > 0)
          { (d) 1 = (dP . e) mod (p - 1)}
           and  (TEST_true('BN_set_word(key.dmp1, DP+1)', BN_set_word(key.dmp1, DP+1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmp1, DP)', BN_set_word(key.dmp1, DP)) > 0)
          { (e) 1 = (dQ . e) mod (q - 1) }
           and  (TEST_true('BN_set_word(key.dmq1, DQ-1)', BN_set_word(key.dmq1, DQ-1)) > 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx)) > 0)
           and  (TEST_true('BN_set_word(key.dmq1, DQ)', BN_set_word(key.dmq1, DQ)) > 0)
          { (f) 1 = (qInv . q) mod p }
           and  (TEST_true('BN_set_word(key.iqmp, QINV+1)', BN_set_word(key.iqmp, QINV+1))> 0)
           and  (TEST_false('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx))> 0)
           and  (TEST_true('BN_set_word(key.iqmp, QINV)', BN_set_word(key.iqmp, QINV))> 0)
          { check defaults are still valid }
           and  (TEST_true('ossl_rsa_check_crt_components(key, ctx)', ossl_rsa_check_crt_components(key, ctx))> 0);
_end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;


function test_pq_diff:integer;
var
  ret : Boolean;
  tmp, p, q : PBIGNUM;
begin
    ret := Boolean(0);
    tmp := nil; p := nil; q := nil;
    tmp := BN_new();
    p   := BN_new();
    q   := BN_new();
    ret := (TEST_ptr('tmp = BN_new', tmp) > 0)
           and  (TEST_ptr('p = BN_new', p)> 0)
           and  (TEST_ptr('q = BN_new', q) > 0)
          { |1-(2+1)| > 2^1 }
           and  (TEST_true('BN_set_word(p, 1)', BN_set_word(p, 1))> 0)
           and  (TEST_true('BN_set_word(q, 1+2)', BN_set_word(q, 1+2)) > 0)
           and  (TEST_false('ossl_rsa_check_pminusq_diff', ossl_rsa_check_pminusq_diff(tmp, p, q, 202)) > 0)
          { Check |p - q| > 2^(nbits/2 - 100) }
           and  (TEST_true('BN_set_word(q, 1+3)', BN_set_word(q, 1+3)) > 0)
           and  (TEST_true('ossl_rsa_check_pminusq_diff', ossl_rsa_check_pminusq_diff(tmp, p, q, 202)) > 0)
           and  (TEST_true('BN_set_word(p, 1+3)', BN_set_word(p, 1+3)) > 0)
           and  (TEST_true('BN_set_word(q, 1)', BN_set_word(q, 1))> 0)
           and  (TEST_true('ossl_rsa_check_pminusq_diff', ossl_rsa_check_pminusq_diff(tmp, p, q, 202))> 0);
    BN_free(p);
    BN_free(q);
    BN_free(tmp);
    Result := Int(ret);
end;


function test_invalid_keypair:integer;
var
  ret : Boolean;
  key : PRSA;
  ctx : PBN_CTX;
  p,q,n,e,d : PBIGNUM;
  label _end;
begin
    ret := boolean(0);
    key := nil;
    ctx := nil;
    p := nil; q := nil; n := nil; e := nil; d := nil;
    key := RSA_new();
    ctx := BN_CTX_new();
    p := bn_load_new(@cav_p, sizeof(cav_p));
    q := bn_load_new(@cav_q, sizeof(cav_q));
    ret := (TEST_ptr('key = RSA_new', key) > 0)
           and  (TEST_ptr('ctx = BN_CTX_new', ctx) > 0)
          { nil parameters }
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 2048)) > 0)
          { load key }
           and  (TEST_ptr('p = bn_load_new(cav_p, sizeof(cav_p))', p)> 0)
           and  (TEST_ptr('q = bn_load_new(cav_q, sizeof(cav_q))', q)> 0)
           and  (TEST_true('RSA_set0_factors(key, p, q)', RSA_set0_factors(key, p, q))> 0);
    if not ret then begin
        BN_free(p);
        BN_free(q);
        goto _end;
    end;
    e := bn_load_new(@cav_e, sizeof(cav_e));
    n := bn_load_new(@cav_n, sizeof(cav_n));
    d := bn_load_new(@cav_d, sizeof(cav_d));
    ret := (TEST_ptr('e = bn_load_new(cav_e, sizeof(cav_e))', e)> 0)
           and  (TEST_ptr('n = bn_load_new(cav_n, sizeof(cav_n))', n)> 0)
           and  (TEST_ptr('d = bn_load_new(cav_d, sizeof(cav_d))', d)> 0)
           and  (TEST_true('RSA_set0_key(key, n, e, d)', RSA_set0_key(key, n, e, d))> 0);
    if not ret then begin
        BN_free(e);
        BN_free(n);
        BN_free(d);
        goto _end;
    end;
          { bad strength/key size }
    ret := (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, 100, 2048))> 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, 112, 1024)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, 128, 2048))> 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, 140, 3072))> 0)
          { mismatching exponent }
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, BN_value_one,
                                                         -1, 2048))> 0)
          { bad exponent }
           and  (TEST_true('BN_add_word(e, 1)', BN_add_word(e, 1)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 2048))> 0)
           and  (TEST_true('BN_sub_word(e, 1)', BN_sub_word(e, 1))> 0)
          { mismatch between bits and modulus }
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 3072))> 0)
           and  (TEST_true('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, e, 112, 2048))> 0)
          { check n = pq failure }
           and  (TEST_true('BN_add_word(n, 1)', BN_add_word(n, 1)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 2048))> 0)
           and  (TEST_true('BN_sub_word(n, 1)', BN_sub_word(n, 1)) > 0)
          { check p  }
           and  (TEST_true('BN_sub_word(p, 2)', BN_sub_word(p, 2)) > 0)
           and  (TEST_true('BN_mul(n, p, q, ctx)', BN_mul(n, p, q, ctx)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 2048))> 0)
           and  (TEST_true('BN_add_word(p, 2)', BN_add_word(p, 2)) > 0)
           and  (TEST_true('BN_mul(n, p, q, ctx)', BN_mul(n, p, q, ctx)) > 0)
          { check q  }
           and  (TEST_true('BN_sub_word(q, 2)', BN_sub_word(q, 2)) > 0)
           and  (TEST_true('BN_mul(n, p, q, ctx)', BN_mul(n, p, q, ctx)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, 2048)) > 0)
           and  (TEST_true('BN_add_word(q, 2)', BN_add_word(q, 2)) > 0)
           and  (TEST_true('BN_mul(n, p, q, ctx)', BN_mul(n, p, q, ctx))> 0);
_end:
    RSA_free(key);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;


function test_sp80056b_keygen( id : integer):integer;
var
  key : PRSA;
  ret: Boolean;
  sz : integer;
begin
    key := nil;
    sz := keygen_size[id];
    key := RSA_new();
    ret := (TEST_ptr('key = RSA_new', key) > 0)
           and  (TEST_true('ossl_rsa_sp800_56b_generate_key', ossl_rsa_sp800_56b_generate_key(key, sz, nil, nil))> 0)
           and  (TEST_true('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key))> 0)
           and  (TEST_true('ossl_rsa_sp800_56b_check_private(key)', ossl_rsa_sp800_56b_check_private(key)) >0 )
           and  (TEST_true('ossl_rsa_sp800_56b_check_keypair', ossl_rsa_sp800_56b_check_keypair(key, nil, -1, sz))> 0);
    RSA_free(key);
    Result := Int(ret);
end;


function TEST_check_private_key:integer;
var
  ret : Boolean;
  n, d, e : PBIGNUM;
  key : PRSA;
  label _end ;
begin
    ret := Boolean(0);
    n := nil; d := nil; e := nil;
    key := nil;
    key := RSA_new();
    n := bn_load_new(@cav_n, sizeof(cav_n));
    d := bn_load_new(@cav_d, sizeof(cav_d));
    e := bn_load_new(@cav_e, sizeof(cav_e));
    ret := (TEST_ptr('key = RSA_new', key) > 0)
          { check nil pointers fail }
           and  (TEST_false('ossl_rsa_sp800_56b_check_private(key)', ossl_rsa_sp800_56b_check_private(key)) > 0)
          { load private key }
           and  (TEST_ptr('n = bn_load_new(cav_n, sizeof(cav_n))', n) > 0)
           and  (TEST_ptr('d = bn_load_new(cav_d, sizeof(cav_d))', d) > 0)
           and  (TEST_ptr('e = bn_load_new(cav_e, sizeof(cav_e))', e) > 0)
           and  (TEST_true('RSA_set0_key(key, n, e, d)', RSA_set0_key(key, n, e, d)) > 0);
    if not ret then begin
        BN_free(n);
        BN_free(e);
        BN_free(d);
        goto _end;
    end;
    { check d is in range }
    ret := (TEST_true('ossl_rsa_sp800_56b_check_private', ossl_rsa_sp800_56b_check_private(key)) > 0)
          { check d is too low }
           and  (TEST_true('BN_set_word(d, 0)', BN_set_word(d, 0)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_private', ossl_rsa_sp800_56b_check_private(key)) > 0)
          { check d is too high }
           and  (TEST_ptr('BN_copy(d, n)', BN_copy(d, n)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_private', ossl_rsa_sp800_56b_check_private(key)) > 0);
_end:
    RSA_free(key);
    Result := Int(ret);
end;


function TEST_check_public_key:integer;
var
  ret : Boolean;
  n, e : PBIGNUM;
  key : PRSA;
  label _end ;
begin
    ret := Boolean(0);
    n := nil; e := nil;
    key := nil;
    key := RSA_new();
    e := bn_load_new(@cav_e, sizeof(cav_e));
    n := bn_load_new(@cav_n, sizeof(cav_n));
    ret := (TEST_ptr('key = RSA_new', key) > 0)
          { check nil pointers fail }
           and  (TEST_false('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key))> 0)
          { load public key }
           and  (TEST_ptr('e = bn_load_new(cav_e, sizeof(cav_e))', e) > 0)
           and  (TEST_ptr('n = bn_load_new(cav_n, sizeof(cav_n))', n)> 0)
           and  (TEST_true('RSA_set0_key(key, n, e, nil)', RSA_set0_key(key, n, e, nil))> 0);
    if not ret then begin
        BN_free(e);
        BN_free(n);
        goto _end;
    end;
    { check public key is valid }
    ret := (TEST_true('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key)) > 0)
          { check fail if n is even }
           and  (TEST_true('BN_add_word(n, 1)', BN_add_word(n, 1))> 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key))> 0)
           and  (TEST_true('BN_sub_word(n, 1)', BN_sub_word(n, 1))> 0)
          { check fail if n is wrong number of bits }
           and  (TEST_true('BN_lshift1(n, n)', BN_lshift1(n, n)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key)) > 0)
           and  (TEST_true('BN_rshift1(n, n)', BN_rshift1(n, n))> 0)
          { (TEST odd exponent fails }
           and  (TEST_true('BN_add_word(e, 1)', BN_add_word(e, 1)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key))> 0)
           and  (TEST_true('BN_sub_word(e, 1)', BN_sub_word(e, 1)) > 0)
          { modulus fails composite check }
           and  (TEST_true('BN_add_word(n, 2)', BN_add_word(n, 2)) > 0)
           and  (TEST_false('ossl_rsa_sp800_56b_check_public(key)', ossl_rsa_sp800_56b_check_public(key))> 0);
_end:
    RSA_free(key);
    Result := Int(ret);
end;


function setup_tests:integer;
begin
    ADD_TEST('test_check_public_exponent', test_check_public_exponent);
    ADD_TEST('test_check_prime_factor_range', test_check_prime_factor_range);
    ADD_TEST('test_check_prime_factor', test_check_prime_factor);
    ADD_TEST('test_check_private_exponent' ,test_check_private_exponent);
    ADD_TEST('test_check_crt_components', test_check_crt_components);
    ADD_TEST('test_check_private_key', test_check_private_key);
    ADD_TEST('test_check_public_key', test_check_public_key);
    ADD_TEST('test_invalid_keypair', test_invalid_keypair);
    ADD_TEST('test_pq_diff', test_pq_diff);
    ADD_ALL_TESTS('test_sp80056b_keygen', test_sp80056b_keygen, length(keygen_size), 1);
    Result := 1;
end;

initialization
   keygen_size := [2048, 3072];
end.
