unit ursa_test;

interface
 uses OpenSSL.api;

 type
  rsa_security_bits_cases_st = record
    bits : integer;
    r : uint32;
  end;

  function key1( key : PRSA; c : PByte):integer;
  function key2( key : PRSA; c : PByte):integer;
  function key3( key : PRSA; c : PByte):integer;

function rsa_setkey( key : PPRSA; ctext : PByte; idx : integer):integer;
  function test_rsa_simple( idx, en_pad_type, de_pad_type, success : integer; ctext_ex : PByte; clen : PInteger; retkey : PPRSA):integer;
  function test_rsa_pkcs1( idx : integer):integer;
  function test_rsa_oaep( idx : integer):integer;
  function test_rsa_security_bit( n : integer):integer;
  function setup_tests:integer;




const // 1d arrays
  vals : array[0..7] of Byte = (
    $80, $01, $02, $04, $08, $10, $20, $40 );

  rsa_security_bits_cases: array[0..16] of rsa_security_bits_cases_st = (
    (* NIST SP 800-56B rev 2 (draft) Appendix D Table 5 *)
    (bits: 2048;     r:112 ),
    (bits: 3072;     r:128 ),
    (bits: 4096;     r:152 ),
    (bits: 6144;     r:176 ),
    (bits: 8192;     r:200 ),
    (* NIST FIPS 140-2 IG 7.5 *)
    (bits: 7680;     r:192 ),
    (bits: 15360;    r:256 ),
    (* Older values *)
    (bits: 256;     r: 40  ),
    (bits: 512;     r: 56  ),
    (bits: 1024;     r:80  ),
    (* Some other values *)
    (bits: 8888;     r:208 ),
    (bits: 2468;     r:120 ),
    (bits: 13456;    r:248 ),
    (* Edge points *)
    (bits: 15359;    r:256 ),
    (bits: 15361;    r:264 ),
    (bits: 7679;     r:192 ),
    (bits: 7681;     r:200 )
);
implementation
uses Tests, openssl3.crypto.rsa.rsa_lib,  OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.bn.bn_lib, driver;






function rsa_setkey( key : PPRSA; ctext : PByte; idx : integer):integer;
var
  clen : integer;
begin
    clen := 0;
    key^ := RSA_new;
    if key^ <> nil then
      case idx of
        0:
            clen := key1( key^, ctext);
            //break;
        1:
            clen := key2( key^, ctext);
            //break;
        2:
            clen := key3( key^, ctext);
            //break;
        end;
    Result := clen;
end;


function test_rsa_simple( idx, en_pad_type, de_pad_type, success : integer; ctext_ex : PByte; clen : PInteger; retkey : PPRSA):integer;
var
  ret      : integer;
  key      : PRSA;
  ptext,
  ctext    : array[0..255] of Byte;
  plen,
  clentmp,
  num      : integer;
const
  ptext_ex: array[0..7] of Byte = ($54,$85,$9b,$34,$2c,$49,$ea,$2a);
  label _err;
begin
    ret := 0;
    clentmp := 0;
    plen := sizeof(ptext_ex) - 1;
    clentmp := rsa_setkey(@key, ctext_ex, idx);
    if clen <> nil then
       clen^ := clentmp;
    num := RSA_public_encrypt(plen, @ptext_ex, @ctext, key, en_pad_type);
    if 0>=TEST_int_eq('num', 'clentmp', num, clentmp) then
        goto _err;
    num := RSA_private_decrypt(num, @ctext, @ptext, key, de_pad_type);
    if success > 0 then
    begin
        if (0>=TEST_int_gt('num', '0', num, 0))  or
           (0>=TEST_mem_eq('ptext', 'ptext_ex', @ptext, num, @ptext_ex, plen)) then
            goto _err;
    end
    else
    begin
        if 0>=TEST_int_lt('num', '0', num, 0 ) then
            goto _err;
    end;
    ret := 1;
    if retkey <> nil then begin
        retkey^ := key;
        key := nil;
    end;
_err:
    RSA_free(key);
    Result := ret;
end;


function test_rsa_pkcs1( idx : integer):integer;
begin
    Exit(test_rsa_simple(idx, RSA_PKCS1_PADDING, RSA_PKCS1_PADDING, 1, nil, nil, nil));
end;


function test_rsa_oaep( idx : integer):integer;
var
  ret      : integer;
  key      : PRSA;
  ptext    : array[0..255] of Byte;
  ctext_ex : array[0..255] of Byte;
  plen,
  clen,
  num,
  n        : integer;
const
  ptext_ex: array[0..7] of Byte = ($54,$85,$9b,$34,$2c,$49,$ea,$2a);
  label _err;
begin
    ret := 0;
    key := nil;

    clen := 0;
    if 0>=test_rsa_simple(idx, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_OAEP_PADDING, 1,
                         @ctext_ex, @clen, @key) then
        goto _err;
    plen := sizeof(ptext_ex) - 1;
    { Different ciphertexts. Try decrypting ctext_ex }
    num := RSA_private_decrypt(clen, @ctext_ex, @ptext, key,
                              RSA_PKCS1_OAEP_PADDING);
    if (num <= 0)  or  (0>=TEST_mem_eq('ptext', 'ptext_ex', @ptext, num, @ptext_ex, plen)) then
        goto _err;
    { Try decrypting corrupted ciphertexts. }
    for n := 0 to clen-1 do
    begin
        ctext_ex[n]  := ctext_ex[n] xor 1;
        num := RSA_private_decrypt(clen, @ctext_ex, @ptext, key,
                                      RSA_PKCS1_OAEP_PADDING);
        if 0>=TEST_int_le('num', '0', num, 0) then
            goto _err;
        ctext_ex[n]  := ctext_ex[n] xor 1;
    end;
    { Test truncated ciphertexts, as well as negative length. }
    for n := -1 to clen-1 do
    begin
        num := RSA_private_decrypt(n, @ctext_ex, @ptext, key,
                                  RSA_PKCS1_OAEP_PADDING);
        if 0>=TEST_int_le('num', '0', num, 0) then
            goto _err;
    end;
    ret := 1;
_err:
    RSA_free(key);
    Result := ret;
end;


function test_rsa_security_bit( n : integer):integer;
var
  key : PRSA;
  r, bits, _bytes : integer;
  num : array[0..1999] of Byte;
const
  vals: array[0..7] of Byte = ($80, $01, $02, $04, $08, $10, $20, $40);
  label _err;
begin

    key := RSA_new;
    bits := rsa_security_bits_cases[n].bits;
    result := rsa_security_bits_cases[n].r;
    _bytes := (bits + 7) div 8;

    r := 0;
    if (0>=TEST_ptr('key', key))  or
       (0>=TEST_int_le('bytes', '(int)sizeof(num)', _bytes, sizeof(num))) then
        goto _err;
    {
     * It is necessary to set the RSA key in order to ask for the strength.
     * A BN of an appropriate size is created, in general it won't have the
     * properties necessary for RSA to function.  This is okay here since
     * the RSA key is never used.
     }
    memset(@num, vals[bits mod 8], _bytes);
    {
     * The 'e' parameter is set to the same value as 'n'.  This saves having
     * an extra BN to hold a sensible value for 'e'.  This is safe since the
     * RSA key is not used.  The 'd' parameter can be nil safely.
     }
    if (TEST_true('RSA_set0_key(key, BN_bin2bn(num, bytes, NULL), BN_bin2bn(num, bytes, NULL), NULL)',
                   RSA_set0_key(key, BN_bin2bn(@num, _bytes, nil) ,
                               BN_bin2bn(@num, _bytes, nil), nil)) > 0)
             and  (TEST_uint_eq('RSA_security_bits(key)', 'result',_RSA_security_bits(key), result) > 0) then
        r := 1;
_err:
    RSA_free(key);
    Result := r;
end;


function setup_tests:integer;
begin
    add_all_tests('test_rsa_pkcs1', test_rsa_pkcs1, 3, 1);
    add_all_tests('test_rsa_oaep', test_rsa_oaep, 3, 1);
    add_all_tests('test_rsa_security_bit', test_rsa_security_bit, (sizeof(rsa_security_bits_cases) div sizeof((rsa_security_bits_cases)[0])), 1);
    Result := 1;
end;







function key1( key : PRSA; c : PByte):integer;
const

    n: array[0..64] of Byte = (
        $00,$AA,$36,$AB,$CE,$88,$AC,$FD,$FF,$55,$52,$3C,$7F,$C4,$52,$3F,
        $90,$EF,$A0,$0D,$F3,$77,$4A,$25,$9F,$2E,$62,$B4,$C5,$D9,$9C,$B5,
        $AD,$B3,$00,$A0,$28,$5E,$53,$01,$93,$0E,$0C,$70,$FB,$68,$76,$93,
        $9C,$E6,$16,$CE,$62,$4A,$11,$E0,$08,$6D,$34,$1E,$BC,$AC,$A0,$A1,
        $F5);
    e: array[0..0] of Byte = ($11);
    d: array[0..63] of Byte = (
        $0A,$03,$37,$48,$62,$64,$87,$69,$5F,$5F,$30,$BC,$38,$B9,$8B,$44,
        $C2,$CD,$2D,$FF,$43,$40,$98,$CD,$20,$D8,$A1,$38,$D0,$90,$BF,$64,
        $79,$7C,$3F,$A7,$A2,$CD,$CB,$3C,$D1,$E0,$BD,$BA,$26,$54,$B4,$F9,
        $DF,$8E,$8A,$E5,$9D,$73,$3D,$9F,$33,$B3,$01,$62,$4A,$FD,$1D,$51);
    p: array[0..32] of Byte = (
        $00,$D8,$40,$B4,$16,$66,$B4,$2E,$92,$EA,$0D,$A3,$B4,$32,$04,$B5,
        $CF,$CE,$33,$52,$52,$4D,$04,$16,$A5,$A4,$41,$E7,$00,$AF,$46,$12,
        $0D);
    q: array[0..32] of Byte = (
        $00,$C9,$7F,$B1,$F0,$27,$F4,$53,$F6,$34,$12,$33,$EA,$AA,$D1,$D9,
        $35,$3F,$6C,$42,$D0,$88,$66,$B1,$D0,$5A,$0F,$20,$35,$02,$8B,$9D,
        $89);
    dmp1: array[0..31] of Byte = (
        $59,$0B,$95,$72,$A2,$C2,$A9,$C4,$06,$05,$9D,$C2,$AB,$2F,$1D,$AF,
        $EB,$7E,$8B,$4F,$10,$A7,$54,$9E,$8E,$ED,$F5,$B4,$FC,$E0,$9E,$05);
    dmq1: array[0..32] of Byte = (
        $00,$8E,$3C,$05,$21,$FE,$15,$E0,$EA,$06,$A3,$6F,$F0,$F1,$0C,$99,
        $52,$C3,$5B,$7A,$75,$14,$FD,$32,$38,$B8,$0A,$AD,$52,$98,$62,$8D,
        $51);
    iqmp: array[0..31] of Byte = (
        $36,$3F,$F7,$18,$9D,$A8,$E9,$0B,$1D,$34,$1F,$71,$D0,$9B,$76,$A8,
        $A9,$43,$E1,$1D,$10,$B2,$4D,$24,$9F,$2D,$EA,$FE,$F8,$0C,$18,$26);
    ctext_ex: array[0..63] of Byte = (
        $1b,$8f,$05,$f9,$ca,$1a,$79,$52,$6e,$53,$f3,$cc,$51,$4f,$db,$89,
        $2b,$fb,$91,$93,$23,$1e,$78,$b9,$92,$e6,$8d,$50,$a4,$80,$cb,$52,
        $33,$89,$5c,$74,$95,$8d,$5d,$02,$ab,$8c,$0f,$d0,$40,$eb,$58,$44,
        $b0,$05,$c3,$9e,$d8,$27,$4a,$9d,$bf,$a8,$06,$71,$40,$94,$39,$d2);

begin
     RSA_set0_key(key,
                     BN_bin2bn(@n, sizeof(n)-1, nil),
                     BN_bin2bn(@e, sizeof(e)-1, nil),
                     BN_bin2bn(@d, sizeof(d)-1, nil));
        RSA_set0_factors(key,
                         BN_bin2bn(@p, sizeof(p)-1, nil),
                         BN_bin2bn(@q, sizeof(q)-1, nil));
        RSA_set0_crt_params(key,
                            BN_bin2bn(@dmp1, sizeof(dmp1)-1, nil),
                            BN_bin2bn(@dmq1, sizeof(dmq1)-1, nil),
                            BN_bin2bn(@iqmp, sizeof(iqmp)-1, nil));
        if c <> nil then
           memcpy(c, @ctext_ex, sizeof(ctext_ex) - 1);
        Result := sizeof(ctext_ex) - 1;

end;


function key2( key : PRSA; c : PByte):integer;
const
    n: array[0..50] of Byte = (
        $00,$A3,$07,$9A,$90,$DF,$0D,$FD,$72,$AC,$09,$0C,$CC,$2A,$78,$B8,
        $74,$13,$13,$3E,$40,$75,$9C,$98,$FA,$F8,$20,$4F,$35,$8A,$0B,$26,
        $3C,$67,$70,$E7,$83,$A9,$3B,$69,$71,$B7,$37,$79,$D2,$71,$7B,$E8,
        $34,$77,$CF);
   e: array[0..0] of Byte = ($3);
   d: array[0..49] of Byte = (
        $6C,$AF,$BC,$60,$94,$B3,$FE,$4C,$72,$B0,$B3,$32,$C6,$FB,$25,$A2,
        $B7,$62,$29,$80,$4E,$68,$65,$FC,$A4,$5A,$74,$DF,$0F,$8F,$B8,$41,
        $3B,$52,$C0,$D0,$E5,$3D,$9B,$59,$0F,$F1,$9B,$E7,$9F,$49,$DD,$21,
        $E5,$EB);
   p: array[0..25] of Byte = (
        $00,$CF,$20,$35,$02,$8B,$9D,$86,$98,$40,$B4,$16,$66,$B4,$2E,$92,
        $EA,$0D,$A3,$B4,$32,$04,$B5,$CF,$CE,$91);
   q: array[0..25] of Byte = (
        $00,$C9,$7F,$B1,$F0,$27,$F4,$53,$F6,$34,$12,$33,$EA,$AA,$D1,$D9,
        $35,$3F,$6C,$42,$D0,$88,$66,$B1,$D0,$5F);
   dmp1: array[0..25] of Byte = (
        $00,$8A,$15,$78,$AC,$5D,$13,$AF,$10,$2B,$22,$B9,$99,$CD,$74,$61,
        $F1,$5E,$6D,$22,$CC,$03,$23,$DF,$DF,$0B);
   dmq1: array[0..25] of Byte = (
        $00,$86,$55,$21,$4A,$C5,$4D,$8D,$4E,$CD,$61,$77,$F1,$C7,$36,$90,
        $CE,$2A,$48,$2C,$8B,$05,$99,$CB,$E0,$3F);
   iqmp: array[0..25] of Byte = (
        $00,$83,$EF,$EF,$B8,$A9,$A4,$0D,$1D,$B6,$ED,$98,$AD,$84,$ED,$13,
        $35,$DC,$C1,$08,$F3,$22,$D0,$57,$CF,$8D);
   ctext_ex: array[0..49] of Byte = (
        $14,$bd,$dd,$28,$c9,$83,$35,$19,$23,$80,$e8,$e5,$49,$b1,$58,$2a,
        $8b,$40,$b4,$48,$6d,$03,$a6,$a5,$31,$1f,$1f,$d5,$f0,$a1,$80,$e4,
        $17,$53,$03,$29,$a9,$34,$90,$74,$b1,$52,$13,$54,$29,$08,$24,$52,
        $62,$51);
begin

    RSA_set0_key(key,
                     BN_bin2bn(@n, sizeof(n)-1, nil),
                     BN_bin2bn(@e, sizeof(e)-1, nil),
                     BN_bin2bn(@d, sizeof(d)-1, nil));
        RSA_set0_factors(key,
                         BN_bin2bn(@p, sizeof(p)-1, nil),
                         BN_bin2bn(@q, sizeof(q)-1, nil));
        RSA_set0_crt_params(key,
                            BN_bin2bn(@dmp1, sizeof(dmp1)-1, nil),
                            BN_bin2bn(@dmq1, sizeof(dmq1)-1, nil),
                            BN_bin2bn(@iqmp, sizeof(iqmp)-1, nil));
        if c <> nil then
           memcpy(c, @ctext_ex, sizeof(ctext_ex) - 1);
        Result := sizeof(ctext_ex) - 1;
end;


function key3( key : PRSA; c : PByte):integer;
const
   n: array[0..128] of Byte = (
        $00,$BB,$F8,$2F,$09,$06,$82,$CE,$9C,$23,$38,$AC,$2B,$9D,$A8,$71,
        $F7,$36,$8D,$07,$EE,$D4,$10,$43,$A4,$40,$D6,$B6,$F0,$74,$54,$F5,
        $1F,$B8,$DF,$BA,$AF,$03,$5C,$02,$AB,$61,$EA,$48,$CE,$EB,$6F,$CD,
        $48,$76,$ED,$52,$0D,$60,$E1,$EC,$46,$19,$71,$9D,$8A,$5B,$8B,$80,
        $7F,$AF,$B8,$E0,$A3,$DF,$C7,$37,$72,$3E,$E6,$B4,$B7,$D9,$3A,$25,
        $84,$EE,$6A,$64,$9D,$06,$09,$53,$74,$88,$34,$B2,$45,$45,$98,$39,
        $4E,$E0,$AA,$B1,$2D,$7B,$61,$A5,$1F,$52,$7A,$9A,$41,$F6,$C1,$68,
        $7F,$E2,$53,$72,$98,$CA,$2A,$8F,$59,$46,$F8,$E5,$FD,$09,$1D,$BD,
        $CB);
    e: array[0..0] of Byte = ($11);
   d: array[0..128] of Byte = (
        $00,$A5,$DA,$FC,$53,$41,$FA,$F2,$89,$C4,$B9,$88,$DB,$30,$C1,$CD,
        $F8,$3F,$31,$25,$1E,$06,$68,$B4,$27,$84,$81,$38,$01,$57,$96,$41,
        $B2,$94,$10,$B3,$C7,$99,$8D,$6B,$C4,$65,$74,$5E,$5C,$39,$26,$69,
        $D6,$87,$0D,$A2,$C0,$82,$A9,$39,$E3,$7F,$DC,$B8,$2E,$C9,$3E,$DA,
        $C9,$7F,$F3,$AD,$59,$50,$AC,$CF,$BC,$11,$1C,$76,$F1,$A9,$52,$94,
        $44,$E5,$6A,$AF,$68,$C5,$6C,$09,$2C,$D3,$8D,$C3,$BE,$F5,$D2,$0A,
        $93,$99,$26,$ED,$4F,$74,$A1,$3E,$DD,$FB,$E1,$A1,$CE,$CC,$48,$94,
        $AF,$94,$28,$C2,$B7,$B8,$88,$3F,$E4,$46,$3A,$4B,$C8,$5B,$1C,$B3,
        $C1);
    p: array[0..64] of Byte = (
        $00,$EE,$CF,$AE,$81,$B1,$B9,$B3,$C9,$08,$81,$0B,$10,$A1,$B5,$60,
        $01,$99,$EB,$9F,$44,$AE,$F4,$FD,$A4,$93,$B8,$1A,$9E,$3D,$84,$F6,
        $32,$12,$4E,$F0,$23,$6E,$5D,$1E,$3B,$7E,$28,$FA,$E7,$AA,$04,$0A,
        $2D,$5B,$25,$21,$76,$45,$9D,$1F,$39,$75,$41,$BA,$2A,$58,$FB,$65,
        $99);
    q: array[0..64] of Byte = (
        $00,$C9,$7F,$B1,$F0,$27,$F4,$53,$F6,$34,$12,$33,$EA,$AA,$D1,$D9,
        $35,$3F,$6C,$42,$D0,$88,$66,$B1,$D0,$5A,$0F,$20,$35,$02,$8B,$9D,
        $86,$98,$40,$B4,$16,$66,$B4,$2E,$92,$EA,$0D,$A3,$B4,$32,$04,$B5,
        $CF,$CE,$33,$52,$52,$4D,$04,$16,$A5,$A4,$41,$E7,$00,$AF,$46,$15,
        $03);
    dmp1: array[0..63] of Byte = (
        $54,$49,$4C,$A6,$3E,$BA,$03,$37,$E4,$E2,$40,$23,$FC,$D6,$9A,$5A,
        $EB,$07,$DD,$DC,$01,$83,$A4,$D0,$AC,$9B,$54,$B0,$51,$F2,$B1,$3E,
        $D9,$49,$09,$75,$EA,$B7,$74,$14,$FF,$59,$C1,$F7,$69,$2E,$9A,$2E,
        $20,$2B,$38,$FC,$91,$0A,$47,$41,$74,$AD,$C9,$3C,$1F,$67,$C9,$81);
    dmq1: array[0..63] of Byte = (
        $47,$1E,$02,$90,$FF,$0A,$F0,$75,$03,$51,$B7,$F8,$78,$86,$4C,$A9,
        $61,$AD,$BD,$3A,$8A,$7E,$99,$1C,$5C,$05,$56,$A9,$4C,$31,$46,$A7,
        $F9,$80,$3F,$8F,$6F,$8A,$E3,$42,$E9,$31,$FD,$8A,$E4,$7A,$22,$0D,
        $1B,$99,$A4,$95,$84,$98,$07,$FE,$39,$F9,$24,$5A,$98,$36,$DA,$3D);
    iqmp: array[0..64] of Byte = (
        $00,$B0,$6C,$4F,$DA,$BB,$63,$01,$19,$8D,$26,$5B,$DB,$AE,$94,$23,
        $B3,$80,$F2,$71,$F7,$34,$53,$88,$50,$93,$07,$7F,$CD,$39,$E2,$11,
        $9F,$C9,$86,$32,$15,$4F,$58,$83,$B1,$67,$A9,$67,$BF,$40,$2B,$4E,
        $9E,$2E,$0F,$96,$56,$E6,$98,$EA,$36,$66,$ED,$FB,$25,$79,$80,$39,
        $F7);
     ctext_ex: array[0..127] of Byte = (
        $b8,$24,$6b,$56,$a6,$ed,$58,$81,$ae,$b5,$85,$d9,$a2,$5b,$2a,$d7,
        $90,$c4,$17,$e0,$80,$68,$1b,$f1,$ac,$2b,$c3,$de,$b6,$9d,$8b,$ce,
        $f0,$c4,$36,$6f,$ec,$40,$0a,$f0,$52,$a7,$2e,$9b,$0e,$ff,$b5,$b3,
        $f2,$f1,$92,$db,$ea,$ca,$03,$c1,$27,$40,$05,$71,$13,$bf,$1f,$06,
        $69,$ac,$22,$e9,$f3,$a7,$85,$2e,$3c,$15,$d9,$13,$ca,$b0,$b8,$86,
        $3a,$95,$c9,$92,$94,$ce,$86,$74,$21,$49,$54,$61,$03,$46,$f4,$d4,
        $74,$b2,$6f,$7c,$48,$b4,$2e,$e6,$8e,$1f,$57,$2a,$1f,$c4,$02,$6a,
        $c4,$56,$b4,$f5,$9f,$7b,$62,$1e,$a1,$b9,$d8,$8f,$64,$20,$2f,$b1);
begin

     RSA_set0_key(key,
                     BN_bin2bn(@n, sizeof(n)-1, nil),
                     BN_bin2bn(@e, sizeof(e)-1, nil),
                     BN_bin2bn(@d, sizeof(d)-1, nil));
        RSA_set0_factors(key,
                         BN_bin2bn(@p, sizeof(p)-1, nil),
                         BN_bin2bn(@q, sizeof(q)-1, nil));
        RSA_set0_crt_params(key,
                            BN_bin2bn(@dmp1, sizeof(dmp1)-1, nil),
                            BN_bin2bn(@dmq1, sizeof(dmq1)-1, nil),
                            BN_bin2bn(@iqmp, sizeof(iqmp)-1, nil));
        if c <> nil then
           memcpy(c, @ctext_ex, sizeof(ctext_ex) - 1);
        Result := sizeof(ctext_ex) - 1;
end;

end.
