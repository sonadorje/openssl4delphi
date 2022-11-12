unit openssl3.crypto.self_test_data;

interface
uses OpenSSL.Api;

type

  st_kat_drbg_st = record
    desc,
    algorithm,
    param_name,
    param_value      : PUTF8Char;
    entropyin        : PByte;
    entropyinlen     : size_t;
    nonce            : PByte;
    noncelen         : size_t;
    persstr          : PByte;
    persstrlen       : size_t;
    entropyinpr1     : PByte;
    entropyinpr1len  : size_t;
    entropyinpr2     : PByte;
    entropyinpr2len  : size_t;
    entropyaddin1    : PByte;
    entropyaddin1len : size_t;
    entropyaddin2    : PByte;
    entropyaddin2len : size_t;
    expected         : PByte;
    expectedlen      : size_t;
  end;
  TST_KAT_DRBG = st_kat_drbg_st;
  PST_KAT_DRBG = ^TST_KAT_DRBG;

  st_kat_st = record
    desc,
    algorithm    : PUTF8Char;
    pt           : PByte;
    pt_len       : size_t;
    expected     : PByte;
    expected_len : size_t;
  end;
  TST_KAT = st_kat_st;
  TST_KAT_DIGEST = TST_KAT ;
  PST_KAT_DIGEST = ^TST_KAT_DIGEST;


  st_kat_cipher_st = record
    base : TST_KAT;
    mode : integer;
    key : PByte;
    key_len : size_t;
    iv : PByte;
    iv_len : size_t;
    aad : PByte;
    aad_len : size_t;
    tag : PByte;
    tag_len : size_t;
  end;
  TST_KAT_CIPHER = st_kat_cipher_st ;
  PST_KAT_CIPHER = ^TST_KAT_CIPHER;


  st_kat_param_st = record
     name     : PUTF8Char;
    &type    : size_t;
    data     : Pointer;
    data_len : size_t;
  end;
  TST_KAT_PARAM = st_kat_param_st;
  PST_KAT_PARAM = ^TST_KAT_PARAM;

  st_kat_asym_cipher_st = record
    desc,
    algorithm    : PUTF8Char;
    encrypt      : integer;
    key,
    postinit     : PST_KAT_PARAM;
    _in          : PByte;
    in_len       : size_t;
    expected     : PByte;
    expected_len : size_t;
  end;
  TST_KAT_ASYM_CIPHER = st_kat_asym_cipher_st;
  PST_KAT_ASYM_CIPHER = ^TST_KAT_ASYM_CIPHER;


  st_kat_kdf_st = record
    desc,
    algorithm    : PUTF8Char;
    params       : PST_KAT_PARAM;
    expected     : PByte;
    expected_len : size_t;
  end;
  TST_KAT_KDF = st_kat_kdf_st;
  PST_KAT_KDF = ^TST_KAT_KDF;

  st_kat_kas_st = record
    desc,
    algorithm     : PUTF8Char;
    key_group,
    key_host_data,
    key_peer_data : PST_KAT_PARAM;
    expected      : PByte;
    expected_len  : size_t;
  end;
  TST_KAT_KAS = st_kat_kas_st;
  PST_KAT_KAS = ^TST_KAT_KAS;


  st_kat_sign_st = record
    desc,
    algorithm,
    mdalgorithm      : PUTF8Char;
    key              : PST_KAT_PARAM;
    sig_expected     : PByte;
    sig_expected_len : size_t;
  end;
  TST_KAT_SIGN = st_kat_sign_st;
  PST_KAT_SIGN = ^TST_KAT_SIGN;
const
  CIPHER_MODE_ENCRYPT = 1;
  CIPHER_MODE_DECRYPT = 2;
  CIPHER_MODE_ALL     = (CIPHER_MODE_ENCRYPT or CIPHER_MODE_DECRYPT);

  x942kdf_digest: PUTF8Char = 'SHA1';
  x942kdf_cekalg: PUTF8Char = 'AES-128-WRAP';
  ecdh_curve_name: PUTF8Char = 'prime256v1';
  ecd_prime_curve_name: PUTF8Char = 'secp224r1';
  ecd_bin_curve_name: PUTF8Char = 'sect233r1';

  sshkdf_digest : array of Byte = [Ord('S'), Ord('H'), Ord('A'), Ord('1')];
  tls13_kdf_digest: array of Byte = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  tls12prf_digest: array of Byte  = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  pbkdf2_digest: array of Byte    = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  kbkdf_digest: array of Byte     = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  hkdf_digest: array of Byte      = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  sskdf_digest: array of Byte     = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('2'), Ord('4')];
  x963kdf_digest: array of Byte   = [Ord('S'), Ord('H'), Ord('A'), Ord('2'), Ord('5'), Ord('6')];
  kbkdf_mac: array of Byte = [Ord('H'), Ord('M'), Ord('A'), Ord('C')];
  sha1_pt: array of Byte = [Ord('a'), Ord('b'), Ord('c')];
  pad_mode_none: array of Byte = [Ord('n'), Ord('o'), Ord('n'), Ord('e')];
  sha512_pt: array of Byte = [Ord('a'), Ord('b'), Ord('c')];
  sha1_digest : array[0..19] of byte = (
    $A9, $99, $3E, $36, $47, $06, $81, $6A, $BA, $3E, $25, $71, $78, $50,
    $C2, $6C, $9C, $D0, $D8, $9D );

   sha512_digest : array[0..63] of byte = (
    $DD, $AF, $35, $A1, $93, $61, $7A, $BA, $CC, $41, $73, $49, $AE, $20,
    $41, $31, $12, $E6, $FA, $4E, $89, $A9, $7E, $A2, $0A, $9E, $EE, $E6,
    $4B, $55, $D3, $9A, $21, $92, $99, $2A, $27, $4F, $C1, $A8, $36, $BA,
    $3C, $23, $A3, $FE, $EB, $BD, $45, $4D, $44, $23, $64, $3C, $E8, $0E,
    $2A, $9A, $C9, $4F, $A5, $4C, $A4, $9F );

    sha3_256_pt : array[0..3] of byte = ($e7, $37, $21, $05 );
    sha3_256_digest : array[0..31] of byte = (
    $3a, $42, $b6, $8a, $b0, $79, $f2, $8c, $4c, $a3, $c7, $52, $29, $6f,
    $27, $90, $06, $c4, $fe, $78, $b1, $eb, $79, $d9, $89, $77, $7f, $05,
    $1e, $40, $46, $ae );

    des_ede3_cbc_pt : array[0..31] of byte = (
    $6B, $C1, $BE, $E2, $2E, $40, $9F, $96, $E9, $3D, $7E, $11, $73, $93,
    $17, $2A, $AE, $2D, $8A, $57, $1E, $03, $AC, $9C, $9E, $B7, $6F, $AC,
    $45, $AF, $8E, $51 );

  des_ede3_cbc_key : array[0..23] of byte = (
    $01, $23, $45, $67, $89, $AB, $CD, $EF, $23, $45, $67, $89, $AB, $CD,
    $EF, $01, $45, $67, $89, $AB, $CD, $EF, $01, $23 );

  des_ede3_cbc_iv : array[0..7] of byte = (
    $F6, $9F, $24, $45, $DF, $4F, $9B, $17 );

  des_ede3_cbc_ct : array[0..31] of byte = (
    $20, $79, $C3, $D5, $3A, $A7, $63, $E1, $93, $B7, $9E, $25, $69, $AB,
    $52, $62, $51, $65, $70, $48, $1F, $25, $B5, $0F, $73, $C0, $BD, $A8,
    $5C, $8E, $0D, $A7 );

  aes_256_gcm_key : array[0..31] of byte = (
    $92, $e1, $1d, $cd, $aa, $86, $6f, $5c, $e7, $90, $fd, $24, $50, $1f,
    $92, $50, $9a, $ac, $f4, $cb, $8b, $13, $39, $d5, $0c, $9c, $12, $40,
    $93, $5d, $d0, $8b );

  aes_256_gcm_iv : array[0..11] of byte = (
    $ac, $93, $a1, $a6, $14, $52, $99, $bd, $e9, $02, $f2, $1a );

  aes_256_gcm_pt : array[0..15] of byte = (
    $2d, $71, $bc, $fa, $91, $4e, $4a, $c0, $45, $b2, $aa, $60, $95, $5f,
    $ad, $24 );

  aes_256_gcm_aad : array[0..15] of byte = (
    $1e, $08, $89, $01, $6f, $67, $60, $1c, $8e, $be, $a4, $94, $3b, $c2,
    $3a, $d6 );

  aes_256_gcm_ct : array[0..15] of byte = (
    $89, $95, $ae, $2e, $6d, $f3, $db, $f9, $6f, $ac, $7b, $71, $37, $ba,
    $e6, $7f );

  aes_256_gcm_tag : array[0..15] of byte = (
    $ec, $a5, $aa, $77, $d5, $1d, $4a, $0a, $14, $d9, $c5, $1e, $1d, $a4,
    $74, $ab );

  aes_128_ecb_key : array[0..15] of byte = (
    $10, $a5, $88, $69, $d7, $4b, $e5, $a3, $74, $cf, $86, $7c, $fb, $47,
    $38, $59 );

  aes_128_ecb_pt : array[0..15] of byte = (
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00 );

  aes_128_ecb_ct : array[0..15] of byte = (
    $6d, $25, $1e, $69, $44, $b0, $51, $e0, $4e, $aa, $6f, $b4, $db, $f7,
    $84, $65 );
  rsa_asym_plaintext_encrypt : array[0..15] of byte = (
    $01, $02, $03, $04, $05, $06, $07, $08, $09, $0a, $0b, $0c, $0d, $0e,
    $0f, $10 );

  rsa_asym_expected_encrypt : array[0..255] of byte = (
    $54, $ac, $23, $96, $1d, $82, $5d, $8b, $8f, $36, $33, $d0, $f4, $02,
    $a2, $61, $b1, $13, $d4, $4a, $46, $06, $37, $3c, $bf, $40, $05, $3c,
    $c6, $3b, $64, $dc, $22, $22, $af, $36, $79, $62, $45, $f0, $97, $82,
    $22, $44, $86, $4a, $7c, $fa, $ac, $03, $21, $84, $3f, $31, $ad, $2a,
    $a4, $6e, $7a, $c5, $93, $f3, $0f, $fc, $f1, $62, $ce, $82, $12, $45,
    $c9, $35, $b0, $7a, $cd, $99, $8c, $91, $6b, $5a, $d3, $46, $db, $f9,
    $9e, $52, $49, $bd, $1e, $e8, $da, $ac, $61, $47, $c2, $da, $fc, $1e,
    $fb, $74, $d7, $d6, $c1, $18, $86, $3e, $20, $9c, $7a, $e1, $04, $b7,
    $38, $43, $b1, $4e, $a0, $d8, $c1, $39, $4d, $e1, $d3, $b0, $b3, $f1,
    $82, $87, $1f, $74, $b5, $69, $fd, $33, $d6, $21, $7c, $61, $60, $28,
    $ca, $70, $db, $a0, $bb, $c8, $73, $a9, $82, $f8, $6b, $d8, $f0, $c9,
    $7b, $20, $df, $9d, $fb, $8c, $d4, $a2, $89, $e1, $9b, $04, $ad, $aa,
    $11, $6c, $8f, $ce, $83, $29, $56, $69, $bb, $00, $3b, $ef, $ca, $2d,
    $cd, $52, $c8, $f1, $b3, $9b, $b4, $4f, $6d, $9c, $3d, $69, $cc, $6d,
    $1f, $38, $4d, $e6, $bb, $0c, $87, $dc, $5f, $a9, $24, $93, $03, $46,
    $a2, $33, $6c, $f4, $d8, $5d, $68, $f3, $d3, $e0, $f2, $30, $db, $f5,
    $4f, $0f, $ad, $c7, $d0, $aa, $47, $d9, $9f, $85, $1b, $2e, $6c, $3c,
    $57, $04, $29, $f4, $f5, $66, $7d, $93, $4a, $aa, $05, $52, $55, $c1,
    $c6, $06, $90, $ab );

  ecd_prime_priv : array[0..27] of byte = (
    $98, $1f, $b5, $f1, $fc, $87, $1d, $7d, $de, $1e, $01, $64, $09, $9b,
    $e7, $1b, $9f, $ad, $63, $dd, $33, $01, $d1, $50, $80, $93, $50, $30 );

  ecd_prime_pub : array[0..56] of byte = (
    $04, $95, $47, $99, $44, $29, $8f, $51, $39, $e2, $53, $ec, $79, $b0,
    $4d, $de, $87, $1a, $76, $54, $d5, $96, $b8, $7a, $6d, $f4, $1c, $2c,
    $87, $91, $5f, $d5, $31, $dd, $24, $e5, $78, $d9, $08, $24, $8a, $49,
    $99, $ec, $55, $f2, $82, $b3, $c4, $b7, $33, $68, $e4, $24, $a9, $12,
    $82 );
   rsa_n : array[0..255] of byte = (
    $DB, $10, $1A, $C2, $A3, $F1, $DC, $FF, $13, $6B, $ED, $44, $DF, $F0,
    $02, $6D, $13, $C7, $88, $DA, $70, $6B, $54, $F1, $E8, $27, $DC, $C3,
    $0F, $99, $6A, $FA, $C6, $67, $FF, $1D, $1E, $3C, $1D, $C1, $B5, $5F,
    $6C, $C0, $B2, $07, $3A, $6D, $41, $E4, $25, $99, $AC, $FC, $D2, $0F,
    $02, $D3, $D1, $54, $06, $1A, $51, $77, $BD, $B6, $BF, $EA, $A7, $5C,
    $06, $A9, $5D, $69, $84, $45, $D7, $F5, $05, $BA, $47, $F0, $1B, $D7,
    $2B, $24, $EC, $CB, $9B, $1B, $10, $8D, $81, $A0, $BE, $B1, $8C, $33,
    $E4, $36, $B8, $43, $EB, $19, $2A, $81, $8D, $DE, $81, $0A, $99, $48,
    $B6, $F6, $BC, $CD, $49, $34, $3A, $8F, $26, $94, $E3, $28, $82, $1A,
    $7C, $8F, $59, $9F, $45, $E8, $5D, $1A, $45, $76, $04, $56, $05, $A1,
    $D0, $1B, $8C, $77, $6D, $AF, $53, $FA, $71, $E2, $67, $E0, $9A, $FE,
    $03, $A9, $85, $D2, $C9, $AA, $BA, $2A, $BC, $F4, $A0, $08, $F5, $13,
    $98, $13, $5D, $F0, $D9, $33, $34, $2A, $61, $C3, $89, $55, $F0, $AE,
    $1A, $9C, $22, $EE, $19, $05, $8D, $32, $FE, $EC, $9C, $84, $BA, $B7,
    $F9, $6C, $3A, $4F, $07, $FC, $45, $EB, $12, $E5, $7B, $FD, $55, $E6,
    $29, $69, $D1, $C2, $E8, $B9, $78, $59, $F6, $79, $10, $C6, $4E, $EB,
    $6A, $5E, $B9, $9A, $C7, $C4, $5B, $63, $DA, $A3, $3F, $5E, $92, $7A,
    $81, $5E, $D6, $B0, $E2, $62, $8F, $74, $26, $C2, $0C, $D3, $9A, $17,
    $47, $E6, $8E, $AB );

  rsa_e : array[0..2] of byte = (
    $01, $00, $01 );

  rsa_d : array[0..255] of byte = (
    $52, $41, $F4, $DA, $7B, $B7, $59, $55, $CA, $D4, $2F, $0F, $3A, $CB,
    $A4, $0D, $93, $6C, $CC, $9D, $C1, $B2, $FB, $FD, $AE, $40, $31, $AC,
    $69, $52, $21, $92, $B3, $27, $DF, $EA, $EE, $2C, $82, $BB, $F7, $40,
    $32, $D5, $14, $C4, $94, $12, $EC, $B8, $1F, $CA, $59, $E3, $C1, $78,
    $F3, $85, $D8, $47, $A5, $D7, $02, $1A, $65, $79, $97, $0D, $24, $F4,
    $F0, $67, $6E, $75, $2D, $BF, $10, $3D, $A8, $7D, $EF, $7F, $60, $E4,
    $E6, $05, $82, $89, $5D, $DF, $C6, $D2, $6C, $07, $91, $33, $98, $42,
    $F0, $02, $00, $25, $38, $C5, $85, $69, $8A, $7D, $2F, $95, $6C, $43,
    $9A, $B8, $81, $E2, $D0, $07, $35, $AA, $05, $41, $C9, $1E, $AF, $E4,
    $04, $3B, $19, $B8, $73, $A2, $AC, $4B, $1E, $66, $48, $D8, $72, $1F,
    $AC, $F6, $CB, $BC, $90, $09, $CA, $EC, $0C, $DC, $F9, $2C, $D7, $EB,
    $AE, $A3, $A4, $47, $D7, $33, $2F, $8A, $CA, $BC, $5E, $F0, $77, $E4,
    $97, $98, $97, $C7, $10, $91, $7D, $2A, $A6, $FF, $46, $83, $97, $DE,
    $E9, $E2, $17, $03, $06, $14, $E2, $D7, $B1, $1D, $77, $AF, $51, $27,
    $5B, $5E, $69, $B8, $81, $E6, $11, $C5, $43, $23, $81, $04, $62, $FF,
    $E9, $46, $B8, $D8, $44, $DB, $A5, $CC, $31, $54, $34, $CE, $3E, $82,
    $D6, $BF, $7A, $0B, $64, $21, $6D, $88, $7E, $5B, $45, $12, $1E, $63,
    $8D, $49, $A7, $1D, $D9, $1E, $06, $CD, $E8, $BA, $2C, $8C, $69, $32,
    $EA, $BE, $60, $71 );

  rsa_p : array[0..127] of byte = (
    $FA, $AC, $E1, $37, $5E, $32, $11, $34, $C6, $72, $58, $2D, $91, $06,
    $3E, $77, $E7, $11, $21, $CD, $4A, $F8, $A4, $3F, $0F, $EF, $31, $E3,
    $F3, $55, $A0, $B9, $AC, $B6, $CB, $BB, $41, $D0, $32, $81, $9A, $8F,
    $7A, $99, $30, $77, $6C, $68, $27, $E2, $96, $B5, $72, $C9, $C3, $D4,
    $42, $AA, $AA, $CA, $95, $8F, $FF, $C9, $9B, $52, $34, $30, $1D, $CF,
    $FE, $CF, $3C, $56, $68, $6E, $EF, $E7, $6C, $D7, $FB, $99, $F5, $4A,
    $A5, $21, $1F, $2B, $EA, $93, $E8, $98, $26, $C4, $6E, $42, $21, $5E,
    $A0, $A1, $2A, $58, $35, $BB, $10, $E7, $BA, $27, $0A, $3B, $B3, $AF,
    $E2, $75, $36, $04, $AC, $56, $A0, $AB, $52, $DE, $CE, $DD, $2C, $28,
    $77, $03 );

  rsa_q : array[0..127] of byte = (
    $DF, $B7, $52, $B6, $D7, $C0, $E2, $96, $E7, $C9, $FE, $5D, $71, $5A,
    $C4, $40, $96, $2F, $E5, $87, $EA, $F3, $A5, $77, $11, $67, $3C, $8D,
    $56, $08, $A7, $B5, $67, $FA, $37, $A8, $B8, $CF, $61, $E8, $63, $D8,
    $38, $06, $21, $2B, $92, $09, $A6, $39, $3A, $EA, $A8, $B4, $45, $4B,
    $36, $10, $4C, $E4, $00, $66, $71, $65, $F8, $0B, $94, $59, $4F, $8C,
    $FD, $D5, $34, $A2, $E7, $62, $84, $0A, $A7, $BB, $DB, $D9, $8A, $CD,
    $05, $E1, $CC, $57, $7B, $F1, $F1, $1F, $11, $9D, $BA, $3E, $45, $18,
    $99, $1B, $41, $64, $43, $EE, $97, $5D, $77, $13, $5B, $74, $69, $73,
    $87, $95, $05, $07, $BE, $45, $07, $17, $7E, $4A, $69, $22, $F3, $DB,
    $05, $39 );

  rsa_dp : array[0..127] of byte = (
    $5E, $D8, $DC, $DA, $53, $44, $C4, $67, $E0, $92, $51, $34, $E4, $83,
    $A5, $4D, $3E, $DB, $A7, $9B, $82, $BB, $73, $81, $FC, $E8, $77, $4B,
    $15, $BE, $17, $73, $49, $9B, $5C, $98, $BC, $BD, $26, $EF, $0C, $E9,
    $2E, $ED, $19, $7E, $86, $41, $1E, $9E, $48, $81, $DD, $2D, $E4, $6F,
    $C2, $CD, $CA, $93, $9E, $65, $7E, $D5, $EC, $73, $FD, $15, $1B, $A2,
    $A0, $7A, $0F, $0D, $6E, $B4, $53, $07, $90, $92, $64, $3B, $8B, $A9,
    $33, $B3, $C5, $94, $9B, $4C, $5D, $9C, $7C, $46, $A4, $A5, $56, $F4,
    $F3, $F8, $27, $0A, $7B, $42, $0D, $92, $70, $47, $E7, $42, $51, $A9,
    $C2, $18, $B1, $58, $B1, $50, $91, $B8, $61, $41, $B6, $A9, $CE, $D4,
    $7C, $BB );

  rsa_dq : array[0..127] of byte = (
    $54, $09, $1F, $0F, $03, $D8, $B6, $C5, $0C, $E8, $B9, $9E, $0C, $38,
    $96, $43, $D4, $A6, $C5, $47, $DB, $20, $0E, $E5, $BD, $29, $D4, $7B,
    $1A, $F8, $41, $57, $49, $69, $9A, $82, $CC, $79, $4A, $43, $EB, $4D,
    $8B, $2D, $F2, $43, $D5, $A5, $BE, $44, $FD, $36, $AC, $8C, $9B, $02,
    $F7, $9A, $03, $E8, $19, $A6, $61, $AE, $76, $10, $93, $77, $41, $04,
    $AB, $4C, $ED, $6A, $CC, $14, $1B, $99, $8D, $0C, $6A, $37, $3B, $86,
    $6C, $51, $37, $5B, $1D, $79, $F2, $A3, $43, $10, $C6, $A7, $21, $79,
    $6D, $F9, $E9, $04, $6A, $E8, $32, $FF, $AE, $FD, $1C, $7B, $8C, $29,
    $13, $A3, $0C, $B2, $AD, $EC, $6C, $0F, $8D, $27, $12, $7B, $48, $B2,
    $DB, $31 );

  rsa_qInv : array[0..127] of byte = (
    $8D, $1B, $05, $CA, $24, $1F, $0C, $53, $19, $52, $74, $63, $21, $FA,
    $78, $46, $79, $AF, $5C, $DE, $30, $A4, $6C, $20, $38, $E6, $97, $39,
    $B8, $7A, $70, $0D, $8B, $6C, $6D, $13, $74, $D5, $1C, $DE, $A9, $F4,
    $60, $37, $FE, $68, $77, $5E, $0B, $4E, $5E, $03, $31, $30, $DF, $D6,
    $AE, $85, $D0, $81, $BB, $61, $C7, $B1, $04, $5A, $C4, $6D, $56, $1C,
    $D9, $64, $E7, $85, $7F, $88, $91, $C9, $60, $28, $05, $E2, $C6, $24,
    $8F, $DD, $61, $64, $D8, $09, $DE, $7E, $D3, $4A, $61, $1A, $D3, $73,
    $58, $4B, $D8, $A0, $54, $25, $48, $83, $6F, $82, $6C, $AF, $36, $51,
    $2A, $5D, $14, $2F, $41, $25, $00, $DD, $F8, $F3, $95, $FE, $31, $25,
    $50, $12 );

    tls13_kdf_early_secret : array[0..31] of byte = (
    $15, $3B, $63, $94, $A9, $C0, $3C, $F3, $F5, $AC, $CC, $6E, $45, $5A,
    $76, $93, $28, $11, $38, $A1, $BC, $FA, $38, $03, $C2, $67, $35, $DD,
    $11, $94, $D2, $16 );

  tls13_kdf_client_early_traffic_secret : array[0..31] of byte = (
    $C8, $05, $83, $A9, $0E, $99, $5C, $48, $96, $00, $49, $2A, $5D, $A6,
    $42, $E6, $B1, $F6, $79, $BA, $67, $48, $28, $79, $2D, $F0, $87, $B9,
    $39, $63, $61, $71 );
   tls12prf_expected : array[0..127] of byte = (
    $d0, $61, $39, $88, $9f, $ff, $ac, $1e, $3a, $71, $86, $5f, $50, $4a,
    $a5, $d0, $d2, $a2, $e8, $95, $06, $c6, $f2, $27, $9b, $67, $0c, $3e,
    $1b, $74, $f5, $31, $01, $6a, $25, $30, $c5, $1a, $3a, $0f, $7e, $1d,
    $65, $90, $d0, $f0, $56, $6b, $2f, $38, $7f, $8d, $11, $fd, $4f, $73,
    $1c, $dd, $57, $2d, $2e, $ae, $92, $7f, $6f, $2f, $81, $41, $0b, $25,
    $e6, $96, $0b, $e6, $89, $85, $ad, $d6, $c3, $84, $45, $ad, $9f, $8c,
    $64, $bf, $80, $68, $bf, $9a, $66, $79, $48, $5d, $96, $6f, $1a, $d6,
    $f6, $8b, $43, $49, $5b, $10, $a6, $83, $75, $5e, $a2, $b8, $58, $d7,
    $0c, $ca, $c7, $ec, $8b, $05, $3c, $6b, $d4, $1c, $a2, $99, $d4, $e5,
    $19, $28 );

    pbkdf2_expected : array[0..15] of byte = (
    $89, $b6, $9d, $05, $16, $f8, $29, $89, $3c, $69, $62, $26, $65, $0a,
    $86, $87 );

    sshkdf_expected : array[0..7] of byte = (
    $e2, $f6, $27, $c0, $b4, $3f, $1a, $c1 );

     kbkdf_expected : array[0..31] of byte = (
    $9D, $18, $86, $16, $F6, $38, $52, $FE, $86, $91, $5B, $B8, $40, $B4,
    $A8, $86, $FF, $3E, $6B, $B0, $F8, $19, $B4, $9B, $89, $33, $93, $D3,
    $93, $85, $42, $95 );

    hkdf_expected : array[0..9] of byte = (
    $2a, $c4, $36, $9f, $52, $59, $96, $f8, $de, $13 );

    sskdf_expected : array[0..13] of byte = (
    $a4, $62, $de, $16, $a8, $9d, $e8, $46, $6e, $f5, $46, $0b, $47, $b8 );

     x942kdf_expected : array[0..15] of byte = (
    $d6, $d6, $b0, $94, $c1, $02, $7a, $7d, $e6, $e3, $11, $72, $94, $a3,
    $53, $64 );

    x963kdf_expected : array[0..31] of byte = (
    $c4, $98, $af, $77, $16, $1c, $c5, $9f, $29, $62, $b9, $a7, $13, $e2,
    $b2, $15, $15, $2d, $13, $97, $66, $ce, $34, $a7, $76, $df, $11, $86,
    $6a, $69, $bf, $2e );

    tls13_kdf_psk : array[0..31] of byte = (
    $F8, $AF, $6A, $EA, $2D, $39, $7B, $AF, $29, $48, $A2, $5B, $28, $34,
    $20, $06, $92, $CF, $F1, $7E, $EE, $91, $65, $E4, $E2, $7B, $AB, $EE,
    $9E, $DE, $FD, $05 );

    tls13_kdf_client_hello_hash : array[0..31] of byte = (
    $7c, $92, $f6, $8b, $d5, $bf, $36, $38, $ea, $33, $8a, $64, $94, $72,
    $2e, $1b, $44, $12, $7e, $1b, $7e, $8a, $ad, $53, $5f, $23, $22, $a6,
    $44, $ff, $22, $b3 );

     tls13_kdf_prefix : array[0..5] of byte = (
    $74, $6C, $73, $31, $33, $20 );

    tls13_kdf_client_early_secret_label : array[0..10] of byte = (
    $63, $20, $65, $20, $74, $72, $61, $66, $66, $69, $63 );

    tls12prf_secret : array[0..47] of byte = (
    $20, $2c, $88, $c0, $0f, $84, $a1, $7a, $20, $02, $70, $79, $60, $47,
    $87, $46, $11, $76, $45, $55, $39, $e7, $05, $be, $73, $08, $90, $60,
    $2c, $28, $9a, $50, $01, $e3, $4e, $eb, $3a, $04, $3e, $5d, $52, $a6,
    $5e, $66, $12, $51, $88, $bf );

  tls12prf_seed : array[0..76] of byte = (
    Ord('k'), Ord('e'), Ord('y'), Ord(' '), Ord('e'), Ord('x'), Ord('p'), Ord('a'),
    Ord('n'), Ord('s'), Ord('i'), Ord('o'), Ord('n'), $ae,
    $6c, $80, $6f, $8a, $d4, $d8, $07, $84, $54, $9d, $ff, $28, $a4, $b5,
    $8f, $d8, $37, $68, $1a, $51, $d9, $28, $c3, $e3, $0e, $e5, $ff, $14,
    $f3, $98, $68, $62, $e1, $fd, $91, $f2, $3f, $55, $8a, $60, $5f, $28,
    $47, $8c, $58, $cf, $72, $63, $7b, $89, $78, $4d, $95, $9d, $f7, $e9,
    $46, $d3, $f0, $7b, $d1, $b6, $16 );

     pbkdf2_password : array[0..8] of byte = (
    $70, $61, $73, $73, $00, $77, $6f, $72, $64 );

      pbkdf2_salt : array[0..4] of byte = (
    $73, $61, $00, $6c, $74 );

     sshkdf_key : array[0..131] of byte = (
    $00, $00, $00, $80, $55, $ba, $e9, $31, $c0, $7f, $d8, $24, $bf, $10,
    $ad, $d1, $90, $2b, $6f, $bc, $7c, $66, $53, $47, $38, $34, $98, $a6,
    $86, $92, $9f, $f5, $a2, $5f, $8e, $40, $cb, $66, $45, $ea, $81, $4f,
    $b1, $a5, $e0, $a1, $1f, $85, $2f, $86, $25, $56, $41, $e5, $ed, $98,
    $6e, $83, $a7, $8b, $c8, $26, $94, $80, $ea, $c0, $b0, $df, $d7, $70,
    $ca, $b9, $2e, $7a, $28, $dd, $87, $ff, $45, $24, $66, $d6, $ae, $86,
    $7c, $ea, $d6, $3b, $36, $6b, $1c, $28, $6e, $6c, $48, $11, $a9, $f1,
    $4c, $27, $ae, $a1, $4c, $51, $71, $d4, $9b, $78, $c0, $6e, $37, $35,
    $d3, $6e, $6a, $3b, $e3, $21, $dd, $5f, $c8, $23, $08, $f3, $4e, $e1,
    $cb, $17, $fb, $a9, $4a, $59 );

    sshkdf_xcghash : array[0..19] of byte = (
    $a4, $eb, $d4, $59, $34, $f5, $67, $92, $b5, $11, $2d, $cd, $75, $a1,
    $07, $5f, $dc, $88, $92, $45 );

  sshkdf_session_id : array[0..19] of byte = (
    $a4, $eb, $d4, $59, $34, $f5, $67, $92, $b5, $11, $2d, $cd, $75, $a1,
    $07, $5f, $dc, $88, $92, $45 );

 
    kbkdf_salt : array[0..2] of byte = (
    Ord('p'), Ord('r'), Ord('f') );

  kbkdf_prfinput : array[0..3] of byte = (
    Ord('t'), Ord('e'), Ord('s'), Ord('t') );

  kbkdf_key : array[0..15] of byte = (
    $37, $05, $D9, $60, $80, $C1, $77, $28, $A0, $E8, $00, $EA, $B6, $E0,
    $D2, $3C );

    hkdf_secret : array[0..5] of byte = (
    Ord('s'), Ord('e'), Ord('c'), Ord('r'), Ord('e'), Ord('t') );

    hkdf_salt : array[0..3] of byte = (
    Ord('s'), Ord('a'), Ord('l'), Ord('t') );

    hkdf_info : array[0..4] of byte = (
    Ord('l'), Ord('a'), Ord('b'), Ord('e'), Ord('l') );

    sskdf_secret : array[0..55] of byte = (
    $6d, $bd, $c2, $3f, $04, $54, $88, $e4, $06, $27, $57, $b0, $6b, $9e,
    $ba, $e1, $83, $fc, $5a, $59, $46, $d8, $0d, $b9, $3f, $ec, $6f, $62,
    $ec, $07, $e3, $72, $7f, $01, $26, $ae, $d1, $2c, $e4, $b2, $62, $f4,
    $7d, $48, $d5, $42, $87, $f8, $1d, $47, $4c, $7c, $3b, $18, $50, $e9 );

  sskdf_otherinfo : array[0..46] of byte = (
    $a1, $b2, $c3, $d4, $e5, $43, $41, $56, $53, $69, $64, $3c, $83, $2e,
    $98, $49, $dc, $db, $a7, $1e, $9a, $31, $39, $e6, $06, $e0, $95, $de,
    $3c, $26, $4a, $66, $e9, $8a, $16, $58, $54, $cd, $07, $98, $9b, $1e,
    $e0, $ec, $3f, $8d, $be );

   x963kdf_secret : array[0..23] of byte = (
    $22, $51, $8b, $10, $e7, $0f, $2a, $3f, $24, $38, $10, $ae, $32, $54,
    $13, $9e, $fb, $ee, $04, $aa, $57, $c7, $af, $7d );

   x963kdf_otherinfo : array[0..15] of byte = (
    $75, $ee, $f8, $1a, $a3, $04, $1e, $33, $b8, $09, $71, $20, $3d, $2c,
    $0c, $52 );

   x942kdf_secret : array[0..19] of byte = (
    $00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $0a, $0b, $0c, $0d,
    $0e, $0f, $10, $11, $12, $13 );

    drbg_hash_sha256_pr_entropyin : array[0..31] of byte = (
    $06, $6d, $c8, $ce, $75, $b2, $89, $66, $a6, $85, $16, $3f, $e2, $a4,
    $d4, $27, $fb, $db, $61, $66, $50, $61, $6b, $a2, $82, $fc, $33, $2b,
    $4e, $6f, $12, $20 );

  drbg_hash_sha256_pr_nonce : array[0..15] of byte = (
    $55, $9f, $7c, $64, $89, $70, $83, $ec, $2d, $73, $70, $d9, $f0, $e5,
    $07, $1f );

  drbg_hash_sha256_pr_persstr : array[0..31] of byte = (
    $88, $6f, $54, $9a, $ad, $1a, $c6, $3d, $18, $cb, $cc, $66, $85, $da,
    $a2, $c2, $f7, $9e, $b0, $89, $4c, $b4, $ae, $f1, $ac, $54, $4f, $ce,
    $57, $f1, $5e, $11 );

  drbg_hash_sha256_pr_entropyinpr0 : array[0..31] of byte = (
    $ff, $80, $b7, $d2, $6a, $05, $bc, $8a, $7a, $be, $53, $28, $6b, $0e,
    $eb, $73, $3b, $71, $5a, $20, $5b, $fa, $4f, $f6, $37, $03, $de, $ad,
    $b6, $ea, $0e, $f4 );

  drbg_hash_sha256_pr_entropyinpr1 : array[0..31] of byte = (
    $c7, $38, $32, $53, $46, $81, $ed, $e3, $7e, $03, $84, $6d, $3c, $84,
    $17, $67, $29, $7d, $24, $6c, $68, $92, $41, $d2, $e7, $75, $be, $7e,
    $c9, $96, $29, $3d );

  drbg_hash_sha256_pr_addin0 : array[0..31] of byte = (
    $b7, $21, $5f, $14, $ac, $7b, $af, $d0, $a9, $17, $72, $ba, $22, $f7,
    $19, $af, $bd, $20, $b3, $11, $63, $6c, $2b, $1e, $83, $e4, $a8, $23,
    $35, $3f, $c6, $ea );

  drbg_hash_sha256_pr_addin1 : array[0..31] of byte = (
    $ce, $d3, $1f, $7e, $0d, $ae, $5b, $b5, $c0, $43, $e2, $46, $b2, $94,
    $73, $e2, $fd, $39, $51, $2e, $ad, $45, $69, $ee, $e3, $e3, $80, $33,
    $14, $ab, $a7, $a3 );

  drbg_hash_sha256_pr_expected : array[0..127] of byte = (
    $60, $c2, $34, $cf, $af, $b4, $68, $03, $3b, $f1, $95, $e5, $78, $ce,
    $26, $6e, $14, $65, $32, $6a, $96, $a9, $e0, $3f, $8b, $89, $36, $70,
    $ef, $62, $75, $4d, $5e, $80, $d5, $53, $a1, $f8, $49, $50, $20, $8b,
    $93, $43, $07, $9f, $2e, $f8, $56, $e9, $c5, $70, $61, $85, $97, $b5,
    $dc, $82, $a2, $da, $ea, $a3, $fd, $9b, $2f, $d2, $a0, $d7, $1b, $c6,
    $29, $35, $cc, $b8, $3d, $a0, $67, $98, $05, $a0, $e3, $1e, $fe, $e4,
    $f0, $e5, $13, $b0, $83, $17, $fa, $ca, $93, $5e, $38, $29, $48, $d2,
    $72, $db, $76, $3e, $6d, $f3, $25, $10, $ff, $1b, $99, $ff, $f8, $c6,
    $0e, $b0, $dd, $29, $2e, $bc, $bb, $c8, $0a, $01, $6e, $d3, $b0, $0e,
    $4e, $ab );

  drbg_ctr_aes128_pr_df_entropyin : array[0..15] of byte = (
    $92, $89, $8f, $31, $fa, $1c, $ff, $6d, $18, $2f, $26, $06, $43, $df,
    $f8, $18 );

  drbg_ctr_aes128_pr_df_nonce : array[0..7] of byte = (
    $c2, $a4, $d9, $72, $c3, $b9, $b6, $97 );

  drbg_ctr_aes128_pr_df_persstr : array[0..15] of byte = (
    $ea, $65, $ee, $60, $26, $4e, $7e, $b6, $0e, $82, $68, $c4, $37, $3c,
    $5c, $0b );

  drbg_ctr_aes128_pr_df_entropyinpr0 : array[0..15] of byte = (
    $20, $72, $8a, $06, $f8, $6f, $8d, $d4, $41, $e2, $72, $b7, $c4, $2c,
    $e8, $10 );

  drbg_ctr_aes128_pr_df_entropyinpr1 : array[0..15] of byte = (
    $3d, $b0, $f0, $94, $f3, $05, $50, $33, $17, $86, $3e, $22, $08, $f7,
    $a5, $01 );

  drbg_ctr_aes128_pr_df_addin0 : array[0..15] of byte = (
    $1a, $40, $fa, $e3, $cc, $6c, $7c, $a0, $f8, $da, $ba, $59, $23, $6d,
    $ad, $1d );

  drbg_ctr_aes128_pr_df_addin1 : array[0..15] of byte = (
    $9f, $72, $76, $6c, $c7, $46, $e5, $ed, $2e, $53, $20, $12, $bc, $59,
    $31, $8c );

  drbg_ctr_aes128_pr_df_expected : array[0..63] of byte = (
    $5a, $35, $39, $87, $0f, $4d, $22, $a4, $09, $24, $ee, $71, $c9, $6f,
    $ac, $72, $0a, $d6, $f0, $88, $82, $d0, $83, $28, $73, $ec, $3f, $93,
    $d8, $ab, $45, $23, $f0, $7e, $ac, $45, $14, $5e, $93, $9f, $b1, $d6,
    $76, $43, $3d, $b6, $e8, $08, $88, $f6, $da, $89, $08, $77, $42, $fe,
    $1a, $f4, $3f, $c4, $23, $c5, $1f, $68 );

  drbg_hmac_sha1_pr_entropyin : array[0..15] of byte = (
    $68, $0f, $ac, $e9, $0d, $7b, $ca, $21, $d4, $a0, $ed, $b7, $79, $9e,
    $e5, $d8 );

  drbg_hmac_sha1_pr_nonce : array[0..7] of byte = (
    $b7, $be, $9e, $ed, $dd, $0e, $3b, $4b );

  drbg_hmac_sha1_pr_persstr : array[0..15] of byte = (
    $f5, $8c, $40, $ae, $70, $f7, $a5, $56, $48, $a9, $31, $a0, $a9, $31,
    $3d, $d7 );

  drbg_hmac_sha1_pr_entropyinpr0 : array[0..15] of byte = (
    $7c, $af, $e2, $31, $63, $0a, $a9, $5a, $74, $2c, $4e, $5f, $5f, $22,
    $c6, $a4 );

  drbg_hmac_sha1_pr_entropyinpr1 : array[0..15] of byte = (
    $1c, $0d, $77, $92, $89, $88, $27, $94, $8a, $58, $9f, $82, $2d, $1a,
    $f7, $a6 );

  drbg_hmac_sha1_pr_addin0 : array[0..15] of byte = (
    $dc, $36, $63, $f0, $62, $78, $9c, $d1, $5c, $bb, $20, $c3, $c1, $8c,
    $d9, $d7 );

  drbg_hmac_sha1_pr_addin1 : array[0..15] of byte = (
    $fe, $85, $b0, $ab, $14, $c6, $96, $e6, $9c, $24, $e7, $b5, $a1, $37,
    $12, $0c );

  drbg_hmac_sha1_pr_expected : array[0..79] of byte = (
    $68, $00, $4b, $3a, $28, $f7, $f0, $1c, $f9, $e9, $b5, $71, $20, $79,
    $ef, $80, $87, $1b, $08, $b9, $a9, $1b, $cd, $2b, $9f, $09, $4d, $a4,
    $84, $80, $b3, $4c, $af, $d5, $59, $6b, $0c, $0a, $48, $e1, $48, $da,
    $bc, $6f, $77, $b8, $ff, $af, $18, $70, $28, $e1, $04, $13, $7a, $4f,
    $eb, $1c, $72, $b0, $c4, $4f, $e8, $b1, $af, $ab, $a5, $bc, $fd, $86,
    $67, $f2, $f5, $5b, $46, $06, $63, $2e, $3c, $bc );
const  st_kat_digest_tests: array[0..2] of TST_KAT_DIGEST =
(
    (
         desc: 'SHA1';
         algorithm    :'SHA1';
         pt :@sha1_pt; pt_len :(SizeOf(sha1_pt) - 1);
         expected :@sha1_digest; expected_len :sizeof(sha1_digest);
    ),
    (
         desc: 'SHA2';
         algorithm    :'SHA512';
         pt: @sha512_pt; pt_len :(sizeof(sha512_pt) - 1);
         expected :@sha512_digest; expected_len :sizeof(sha512_digest);
    ),
    (
         desc: 'SHA3';
         algorithm    :'SHA3-256';
         pt: @sha3_256_pt; pt_len :sizeof(sha3_256_pt);
         expected :@sha3_256_digest; expected_len :sizeof(sha3_256_digest);
    )

);
    dh_secret_expected : array[0..255] of byte = (
    $08, $ff, $33, $bb, $2e, $cf, $f4, $9a, $7d, $4a, $79, $12, $ae, $b1,
    $bb, $6a, $b5, $11, $64, $1b, $4a, $76, $77, $0c, $8c, $c1, $bc, $c2,
    $33, $34, $3d, $fe, $70, $0d, $11, $81, $3d, $2c, $9e, $d2, $3b, $21,
    $1c, $a9, $e8, $78, $69, $21, $ed, $ca, $28, $3c, $68, $b1, $61, $53,
    $fa, $01, $e9, $1a, $b8, $2c, $90, $dd, $ab, $4a, $95, $81, $67, $70,
    $a9, $87, $10, $e1, $4c, $92, $ab, $83, $b6, $e4, $6e, $1e, $42, $6e,
    $e8, $52, $43, $0d, $61, $87, $da, $a3, $72, $0a, $6b, $cd, $73, $23,
    $5c, $6b, $0f, $94, $1f, $33, $64, $f5, $04, $20, $55, $1a, $4b, $fe,
    $af, $e2, $bc, $43, $85, $05, $a5, $9a, $4a, $40, $da, $ca, $7a, $89,
    $5a, $73, $db, $57, $5c, $74, $c1, $3a, $23, $ad, $88, $32, $95, $7d,
    $58, $2d, $38, $f0, $a6, $16, $5f, $b0, $d7, $e9, $b8, $79, $9e, $42,
    $fd, $32, $20, $e3, $32, $e9, $81, $85, $a0, $c9, $42, $97, $57, $b2,
    $d0, $d0, $2c, $17, $db, $aa, $1f, $f6, $ed, $93, $d7, $e7, $3e, $24,
    $1e, $ae, $d9, $0c, $af, $39, $4d, $2b, $c6, $57, $0f, $18, $c8, $1f,
    $2b, $e5, $d0, $1a, $2c, $a9, $9f, $f1, $42, $b5, $d9, $63, $f9, $f5,
    $00, $32, $5e, $75, $56, $f9, $58, $49, $b3, $ff, $c7, $47, $94, $86,
    $be, $1d, $45, $96, $a3, $10, $6b, $d5, $cb, $4f, $61, $c5, $7e, $c5,
    $f1, $00, $fb, $7a, $0c, $82, $a1, $0b, $82, $52, $6a, $97, $d1, $d9,
    $7d, $98, $ea, $f6 );

    ecdh_secret_expected : array[0..31] of byte = (
    $45, $2a, $2f, $0d, $24, $e6, $8d, $d0, $da, $59, $7b, $0c, $ec, $9b,
    $4c, $38, $41, $dd, $ce, $b3, $cc, $f1, $90, $8e, $30, $db, $5b, $5f,
    $97, $ea, $e0, $c2 );

     dh_p : array[0..255] of byte = (
    $dc, $ca, $15, $11, $b2, $31, $32, $25, $f5, $21, $16, $e1, $54, $27,
    $89, $e0, $01, $f0, $42, $5b, $cc, $c7, $f3, $66, $f7, $40, $64, $07,
    $f1, $c9, $fa, $8b, $e6, $10, $f1, $77, $8b, $b1, $70, $be, $39, $db,
    $b7, $6f, $85, $bf, $24, $ce, $68, $80, $ad, $b7, $62, $9f, $7c, $6d,
    $01, $5e, $61, $d4, $3f, $a3, $ee, $4d, $e1, $85, $f2, $cf, $d0, $41,
    $ff, $de, $9d, $41, $84, $07, $e1, $51, $38, $bb, $02, $1d, $ae, $b3,
    $5f, $76, $2d, $17, $82, $ac, $c6, $58, $d3, $2b, $d4, $b0, $23, $2c,
    $92, $7d, $d3, $8f, $a0, $97, $b3, $d1, $85, $9f, $a8, $ac, $af, $b9,
    $8f, $06, $66, $08, $fc, $64, $4e, $c7, $dd, $b6, $f0, $85, $99, $f9,
    $2a, $c1, $b5, $98, $25, $da, $84, $32, $07, $7d, $ef, $69, $56, $46,
    $06, $3c, $20, $82, $3c, $95, $07, $ab, $6f, $01, $76, $d4, $73, $0d,
    $99, $0d, $bb, $e6, $36, $1c, $d8, $b2, $b9, $4d, $3d, $2f, $32, $9b,
    $82, $09, $9b, $d6, $61, $f4, $29, $50, $f4, $03, $df, $3e, $de, $62,
    $a3, $31, $88, $b0, $27, $98, $ba, $82, $3f, $44, $b9, $46, $fe, $9d,
    $f6, $77, $a0, $c5, $a1, $23, $8e, $aa, $97, $b7, $0f, $80, $da, $8c,
    $ac, $88, $e0, $92, $b1, $12, $70, $60, $ff, $bf, $45, $57, $99, $94,
    $01, $1d, $c2, $fa, $a5, $e7, $f6, $c7, $62, $45, $e1, $cc, $31, $22,
    $31, $c1, $7d, $1c, $a6, $b1, $90, $07, $ef, $0d, $b9, $9f, $9c, $b6,
    $0e, $1d, $5f, $69 );

  dh_q : array[0..27] of byte = (
    $89, $8b, $22, $67, $17, $ef, $03, $9e, $60, $3e, $82, $e5, $c7, $af,
    $e4, $83, $74, $ac, $5f, $62, $5c, $54, $f1, $ea, $11, $ac, $b5, $7d );

  dh_g : array[0..255] of byte = (
    $5e, $f7, $b8, $8f, $2d, $f6, $01, $39, $35, $1d, $fb, $fe, $12, $66,
    $80, $5f, $df, $35, $6c, $df, $d1, $3a, $4d, $a0, $05, $0c, $7e, $de,
    $24, $6d, $f5, $9f, $6a, $bf, $96, $ad, $e5, $f2, $b2, $8f, $fe, $88,
    $d6, $bc, $e7, $f7, $89, $4a, $3d, $53, $5f, $c8, $21, $26, $dd, $d4,
    $24, $87, $2e, $16, $b8, $38, $df, $8c, $51, $e9, $01, $6f, $88, $9c,
    $7c, $20, $3e, $98, $a8, $b6, $31, $f9, $c7, $25, $63, $d3, $8a, $49,
    $58, $9a, $07, $53, $d3, $58, $e7, $83, $31, $8c, $ef, $d9, $67, $7c,
    $7b, $2d, $bb, $77, $d6, $dc, $e2, $a1, $96, $37, $95, $ca, $64, $b9,
    $2d, $1c, $9a, $ac, $6d, $0e, $8d, $43, $1d, $e5, $e5, $00, $60, $df,
    $f7, $86, $89, $c9, $ec, $a1, $c1, $24, $8c, $16, $ed, $09, $c7, $ad,
    $41, $2a, $17, $40, $6d, $2b, $52, $5a, $a1, $ca, $bb, $23, $7b, $97,
    $34, $ec, $7b, $8c, $e3, $fa, $e0, $2f, $29, $c5, $ef, $ed, $30, $d6,
    $91, $87, $da, $10, $9c, $2c, $9f, $e2, $aa, $db, $b0, $c2, $2a, $f5,
    $4c, $61, $66, $55, $00, $0c, $43, $1c, $6b, $4a, $37, $97, $63, $b0,
    $a9, $16, $58, $ef, $c8, $4e, $8b, $06, $35, $8c, $8b, $4f, $21, $37,
    $10, $fd, $10, $17, $2c, $f3, $9b, $83, $0c, $2d, $d8, $4a, $0c, $8a,
    $b8, $25, $16, $ec, $ab, $99, $5f, $a4, $21, $5e, $02, $3e, $4e, $cf,
    $80, $74, $c3, $9d, $6c, $88, $b7, $0d, $1e, $e4, $e9, $6f, $dc, $20,
    $ea, $11, $5c, $32 );

  dh_priv : array[0..27] of byte = (
    $14, $33, $e0, $b5, $a9, $17, $b6, $0a, $30, $23, $f2, $f8, $aa, $2c,
    $2d, $70, $d2, $96, $8a, $ba, $9a, $ea, $c8, $15, $40, $b8, $fc, $e6 );

  dh_pub : array[0..255] of byte = (
    $95, $dd, $33, $8d, $29, $e5, $71, $04, $92, $b9, $18, $31, $7b, $72,
    $a3, $69, $36, $e1, $95, $1a, $2e, $e5, $a5, $59, $16, $99, $c0, $48,
    $6d, $0d, $4f, $9b, $dd, $6d, $5a, $3f, $6b, $98, $89, $0c, $62, $b3,
    $76, $52, $d3, $6e, $71, $21, $11, $e6, $8a, $73, $55, $37, $25, $06,
    $99, $ef, $e3, $30, $53, $73, $91, $fb, $c2, $c5, $48, $bc, $5a, $c3,
    $e5, $b2, $33, $86, $c3, $ee, $f5, $eb, $43, $c0, $99, $d7, $0a, $52,
    $02, $68, $7e, $83, $96, $42, $48, $fc, $a9, $1f, $40, $90, $8e, $8f,
    $b3, $31, $93, $15, $f6, $d2, $60, $6d, $7f, $7c, $d5, $2c, $c6, $e7,
    $c5, $84, $3a, $fb, $22, $51, $9c, $f0, $f0, $f9, $d3, $a0, $a4, $e8,
    $c8, $88, $99, $ef, $ed, $e7, $36, $43, $51, $fb, $6a, $36, $3e, $e7,
    $17, $e5, $44, $5a, $da, $b4, $c9, $31, $a6, $48, $39, $97, $b8, $7d,
    $ad, $83, $67, $7e, $4d, $1d, $3a, $77, $75, $e0, $f6, $d0, $0f, $df,
    $73, $c7, $ad, $80, $1e, $66, $5a, $0e, $5a, $79, $6d, $0a, $03, $80,
    $a1, $9f, $a1, $82, $ef, $c8, $a0, $4f, $5e, $4d, $b9, $0d, $1a, $86,
    $37, $f9, $5d, $b1, $64, $36, $bd, $c8, $f3, $fc, $09, $6c, $4f, $f7,
    $f2, $34, $be, $8f, $ef, $47, $9a, $c4, $b0, $dc, $4b, $77, $26, $3e,
    $07, $d9, $95, $9d, $e0, $f1, $bf, $3f, $0a, $e3, $d9, $d5, $0e, $4b,
    $89, $c9, $9e, $3e, $a1, $21, $73, $43, $dd, $8c, $65, $81, $ac, $c4,
    $95, $9c, $91, $d3 );

  dh_peer_pub : array[0..255] of byte = (
    $1f, $c1, $da, $34, $1d, $1a, $84, $6a, $96, $b7, $be, $24, $34, $0f,
    $87, $7d, $d0, $10, $aa, $03, $56, $d5, $ad, $58, $aa, $e9, $c7, $b0,
    $8f, $74, $9a, $32, $23, $51, $10, $b5, $d8, $8e, $b5, $db, $fa, $97,
    $8d, $27, $ec, $c5, $30, $f0, $2d, $31, $14, $00, $5b, $64, $b1, $c0,
    $e0, $24, $cb, $8a, $e2, $16, $98, $bc, $a9, $e6, $0d, $42, $80, $86,
    $22, $f1, $81, $c5, $6e, $1d, $e7, $a9, $6e, $6e, $fe, $e9, $d6, $65,
    $67, $e9, $1b, $97, $70, $42, $c7, $e3, $d0, $44, $8f, $05, $fb, $77,
    $f5, $22, $b9, $bf, $c8, $d3, $3c, $c3, $c3, $1e, $d3, $b3, $1f, $0f,
    $ec, $b6, $db, $4f, $6e, $a3, $11, $e7, $7a, $fd, $bc, $d4, $7a, $ee,
    $1b, $b1, $50, $f2, $16, $87, $35, $78, $fb, $96, $46, $8e, $8f, $9f,
    $3d, $e8, $ef, $bf, $ce, $75, $62, $4b, $1d, $f0, $53, $22, $a3, $4f,
    $14, $63, $e8, $39, $e8, $98, $4c, $4a, $d0, $a9, $6e, $1a, $c8, $42,
    $e5, $31, $8c, $c2, $3c, $06, $2a, $8c, $a1, $71, $b8, $d5, $75, $98,
    $0d, $de, $7f, $c5, $6f, $15, $36, $52, $38, $20, $d4, $31, $92, $bf,
    $d5, $1e, $8e, $22, $89, $78, $ac, $a5, $b9, $44, $72, $f3, $39, $ca,
    $eb, $99, $31, $b4, $2b, $e3, $01, $26, $8b, $c9, $97, $89, $c9, $b2,
    $55, $71, $c3, $c0, $e4, $cb, $3f, $00, $7f, $1a, $51, $1c, $bb, $53,
    $c8, $51, $9c, $dd, $13, $02, $ab, $ca, $6c, $0f, $34, $f9, $67, $39,
    $f1, $7f, $f4, $8b );

     ecdh_pub : array[0..64] of byte = (
    $04, $1b, $93, $67, $55, $1c, $55, $9f, $63, $d1, $22, $a4, $d8, $d1,
    $0a, $60, $6d, $02, $a5, $77, $57, $c8, $a3, $47, $73, $3a, $6a, $08,
    $28, $39, $bd, $c9, $d2, $80, $ec, $e9, $a7, $08, $29, $71, $2f, $c9,
    $56, $82, $ee, $9a, $85, $0f, $6d, $7f, $59, $5f, $8c, $d1, $96, $0b,
    $df, $29, $3e, $49, $07, $88, $3f, $9a, $29 );

  ecdh_peer_pub : array[0..64] of byte = (
    $04, $1f, $72, $bd, $2a, $3e, $eb, $6c, $76, $e5, $5d, $69, $75, $24,
    $bf, $2f, $5b, $96, $b2, $91, $62, $06, $35, $cc, $b2, $4b, $31, $1b,
    $0c, $6f, $06, $9f, $86, $cf, $c8, $ac, $d5, $4f, $4d, $77, $f3, $70,
    $4a, $8f, $04, $9a, $b1, $03, $c7, $eb, $d5, $94, $78, $61, $ab, $78,
    $0c, $4a, $2d, $6b, $f3, $2f, $2e, $4a, $bc );

    ecdh_privd : array[0..31] of byte = (
    $33, $d0, $43, $83, $a9, $89, $56, $03, $d2, $d7, $fe, $6b, $01, $6f,
    $e4, $59, $cc, $0d, $9a, $24, $6c, $86, $1b, $2e, $dc, $4b, $4d, $35,
    $43, $e1, $1b, $ad );

     rsa_expected_sig : array[0..255] of byte = (
    $ad, $be, $2a, $af, $16, $85, $c5, $00, $91, $3e, $d0, $49, $fb, $3a,
    $81, $b9, $6c, $28, $bc, $bf, $ea, $96, $5f, $e4, $9f, $99, $f7, $18,
    $8c, $ec, $60, $28, $eb, $29, $02, $49, $fc, $da, $d7, $78, $68, $f8,
    $e1, $e9, $4d, $20, $6d, $32, $a6, $de, $fc, $e4, $da, $cc, $6c, $75,
    $36, $6b, $ff, $5a, $ac, $01, $a8, $c2, $a9, $e6, $8b, $18, $3e, $ec,
    $ea, $4c, $4a, $9e, $00, $09, $d1, $8a, $69, $1b, $8b, $d9, $ad, $37,
    $e5, $7c, $ff, $7d, $59, $56, $3e, $a0, $c6, $32, $d8, $35, $2f, $ff,
    $fb, $05, $02, $cd, $d7, $19, $b9, $00, $86, $2a, $cf, $aa, $78, $16,
    $4b, $f1, $a7, $59, $ef, $7d, $e8, $74, $23, $5c, $b2, $d4, $8a, $99,
    $a5, $bc, $fa, $63, $d8, $f7, $bd, $c6, $00, $13, $06, $02, $9a, $d4,
    $a7, $b4, $3d, $61, $ab, $f1, $c2, $95, $59, $9b, $3d, $67, $1f, $de,
    $57, $b6, $b6, $9f, $b0, $87, $d6, $51, $d5, $3e, $00, $e2, $c9, $a0,
    $03, $66, $bc, $01, $b3, $8e, $fa, $f1, $15, $eb, $26, $f1, $5d, $81,
    $90, $b4, $1c, $00, $7c, $83, $4a, $a5, $de, $64, $ae, $ea, $6c, $43,
    $c3, $20, $77, $77, $42, $12, $24, $f5, $e3, $70, $dd, $59, $48, $9c,
    $ef, $d4, $8a, $3c, $29, $6a, $0c, $9c, $f2, $13, $a4, $1c, $2f, $49,
    $cd, $b4, $aa, $28, $40, $34, $c6, $75, $ba, $30, $e6, $d8, $5b, $2f,
    $08, $d0, $29, $a5, $39, $fb, $6e, $3b, $0f, $52, $2c, $68, $f0, $37,
    $a9, $d2, $56, $d6 );

     ecd_bin_pub : array[0..60] of byte = (
    $04, $00, $06, $e2, $56, $f7, $37, $f9, $ea, $b6, $d1, $0f, $59, $fa,
    $23, $c3, $93, $a8, $b2, $26, $e2, $5c, $08, $be, $63, $49, $26, $dc,
    $c7, $1e, $6f, $01, $32, $3b, $e6, $54, $8d, $c1, $13, $3e, $54, $b2,
    $66, $89, $b2, $82, $0a, $72, $02, $a8, $e9, $6f, $54, $fd, $3a, $6b,
    $99, $b6, $8f, $80, $46 );

     ecd_bin_priv : array[0..29] of byte = (
    $00, $6d, $d6, $39, $9d, $2a, $a2, $c8, $8c, $fc, $7b, $80, $66, $aa,
    $e1, $aa, $ba, $ee, $cb, $fd, $c9, $e5, $36, $38, $2e, $f7, $37, $6d,
    $d3, $20 );

    dsa_p : array[0..255] of byte = (
    $a2, $9b, $88, $72, $ce, $8b, $84, $23, $b7, $d5, $d2, $1d, $4b, $02,
    $f5, $7e, $03, $e9, $e6, $b8, $a2, $58, $dc, $16, $61, $1b, $a0, $98,
    $ab, $54, $34, $15, $e4, $15, $f1, $56, $99, $7a, $3e, $e2, $36, $65,
    $8f, $a0, $93, $26, $0d, $e3, $ad, $42, $2e, $05, $e0, $46, $f9, $ec,
    $29, $16, $1a, $37, $5f, $0e, $b4, $ef, $fc, $ef, $58, $28, $5c, $5d,
    $39, $ed, $42, $5d, $7a, $62, $ca, $12, $89, $6c, $4a, $92, $cb, $19,
    $46, $f2, $95, $2a, $48, $13, $3f, $07, $da, $36, $4d, $1b, $df, $6b,
    $0f, $71, $39, $98, $3e, $69, $3c, $80, $05, $9b, $0e, $ac, $d1, $47,
    $9b, $a9, $f2, $85, $77, $54, $ed, $e7, $5f, $11, $2b, $07, $eb, $bf,
    $35, $34, $8b, $bf, $3e, $01, $e0, $2f, $2d, $47, $3d, $e3, $94, $53,
    $f9, $9d, $d2, $36, $75, $41, $ca, $ca, $3b, $a0, $11, $66, $34, $3d,
    $7b, $5b, $58, $a3, $7b, $d1, $b7, $52, $1d, $b2, $f1, $3b, $86, $70,
    $71, $32, $fe, $09, $f4, $cd, $09, $dc, $16, $18, $fa, $34, $01, $eb,
    $f9, $cc, $7b, $19, $fa, $94, $aa, $47, $20, $88, $13, $3d, $6c, $b2,
    $d3, $5c, $11, $79, $c8, $c8, $ff, $36, $87, $58, $d5, $07, $d9, $f9,
    $a1, $7d, $46, $c1, $10, $fe, $31, $44, $ce, $9b, $02, $2b, $42, $e4,
    $19, $eb, $4f, $53, $88, $61, $3b, $fc, $3e, $26, $24, $1a, $43, $2e,
    $87, $06, $bc, $58, $ef, $76, $11, $72, $78, $de, $ab, $6c, $f6, $92,
    $61, $82, $91, $b7 );

  dsa_q : array[0..27] of byte = (
    $a3, $bf, $d9, $ab, $78, $84, $79, $4e, $38, $34, $50, $d5, $89, $1d,
    $c1, $8b, $65, $15, $7b, $dc, $fc, $da, $c5, $15, $18, $90, $28, $67 );

  dsa_g : array[0..255] of byte = (
    $68, $19, $27, $88, $69, $c7, $fd, $3d, $2d, $7b, $77, $f7, $7e, $81,
    $50, $d9, $ad, $43, $3b, $ea, $3b, $a8, $5e, $fc, $80, $41, $5a, $a3,
    $54, $5f, $78, $f7, $22, $96, $f0, $6c, $b1, $9c, $ed, $a0, $6c, $94,
    $b0, $55, $1c, $fe, $6e, $6f, $86, $3e, $31, $d1, $de, $6e, $ed, $7d,
    $ab, $8b, $0c, $9d, $f2, $31, $e0, $84, $34, $d1, $18, $4f, $91, $d0,
    $33, $69, $6b, $b3, $82, $f8, $45, $5e, $98, $88, $f5, $d3, $1d, $47,
    $84, $ec, $40, $12, $02, $46, $f4, $be, $a6, $17, $94, $bb, $a5, $86,
    $6f, $09, $74, $64, $63, $bd, $f8, $e9, $e1, $08, $cd, $95, $29, $c3,
    $d0, $f6, $df, $80, $31, $6e, $2e, $70, $aa, $eb, $1b, $26, $cd, $b8,
    $ad, $97, $bc, $3d, $28, $7e, $0b, $8d, $61, $6c, $42, $e6, $5b, $87,
    $db, $20, $de, $b7, $00, $5b, $c4, $16, $74, $7a, $64, $70, $14, $7a,
    $68, $a7, $82, $03, $88, $eb, $f4, $4d, $52, $e0, $62, $8a, $f9, $cf,
    $1b, $71, $66, $d0, $34, $65, $f3, $5a, $cc, $31, $b6, $11, $0c, $43,
    $da, $bc, $7c, $5d, $59, $1e, $67, $1e, $af, $7c, $25, $2c, $1c, $14,
    $53, $36, $a1, $a4, $dd, $f1, $32, $44, $d5, $5e, $83, $56, $80, $ca,
    $b2, $53, $3b, $82, $df, $2e, $fe, $55, $ec, $18, $c1, $e6, $cd, $00,
    $7b, $b0, $89, $75, $8b, $b1, $7c, $2c, $be, $14, $44, $1b, $d0, $93,
    $ae, $66, $e5, $97, $6d, $53, $73, $3f, $4f, $a3, $26, $97, $01, $d3,
    $1d, $23, $d4, $67 );

  dsa_pub : array[0..255] of byte = (
    $a0, $12, $b3, $b1, $70, $b3, $07, $22, $79, $57, $b7, $ca, $20, $61,
    $a8, $16, $ac, $7a, $2b, $3d, $9a, $e9, $95, $a5, $11, $9c, $38, $5b,
    $60, $3b, $f6, $f6, $c5, $de, $4d, $c5, $ec, $b5, $df, $a4, $a4, $1c,
    $68, $66, $2e, $b2, $5b, $63, $8b, $7e, $26, $20, $ba, $89, $8d, $07,
    $da, $6c, $49, $91, $e7, $6c, $c0, $ec, $d1, $ad, $34, $21, $07, $70,
    $67, $e4, $7c, $18, $f5, $8a, $92, $a7, $2a, $d4, $31, $99, $ec, $b7,
    $bd, $84, $e7, $d3, $af, $b9, $01, $9f, $0e, $9d, $d0, $fb, $aa, $48,
    $73, $00, $b1, $30, $81, $e3, $3c, $90, $28, $76, $43, $6f, $7b, $03,
    $c3, $45, $52, $84, $81, $d3, $62, $81, $5e, $24, $fe, $59, $da, $c5,
    $ac, $34, $66, $0d, $4c, $8a, $76, $cb, $99, $a7, $c7, $de, $93, $eb,
    $95, $6c, $d6, $bc, $88, $e5, $8d, $90, $10, $34, $94, $4a, $09, $4b,
    $01, $80, $3a, $43, $c6, $72, $b9, $68, $8c, $0e, $01, $d8, $f4, $fc,
    $91, $c6, $2a, $3f, $88, $02, $1f, $7b, $d6, $a6, $51, $b1, $a8, $8f,
    $43, $aa, $4e, $f2, $76, $53, $d1, $2b, $f8, $b7, $09, $9f, $df, $6b,
    $46, $10, $82, $f8, $e9, $39, $10, $7b, $fd, $2f, $72, $10, $08, $7d,
    $32, $6c, $37, $52, $00, $f1, $f5, $1e, $7e, $74, $a3, $41, $31, $90,
    $1b, $cd, $08, $63, $52, $1f, $f8, $d6, $76, $c4, $85, $81, $86, $87,
    $36, $c5, $e5, $1b, $16, $a4, $e3, $92, $15, $ea, $0b, $17, $c4, $73,
    $59, $74, $c5, $16 );

  dsa_priv : array[0..27] of byte = (
    $6c, $ca, $ee, $f6, $d7, $3b, $4e, $80, $f1, $1c, $17, $b8, $e9, $62,
    $7c, $03, $66, $35, $ba, $c3, $94, $23, $50, $5e, $40, $7e, $5c, $b7 );
var
   st_kat_cipher_tests: array of TST_KAT_CIPHER;
   st_kat_asym_cipher_tests: array of TST_KAT_ASYM_CIPHER;
   rsa_pub_key, rsa_enc_params, rsa_priv_key,
   rsa_crt_key, tls13_kdf_early_secret_params,
   tls13_kdf_client_early_secret_params,
   tls12prf_params, pbkdf2_params, sshkdf_params,
   kbkdf_params, hkdf_params, sskdf_params,
   x963kdf_params, x942kdf_params :array of TST_KAT_PARAM ;
   st_kat_kdf_tests: array of TST_KAT_KDF;
   st_kat_drbg_tests :array of TST_KAT_DRBG ;
   st_kat_kas_tests :array of TST_KAT_KAS;
    dh_group, dh_host_key, dh_peer_key, ecdsa_prime_key,
    ecdsa_bin_key, dsa_key,
    ecdh_group, ecdh_host_key, ecdh_peer_key: array of TST_KAT_PARAM;
   st_kat_sign_tests :array of TST_KAT_SIGN;

   tls13_kdf_extract_mode: int = 1;
   tls13_kdf_expand_mode: int = 2;
   pbkdf2_iterations: int = 4096;
   pbkdf2_pkcs5: int = 1;
   sshkdf_type:int = 65;

implementation

function get_ST_KAT_SIGN(
    desc,
    algorithm,
    mdalgorithm      : PUTF8Char;
    key              : PST_KAT_PARAM;
    sig_expected     : PByte;
    sig_expected_len : size_t):  TST_KAT_SIGN;
begin
    Result.desc          := desc;
    Result.algorithm     := algorithm;
    Result.mdalgorithm   := mdalgorithm ;
    Result.key            := key;
    Result.sig_expected      := sig_expected;
    Result.sig_expected_len  := sig_expected_len;
end;

function get_ST_KAT_KAS(
    desc,
    algorithm     : PUTF8Char;
    key_group,
    key_host_data,
    key_peer_data : PST_KAT_PARAM;
    expected      : PByte;
    expected_len  : size_t): TST_KAT_KAS;
begin
    Result.desc          := desc;
    Result.algorithm     := algorithm;
    Result.key_group     := key_group;
    Result.key_host_data := key_host_data;
    Result.key_peer_data := key_peer_data;
    Result.expected      := expected;
    Result.expected_len  := expected_len;
end;


function get_ST_KAT_DRBG(
    desc,
    algorithm,
    param_name,
    param_value      : PUTF8Char;
    entropyin        : PByte;
    entropyinlen     : size_t;
    nonce            : PByte;
    noncelen         : size_t;
    persstr          : PByte;
    persstrlen       : size_t;
    entropyinpr1     : PByte;
    entropyinpr1len  : size_t;
    entropyinpr2     : PByte;
    entropyinpr2len  : size_t;
    entropyaddin1    : PByte;
    entropyaddin1len : size_t;
    entropyaddin2    : PByte;
    entropyaddin2len : size_t;
    expected         : PByte;
    expectedlen      : size_t): TST_KAT_DRBG;
begin
    Result.desc             := desc ;
    Result.algorithm        := algorithm;
    Result.param_name       := param_name;
    Result.param_value      :=  param_value;
    Result.entropyin        :=  entropyin;
    Result.entropyinlen     :=  entropyinlen;
    Result.nonce            :=  nonce;
    Result.noncelen         :=  noncelen;
    Result.persstr          :=  persstr;
    Result.persstrlen       :=  persstrlen;
    Result.entropyinpr1     :=  entropyinpr1;
    Result.entropyinpr1len  :=  entropyinpr1len;
    Result.entropyinpr2     :=  entropyinpr2;
    Result.entropyinpr2len  :=  entropyinpr2len;
    Result.entropyaddin1    :=  entropyaddin1;
    Result.entropyaddin1len :=  entropyaddin1len;
    Result.entropyaddin2    :=  entropyaddin2;
    Result.entropyaddin2len :=  entropyaddin2len;
    Result.expected         :=  expected;
    Result.expectedlen      :=  expectedlen;
end;


function get_ST_KAT_KDF(
    desc,
    algorithm    : PUTF8Char;
    params       : PST_KAT_PARAM;
    expected     : PByte;
    expected_len : size_t):  TST_KAT_KDF;
begin
     Result.desc        :=  desc;
    Result.algorithm    :=  algorithm ;
    Result.params       :=  params ;
    Result.expected     :=  expected;
    Result.expected_len :=  expected_len;
end;

function get_ST_KAT_PARAM(
    name     : PUTF8Char;
    &type    : size_t;
    data     : Pointer;
    data_len : size_t): TST_KAT_PARAM;
begin
   Result.name:= name;
   Result.&type    := &type;
   Result.data     := data;
   Result.data_len := data_len;
end;

function get_ST_KAT_ASYM_CIPHER(
    desc,
    algorithm    : PUTF8Char;
    encrypt      : integer;
    key,
    postinit     : PST_KAT_PARAM;
    _in          : PByte;
    in_len       : size_t;
    expected     : PByte;
    expected_len : size_t): TST_KAT_ASYM_CIPHER;
begin
    Result.desc         :=  desc;
    Result.algorithm    :=  algorithm ;
    Result.encrypt      :=  encrypt ;
    Result.key          :=  key;
    Result.postinit     :=  postinit ;
    Result._in          :=  _in;
    Result.in_len       :=  in_len;
    Result.expected     :=  expected;
    Result.expected_len :=  expected_len;
end;

function get_ST_KAT(
    desc,
    algorithm    : PUTF8Char;
    pt           : PByte;
    pt_len       : size_t;
    expected     : PByte;
    expected_len : size_t): TST_KAT;
begin
    Result.desc         := desc;
    Result.algorithm    := algorithm;
    Result.pt           := pt;
    Result.pt_len       := pt_len;
    Result.expected     := expected;
    Result.expected_len := expected_len;
end;

function get_ST_KAT_CIPHER(
    base : TST_KAT;
    mode : integer;
    key : PByte;
    key_len : size_t;
    iv : PByte;
    iv_len : size_t;
    aad : PByte;
    aad_len : size_t;
    tag : PByte;
    tag_len : size_t): TST_KAT_CIPHER;
begin
    Result.base := base;
    Result.mode :=  mode;
    Result.key :=  key;
    Result.key_len :=  key_len;
    Result.iv :=  iv;
    Result.iv_len :=  iv_len;
    Result.aad :=  aad;
    Result.aad_len :=  aad_len;
    Result.tag :=  tag;
    Result.tag_len := tag_len;
end;


initialization

st_kat_cipher_tests := [

        get_ST_KAT_CIPHER(
        get_ST_KAT(
                    'TDES',
                    'DES-EDE3-CBC',
                    (@des_ede3_cbc_pt), sizeof(des_ede3_cbc_pt),
                    (@des_ede3_cbc_ct), sizeof(des_ede3_cbc_ct)
                ),
                1 or 2,
                (@des_ede3_cbc_key), sizeof(des_ede3_cbc_key),
                (@des_ede3_cbc_iv), sizeof(des_ede3_cbc_iv),
                nil, 0, nil, 0
            ),

        get_ST_KAT_CIPHER(
        get_ST_KAT(
                    'AES_GCM',
                    'AES-256-GCM',
                    (@aes_256_gcm_pt), sizeof(aes_256_gcm_pt),
                    (@aes_256_gcm_ct), sizeof(aes_256_gcm_ct)
                ),
                1 or 2,
                (@aes_256_gcm_key), sizeof(aes_256_gcm_key),
                (@aes_256_gcm_iv), sizeof(aes_256_gcm_iv),
                (@aes_256_gcm_aad), sizeof(aes_256_gcm_aad),
                (@aes_256_gcm_tag), sizeof(aes_256_gcm_tag)
            ),
        get_ST_KAT_CIPHER(
        get_ST_KAT(
                    'AES_ECB_Decrypt',
                    'AES-128-ECB',
                    (@aes_128_ecb_pt), sizeof(aes_128_ecb_pt),
                    (@aes_128_ecb_ct), sizeof(aes_128_ecb_ct)
                ),
                2,
                (@aes_128_ecb_key), sizeof(aes_128_ecb_key),
                nil, 0, nil, 0,
                nil, 0
            )
];

 st_kat_asym_cipher_tests := [
    get_ST_KAT_ASYM_CIPHER(
        'RSA_Encrypt',
        'RSA',
        1,
        @rsa_pub_key,
        @rsa_enc_params,
        (@rsa_asym_plaintext_encrypt), sizeof(rsa_asym_plaintext_encrypt),
        (@rsa_asym_expected_encrypt), sizeof(rsa_asym_expected_encrypt)
    ),
    get_ST_KAT_ASYM_CIPHER(
        'RSA_Decrypt',
        'RSA',
        0,
        @rsa_priv_key,
        @rsa_enc_params,
        (@rsa_asym_expected_encrypt), sizeof(rsa_asym_expected_encrypt),
        (@rsa_asym_plaintext_encrypt), sizeof(rsa_asym_plaintext_encrypt)
    ),
    get_ST_KAT_ASYM_CIPHER(
        'RSA_Decrypt',
        'RSA',
        0,
        @rsa_crt_key,
        @rsa_enc_params,
        (@rsa_asym_expected_encrypt), sizeof(rsa_asym_expected_encrypt),
        (@rsa_asym_plaintext_encrypt), sizeof(rsa_asym_plaintext_encrypt)
    )
];

   rsa_pub_key := [
    get_ST_KAT_PARAM( 'n', 2, (@rsa_n), sizeof(rsa_n) ),
    get_ST_KAT_PARAM( 'e', 2, (@rsa_e), sizeof(rsa_e) ),
    get_ST_KAT_PARAM( '', 0, nil , 0 )
];

 rsa_enc_params := [
    get_ST_KAT_PARAM( 'pad-mode', 4, (@pad_mode_none), (sizeof(pad_mode_none) - 1) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];

 rsa_priv_key := [
    get_ST_KAT_PARAM( 'n', 2, (@rsa_n), sizeof(rsa_n) ),
    get_ST_KAT_PARAM( 'e', 2, (@rsa_e), sizeof(rsa_e) ),
    get_ST_KAT_PARAM( 'd', 2, (@rsa_d), sizeof(rsa_d) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];

  rsa_crt_key := [
    get_ST_KAT_PARAM( 'n', 2, (@rsa_n), sizeof(rsa_n) ),
    get_ST_KAT_PARAM( 'e', 2, (@rsa_e), sizeof(rsa_e) ),
    get_ST_KAT_PARAM( 'd', 2, (@rsa_d), sizeof(rsa_d) ),
    get_ST_KAT_PARAM( 'rsa-factor', 2, (@rsa_p), sizeof(rsa_p) ),
    get_ST_KAT_PARAM( 'rsa-factor', 2, (@rsa_q), sizeof(rsa_q) ),
    get_ST_KAT_PARAM( 'rsa-exponent', 2, (@rsa_dp), sizeof(rsa_dp) ),
    get_ST_KAT_PARAM( 'rsa-exponent', 2, (@rsa_dq), sizeof(rsa_dq) ),
    get_ST_KAT_PARAM( 'rsa-coefficient', 2, (@rsa_qInv), sizeof(rsa_qInv) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];

  st_kat_kdf_tests:= [

    get_ST_KAT_KDF(
        'TLS13_KDF_EXTRACT',
        'TLS13-KDF',
        @tls13_kdf_early_secret_params,
        (@tls13_kdf_early_secret), sizeof(tls13_kdf_early_secret)
    ),
    get_ST_KAT_KDF(
        'TLS13_KDF_EXPAND',
        'TLS13-KDF',
        @tls13_kdf_client_early_secret_params,
        (@tls13_kdf_client_early_traffic_secret), sizeof(tls13_kdf_client_early_traffic_secret)
    ),
    get_ST_KAT_KDF(
        'TLS12_PRF',
        'TLS1-PRF',
        @tls12prf_params,
        (@tls12prf_expected), sizeof(tls12prf_expected)
    ),
    get_ST_KAT_KDF(
        'PBKDF2',
        'PBKDF2',
        @pbkdf2_params,
        (@pbkdf2_expected), sizeof(pbkdf2_expected)
    ),
    get_ST_KAT_KDF(
        'SSHKDF',
        'SSHKDF',
        @sshkdf_params,
        (@sshkdf_expected), sizeof(sshkdf_expected)
    ),
    get_ST_KAT_KDF(
        'KBKDF',
        'KBKDF',
        @kbkdf_params,
        (@kbkdf_expected), sizeof(kbkdf_expected)
    ),
    get_ST_KAT_KDF(
        'HKDF',
        'HKDF',
        @hkdf_params,
        (@hkdf_expected), sizeof(hkdf_expected)
    ),
    get_ST_KAT_KDF(
        'SSKDF',
        'SSKDF',
        @sskdf_params,
        (@sskdf_expected), sizeof(sskdf_expected)
    ),
    get_ST_KAT_KDF(
        'X963KDF',
        'X963KDF',
        @x963kdf_params,
        (@x963kdf_expected), sizeof(x963kdf_expected)
    ),
    get_ST_KAT_KDF(
        'X942KDF',
        'X942KDF-ASN1',
        @x942kdf_params,
        (@x942kdf_expected), sizeof(x942kdf_expected)
    )
];
   tls13_kdf_early_secret_params:= [
    get_ST_KAT_PARAM( 'mode', 1, (@tls13_kdf_extract_mode), sizeof(tls13_kdf_extract_mode) ),
    get_ST_KAT_PARAM( 'digest', 4, (@tls13_kdf_digest), (sizeof(tls13_kdf_digest) - 1) ),
    get_ST_KAT_PARAM( 'key', 5, (@tls13_kdf_psk), sizeof(tls13_kdf_psk) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
   ];

    tls13_kdf_client_early_secret_params := [
    get_ST_KAT_PARAM( 'mode', 1, (@tls13_kdf_expand_mode), sizeof(tls13_kdf_expand_mode) ),
    get_ST_KAT_PARAM( 'digest', 4, (@tls13_kdf_digest), (sizeof(tls13_kdf_digest) - 1) ),
    get_ST_KAT_PARAM( 'key', 5, (@tls13_kdf_early_secret), sizeof(tls13_kdf_early_secret) ),
    get_ST_KAT_PARAM( 'data', 5, (@tls13_kdf_client_hello_hash), sizeof(tls13_kdf_client_hello_hash) ),
    get_ST_KAT_PARAM( 'prefix', 5, (@tls13_kdf_prefix), sizeof(tls13_kdf_prefix) ),
    get_ST_KAT_PARAM( 'label', 5, (@tls13_kdf_client_early_secret_label), sizeof(tls13_kdf_client_early_secret_label) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];
     tls12prf_params := [
    get_ST_KAT_PARAM('digest', 4, (@tls12prf_digest), (sizeof(tls12prf_digest) - 1) ),
    get_ST_KAT_PARAM('secret', 5, (@tls12prf_secret), sizeof(tls12prf_secret) ),
    get_ST_KAT_PARAM('seed', 5, (@tls12prf_seed), sizeof(tls12prf_seed) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
];
    pbkdf2_params := [
    get_ST_KAT_PARAM('digest', 4, (@pbkdf2_digest), (sizeof(pbkdf2_digest) - 1) ),
    get_ST_KAT_PARAM('pass', 5, (@pbkdf2_password), sizeof(pbkdf2_password) ),
    get_ST_KAT_PARAM('salt', 5, (@pbkdf2_salt), sizeof(pbkdf2_salt) ),
    get_ST_KAT_PARAM('iter', 1, (@pbkdf2_iterations), sizeof(pbkdf2_iterations) ),
    get_ST_KAT_PARAM('pkcs5', 1, (@pbkdf2_pkcs5), sizeof(pbkdf2_pkcs5) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
];
   sshkdf_params := [
    get_ST_KAT_PARAM('digest', 4, (@sshkdf_digest), (sizeof(sshkdf_digest) - 1) ),
    get_ST_KAT_PARAM('type', 4, (@sshkdf_type), sizeof(sshkdf_type) ),
    get_ST_KAT_PARAM('key', 5, (@sshkdf_key), sizeof(sshkdf_key) ),
    get_ST_KAT_PARAM('xcghash', 5, (@sshkdf_xcghash), sizeof(sshkdf_xcghash) ),
    get_ST_KAT_PARAM('session_id', 5, (@sshkdf_session_id), sizeof(sshkdf_session_id) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

    kbkdf_params := [
    get_ST_KAT_PARAM('digest', 4, (@kbkdf_digest), (sizeof(kbkdf_digest) - 1) ),
    get_ST_KAT_PARAM('mac', 4, (@kbkdf_mac), (sizeof(kbkdf_mac) - 1) ),
    get_ST_KAT_PARAM('key', 5, (@kbkdf_key), sizeof(kbkdf_key) ),
    get_ST_KAT_PARAM('salt', 5, (@kbkdf_salt), sizeof(kbkdf_salt) ),
    get_ST_KAT_PARAM('info', 5, (@kbkdf_prfinput), sizeof(kbkdf_prfinput) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

    hkdf_params := [
    get_ST_KAT_PARAM('digest', 4, (@hkdf_digest), (sizeof(hkdf_digest) - 1) ),
    get_ST_KAT_PARAM('key', 5, (@hkdf_secret), sizeof(hkdf_secret) ),
    get_ST_KAT_PARAM('salt', 5, (@hkdf_salt), sizeof(hkdf_salt) ),
    get_ST_KAT_PARAM('info', 5, (@hkdf_info), sizeof(hkdf_info) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

   sskdf_params := [
    get_ST_KAT_PARAM('digest', 4, (@sskdf_digest), (sizeof(sskdf_digest) - 1) ),
    get_ST_KAT_PARAM('key', 5, (@sskdf_secret), sizeof(sskdf_secret) ),
    get_ST_KAT_PARAM('info', 5, (@sskdf_otherinfo), sizeof(sskdf_otherinfo) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

   x963kdf_params := [
    get_ST_KAT_PARAM('digest', 4, (@x963kdf_digest), (sizeof(x963kdf_digest) - 1) ),
    get_ST_KAT_PARAM('key', 5, (@x963kdf_secret), sizeof(x963kdf_secret) ),
    get_ST_KAT_PARAM('info', 5, (@x963kdf_otherinfo), sizeof(x963kdf_otherinfo) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

   x942kdf_params := [
    get_ST_KAT_PARAM('digest', 4, (x942kdf_digest), (Length(x942kdf_digest) - 1) ),
    get_ST_KAT_PARAM('cekalg', 4, (x942kdf_cekalg), (Length(x942kdf_cekalg) - 1) ),
    get_ST_KAT_PARAM('key', 5, (@x942kdf_secret), sizeof(x942kdf_secret) ),
    get_ST_KAT_PARAM('', 0, Pointer(0) , 0 )
   ];

    st_kat_drbg_tests := [

    get_ST_KAT_DRBG(
        'HASH',
        'HASH-DRBG', 'digest', 'SHA256',
        (@drbg_hash_sha256_pr_entropyin), sizeof(drbg_hash_sha256_pr_entropyin),
        (@drbg_hash_sha256_pr_nonce), sizeof(drbg_hash_sha256_pr_nonce),
        (@drbg_hash_sha256_pr_persstr), sizeof(drbg_hash_sha256_pr_persstr),
        (@drbg_hash_sha256_pr_entropyinpr0), sizeof(drbg_hash_sha256_pr_entropyinpr0),
        (@drbg_hash_sha256_pr_entropyinpr1), sizeof(drbg_hash_sha256_pr_entropyinpr1),
        (@drbg_hash_sha256_pr_addin0), sizeof(drbg_hash_sha256_pr_addin0),
        (@drbg_hash_sha256_pr_addin1), sizeof(drbg_hash_sha256_pr_addin1),
        (@drbg_hash_sha256_pr_expected), sizeof(drbg_hash_sha256_pr_expected)
    ),
    get_ST_KAT_DRBG(
        'CTR',
        'CTR-DRBG', 'cipher', 'AES-128-CTR',
        (@drbg_ctr_aes128_pr_df_entropyin), sizeof(drbg_ctr_aes128_pr_df_entropyin),
        (@drbg_ctr_aes128_pr_df_nonce), sizeof(drbg_ctr_aes128_pr_df_nonce),
        (@drbg_ctr_aes128_pr_df_persstr), sizeof(drbg_ctr_aes128_pr_df_persstr),
        (@drbg_ctr_aes128_pr_df_entropyinpr0), sizeof(drbg_ctr_aes128_pr_df_entropyinpr0),
        (@drbg_ctr_aes128_pr_df_entropyinpr1), sizeof(drbg_ctr_aes128_pr_df_entropyinpr1),
        (@drbg_ctr_aes128_pr_df_addin0), sizeof(drbg_ctr_aes128_pr_df_addin0),
        (@drbg_ctr_aes128_pr_df_addin1), sizeof(drbg_ctr_aes128_pr_df_addin1),
        (@drbg_ctr_aes128_pr_df_expected), sizeof(drbg_ctr_aes128_pr_df_expected)
    ),
    get_ST_KAT_DRBG(
        'HMAC',
        'HMAC-DRBG', 'digest', 'SHA1',
        (@drbg_hmac_sha1_pr_entropyin), sizeof(drbg_hmac_sha1_pr_entropyin),
        (@drbg_hmac_sha1_pr_nonce), sizeof(drbg_hmac_sha1_pr_nonce),
        (@drbg_hmac_sha1_pr_persstr), sizeof(drbg_hmac_sha1_pr_persstr),
        (@drbg_hmac_sha1_pr_entropyinpr0), sizeof(drbg_hmac_sha1_pr_entropyinpr0),
        (@drbg_hmac_sha1_pr_entropyinpr1), sizeof(drbg_hmac_sha1_pr_entropyinpr1),
        (@drbg_hmac_sha1_pr_addin0), sizeof(drbg_hmac_sha1_pr_addin0),
        (@drbg_hmac_sha1_pr_addin1), sizeof(drbg_hmac_sha1_pr_addin1),
        (@drbg_hmac_sha1_pr_expected), sizeof(drbg_hmac_sha1_pr_expected)
    )
];
   st_kat_kas_tests := [
    get_ST_KAT_KAS(
        'DH',
        'DH',
        @dh_group,
        @dh_host_key,
        @dh_peer_key,
        (@dh_secret_expected), sizeof(dh_secret_expected)
    ),
    get_ST_KAT_KAS(
        'ECDH',
        'EC',
        @ecdh_group,
        @ecdh_host_key,
        @ecdh_peer_key,
        (@ecdh_secret_expected), sizeof(ecdh_secret_expected)
    )];

    dh_group := [
    get_ST_KAT_PARAM( 'p', 2, (@dh_p), sizeof(dh_p) ),
    get_ST_KAT_PARAM( 'q', 2, (@dh_q), sizeof(dh_q) ),
    get_ST_KAT_PARAM( 'g', 2, (@dh_g), sizeof(dh_g) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];


  dh_host_key := [
    get_ST_KAT_PARAM( 'pub', 2, (@dh_pub), sizeof(dh_pub) ),
    get_ST_KAT_PARAM( 'priv', 2, (@dh_priv), sizeof(dh_priv) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];


  dh_peer_key := [
    get_ST_KAT_PARAM( 'pub', 2, (@dh_peer_pub), sizeof(dh_peer_pub) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];

  ecdh_group := [
      get_ST_KAT_PARAM( 'group', 4, (ecdh_curve_name), (Length(ecdh_curve_name) - 1) ),
      get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
  ];
  ecdh_host_key := [
      get_ST_KAT_PARAM( 'pub', 5, (@ecdh_pub), sizeof(ecdh_pub) ),
      get_ST_KAT_PARAM( 'priv', 2, (@ecdh_privd), sizeof(ecdh_privd) ),
      get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
  ];
  ecdh_peer_key := [
      get_ST_KAT_PARAM( 'pub', 5, (@ecdh_peer_pub), sizeof(ecdh_peer_pub) ),
      get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
  ];

  st_kat_sign_tests := [
    get_ST_KAT_SIGN(
        'RSA',
        'RSA',
        'SHA-256',
        @rsa_crt_key,
        (@rsa_expected_sig), sizeof(rsa_expected_sig)
    ),

    get_ST_KAT_SIGN(
        'ECDSA',
        'EC',
        'SHA-256',
        @ecdsa_prime_key,nil,0
    ),

    get_ST_KAT_SIGN(
        'ECDSA',
        'EC',
        'SHA-256',
        @ecdsa_bin_key,nil,0
    ),

    get_ST_KAT_SIGN(
        'DSA',
        'DSA',
        'SHA-256',
        @dsa_key,nil,0
    )];

    ecdsa_prime_key := [
        get_ST_KAT_PARAM( 'group', 4, (ecd_prime_curve_name), (Length(ecd_prime_curve_name) - 1) ),
        get_ST_KAT_PARAM( 'pub', 5, (@ecd_prime_pub), sizeof(ecd_prime_pub) ),
        get_ST_KAT_PARAM( 'priv', 2, (@ecd_prime_priv), sizeof(ecd_prime_priv) ),
        get_ST_KAT_PARAM( '', 0, nil, 0 )
   ];

   ecdsa_bin_key := [
    get_ST_KAT_PARAM( 'group', 4, (ecd_bin_curve_name), (Length(ecd_bin_curve_name) - 1) ),
    get_ST_KAT_PARAM( 'pub', 5, (@ecd_bin_pub), sizeof(ecd_bin_pub) ),
    get_ST_KAT_PARAM( 'priv', 2, (@ecd_bin_priv), sizeof(ecd_bin_priv) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
  ];

  dsa_key := [
    get_ST_KAT_PARAM( 'p', 2, (@dsa_p), sizeof(dsa_p) ),
    get_ST_KAT_PARAM( 'q', 2, (@dsa_q), sizeof(dsa_q) ),
    get_ST_KAT_PARAM( 'g', 2, (@dsa_g), sizeof(dsa_g) ),
    get_ST_KAT_PARAM( 'pub', 2, (@dsa_pub), sizeof(dsa_pub) ),
    get_ST_KAT_PARAM( 'priv', 2, (@dsa_priv), sizeof(dsa_priv) ),
    get_ST_KAT_PARAM( '', 0, Pointer(0) , 0 )
];

end.
