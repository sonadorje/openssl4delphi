unit openssl3.crypto.ec.ec_curve;
{$INCLUDE Config.inc}
interface
uses OpenSSL.Api, SysUtils;

type
  TEC_NIST_PRIME_192 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_NIST_PRIME_224 = record
    h: TEC_CURVE_DATA;
    data: array [0..187] of Byte;
  end;

  TEC_NIST_PRIME_384 = record
    h: TEC_CURVE_DATA;
    data: array [0..307] of Byte;
  end;

  TEC_NIST_PRIME_521 = record
    h: TEC_CURVE_DATA;
    data: array [0..415] of Byte;
  end;

  TEC_X9_62_PRIME_192V2 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_X9_62_PRIME_192V3 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_X9_62_PRIME_239V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_PRIME_239V2 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_PRIME_239V3 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_PRIME_256V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..211] of Byte;
  end;

  TEC_SECG_PRIME_112R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..103] of Byte;
  end;

  TEC_SECG_PRIME_112R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..103] of Byte;
  end;

  TEC_SECG_PRIME_128R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..115] of Byte;
  end;

  TEC_SECG_PRIME_128R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..115] of Byte;
  end;

  TEC_SECG_PRIME_160K1 = record
    h: TEC_CURVE_DATA;
    data: array [0..125] of Byte;
  end;

  TEC_SECG_PRIME_160R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..145] of Byte;
  end;

  TEC_SECG_PRIME_160R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..145] of Byte;
  end;

  TEC_SECG_PRIME_192K1 = record
    h: TEC_CURVE_DATA;
    data: array [0..143] of Byte;
  end;

  TEC_SECG_PRIME_224K1 = record
    h: TEC_CURVE_DATA;
    data: array [0..173] of Byte;
  end;

  TEC_SECG_PRIME_256K1 = record
    h: TEC_CURVE_DATA;
    data: array [0..191] of Byte;
  end;

  TEC_WTLS_8 = record
    h: TEC_CURVE_DATA;
    data: array [0..89] of Byte;
  end;

  TEC_WTLS_12 = record
    h: TEC_CURVE_DATA;
    data: array [0..167] of Byte;
  end;

  TEC_SECG_CHAR2_113R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..109] of Byte;
  end;

  TEC_SECG_CHAR2_113R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..109] of Byte;
  end;

  TEC_SECG_CHAR2_131R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..121] of Byte;
  end;

  TEC_SECG_CHAR2_131R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..121] of Byte;
  end;

  TEC_NIST_CHAR2_163K = record
    h: TEC_CURVE_DATA;
    data: array [0..125] of Byte;
  end;

  TEC_SECG_CHAR2_163R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..125] of Byte;
  end;

  TEC_NIST_CHAR2_163B = record
    h: TEC_CURVE_DATA;
    data: array [0..125] of Byte;
  end;

  TEC_SECG_CHAR2_193R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..169] of Byte;
  end;

  TEC_SECG_CHAR2_193R2 = record
    h: TEC_CURVE_DATA;
    data: array [0..169] of Byte;
  end;

  TEC_NIST_CHAR2_233K = record
    h: TEC_CURVE_DATA;
    data: array [0..179] of Byte;
  end;

  TEC_NIST_CHAR2_233B = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_SECG_CHAR2_239K1 = record
    h: TEC_CURVE_DATA;
    data: array [0..179] of Byte;
  end;

  TEC_NIST_CHAR2_283K = record
    h: TEC_CURVE_DATA;
    data: array [0..215] of Byte;
  end;

  TEC_NIST_CHAR2_283B = record
    h: TEC_CURVE_DATA;
    data: array [0..235] of Byte;
  end;

  TEC_NIST_CHAR2_409K = record
    h: TEC_CURVE_DATA;
    data: array [0..311] of Byte;
  end;

  TEC_NIST_CHAR2_409B = record
    h: TEC_CURVE_DATA;
    data: array [0..331] of Byte;
  end;

  TEC_NIST_CHAR2_571K = record
    h: TEC_CURVE_DATA;
    data: array [0..431] of Byte;
  end;

  TEC_NIST_CHAR2_571B = record
    h: TEC_CURVE_DATA;
    data: array [0..451] of Byte;
  end;

  TEC_X9_62_CHAR2_163V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..145] of Byte;
  end;

  TEC_X9_62_CHAR2_163V2 = record
    h: TEC_CURVE_DATA;
    data: array [0..145] of Byte;
  end;

  TEC_X9_62_CHAR2_163V3 = record
    h: TEC_CURVE_DATA;
    data: array [0..145] of Byte;
  end;

  TEC_X9_62_CHAR2_176V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..137] of Byte;
  end;

  TEC_X9_62_CHAR2_191V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_X9_62_CHAR2_191V2 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_X9_62_CHAR2_191V3 = record
    h: TEC_CURVE_DATA;
    data: array [0..163] of Byte;
  end;

  TEC_X9_62_CHAR2_208W1 = record
    h: TEC_CURVE_DATA;
    data: array [0..161] of Byte;
  end;

  TEC_X9_62_CHAR2_239V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_CHAR2_239V2 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_CHAR2_239V3 = record
    h: TEC_CURVE_DATA;
    data: array [0..199] of Byte;
  end;

  TEC_X9_62_CHAR2_272W1 = record
    h: TEC_CURVE_DATA;
    data: array [0..209] of Byte;
  end;

  TEC_X9_62_CHAR2_304W1 = record
    h: TEC_CURVE_DATA;
    data: array [0..233] of Byte;
  end;

  TEC_X9_62_CHAR2_359V1 = record
    h: TEC_CURVE_DATA;
    data: array [0..289] of Byte;
  end;

  TEC_X9_62_CHAR2_368W1 = record
    h: TEC_CURVE_DATA;
    data: array [0..281] of Byte;
  end;

  TEC_X9_62_CHAR2_431R1 = record
    h: TEC_CURVE_DATA;
    data: array [0..323] of Byte;
  end;

  TEC_WTLS_1 = record
    h: TEC_CURVE_DATA;
    data: array [0..89] of Byte;
  end;

  TEC_IPSEC_155_ID3 = record
    h: TEC_CURVE_DATA;
    data: array [0..119] of Byte;
  end;

  TEC_IPSEC_185_ID4 = record
    h: TEC_CURVE_DATA;
    data: array [0..143] of Byte;
  end;

  TEC_brainpoolP160r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..119] of Byte;
  end;

  TEC_brainpoolP160t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..119] of Byte;
  end;

  TEC_brainpoolP192r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..143] of Byte;
  end;

  TEC_brainpoolP192t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..143] of Byte;
  end;

  TEC_brainpoolP224r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..167] of Byte;
  end;

  TEC_brainpoolP224t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..167] of Byte;
  end;

  TEC_brainpoolP256r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..191] of Byte;
  end;

  TEC_brainpoolP256t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..191] of Byte;
  end;

  TEC_brainpoolP320r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..239] of Byte;
  end;

  TEC_brainpoolP320t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..239] of Byte;
  end;

  TEC_brainpoolP384r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..287] of Byte;
  end;

  TEC_brainpoolP384t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..287] of Byte;
  end;

  TEC_brainpoolP512r1 = record
    h: TEC_CURVE_DATA;
    data: array [0..383] of Byte;
  end;

  TEC_brainpoolP512t1 = record
    h: TEC_CURVE_DATA;
    data: array [0..383] of Byte;
  end;

  TEC_WTLS_9 = record
    h: TEC_CURVE_DATA;
    data: array [0..125] of Byte;
  end;

  TEC_sm2p256v1 = record
    h: TEC_CURVE_DATA;
    data: array [0..191] of Byte;
  end;



function ec_curve_nid2curve( nid : integer):Pec_list_element;
function EC_GROUP_new_by_curve_name_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; nid : integer):PEC_GROUP;
function ec_group_new_from_data(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; curve : Tec_list_element):PEC_GROUP;

var
  curve_list_length: size_t;

const
  _EC_SECG_PRIME_112R1: TEC_SECG_PRIME_112R1 = (

   h:(field_type:NID_X9_62_prime_field; seed_len:20; param_len:14; cofactor:1);
   data: (
        (* seed *)
        $00, $F5, $0B, $02, $8E, $4D, $69, $6E, $67, $68, $75, $61,
        $51, $75, $29, $04, $72, $78, $3F, $B1,
        (* p *)
        $DB, $7C, $2A, $BF, $62, $E3, $5E, $66, $80, $76, $BE, $AD,
        $20, $8B,
        (* a *)
        $DB, $7C, $2A, $BF, $62, $E3, $5E, $66, $80, $76, $BE, $AD,
        $20, $88,
        (* b *)
        $65, $9E, $F8, $BA, $04, $39, $16, $EE, $DE, $89, $11, $70,
        $2B, $22,
        (* x *)
        $09, $48, $72, $39, $99, $5A, $5E, $E7, $6B, $55, $F9, $C2,
        $F0, $98,
        (* y *)
        $a8, $9c, $e5, $af, $87, $24, $c0, $a2, $3e, $0e, $0f, $f7,
        $75, $00,
        (* order *)
        $DB, $7C, $2A, $BF, $62, $E3, $5E, $76, $28, $DF, $AC, $65,
        $61, $C5
    )
);
  _EC_SECG_PRIME_112R2: TEC_SECG_PRIME_112R2 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:14;cofactor: 4
    );
    data:(
        (* seed *)
        $00, $27, $57, $A1, $11, $4D, $69, $6E, $67, $68, $75, $61,
        $51, $75, $53, $16, $C0, $5E, $0B, $D4,
        (* p *)
        $DB, $7C, $2A, $BF, $62, $E3, $5E, $66, $80, $76, $BE, $AD,
        $20, $8B,
        (* a *)
        $61, $27, $C2, $4C, $05, $F3, $8A, $0A, $AA, $F6, $5C, $0E,
        $F0, $2C,
        (* b *)
        $51, $DE, $F1, $81, $5D, $B5, $ED, $74, $FC, $C3, $4C, $85,
        $D7, $09,
        (* x *)
        $4B, $A3, $0A, $B5, $E8, $92, $B4, $E1, $64, $9D, $D0, $92,
        $86, $43,
        (* y *)
        $ad, $cd, $46, $f5, $88, $2e, $37, $47, $de, $f3, $6e, $95,
        $6e, $97,
        (* order *)
        $36, $DF, $0A, $AF, $D8, $B8, $D7, $59, $7C, $A1, $05, $20,
        $D0, $4B
    )
);
_EC_SECG_PRIME_128R1: TEC_SECG_PRIME_128R1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:16; cofactor:1
    );
    data:(
        (* seed *)
        $00, $0E, $0D, $4D, $69, $6E, $67, $68, $75, $61, $51, $75,
        $0C, $C0, $3A, $44, $73, $D0, $36, $79,
        (* p *)
        $FF, $FF, $FF, $FD, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FD, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FC,
        (* b *)
        $E8, $75, $79, $C1, $10, $79, $F4, $3D, $D8, $24, $99, $3C,
        $2C, $EE, $5E, $D3,
        (* x *)
        $16, $1F, $F7, $52, $8B, $89, $9B, $2D, $0C, $28, $60, $7C,
        $A5, $2C, $5B, $86,
        (* y *)
        $cf, $5a, $c8, $39, $5b, $af, $eb, $13, $c0, $2d, $a2, $92,
        $dd, $ed, $7a, $83,
        (* order *)
        $FF, $FF, $FF, $FE, $00, $00, $00, $00, $75, $A3, $0D, $1B,
        $90, $38, $A1, $15
    )
);
_EC_SECG_PRIME_128R2: TEC_SECG_PRIME_128R2 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:16;cofactor: 4
    );
    data:(
        (* seed *)
        $00, $4D, $69, $6E, $67, $68, $75, $61, $51, $75, $12, $D8,
        $F0, $34, $31, $FC, $E6, $3B, $88, $F4,
        (* p *)
        $FF, $FF, $FF, $FD, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF,
        (* a *)
        $D6, $03, $19, $98, $D1, $B3, $BB, $FE, $BF, $59, $CC, $9B,
        $BF, $F9, $AE, $E1,
        (* b *)
        $5E, $EE, $FC, $A3, $80, $D0, $29, $19, $DC, $2C, $65, $58,
        $BB, $6D, $8A, $5D,
        (* x *)
        $7B, $6A, $A5, $D8, $5E, $57, $29, $83, $E6, $FB, $32, $A7,
        $CD, $EB, $C1, $40,
        (* y *)
        $27, $b6, $91, $6a, $89, $4d, $3a, $ee, $71, $06, $fe, $80,
        $5f, $c3, $4b, $44,
        (* order *)
        $3F, $FF, $FF, $FF, $7F, $FF, $FF, $FF, $BE, $00, $24, $72,
        $06, $13, $B5, $A3
    )
);
_EC_SECG_PRIME_160K1: TEC_SECG_PRIME_160K1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:0; param_len:21; cofactor:1
    );
    data:(
        (* no seed *)
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FE, $FF, $FF, $AC, $73,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $07,
        (* x *)
        $00, $3B, $4C, $38, $2C, $E3, $7A, $A1, $92, $A4, $01, $9E,
        $76, $30, $36, $F4, $F5, $DD, $4D, $7E, $BB,
        (* y *)
        $00, $93, $8c, $f9, $35, $31, $8f, $dc, $ed, $6b, $c2, $82,
        $86, $53, $17, $33, $c3, $f0, $3c, $4f, $ee,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $B8,
        $FA, $16, $DF, $AB, $9A, $CA, $16, $B6, $B3
    )
);
_EC_SECG_PRIME_160R1: TEC_SECG_PRIME_160R1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:21; cofactor:1
    );
    data:(
        (* seed *)
        $10, $53, $CD, $E4, $2C, $14, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $53, $3B, $F3, $F8, $33, $45,
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $7F, $FF, $FF, $FF,
        (* a *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $7F, $FF, $FF, $FC,
        (* b *)
        $00, $1C, $97, $BE, $FC, $54, $BD, $7A, $8B, $65, $AC, $F8,
        $9F, $81, $D4, $D4, $AD, $C5, $65, $FA, $45,
        (* x *)
        $00, $4A, $96, $B5, $68, $8E, $F5, $73, $28, $46, $64, $69,
        $89, $68, $C3, $8B, $B9, $13, $CB, $FC, $82,
        (* y *)
        $00, $23, $a6, $28, $55, $31, $68, $94, $7d, $59, $dc, $c9,
        $12, $04, $23, $51, $37, $7a, $c5, $fb, $32,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $F4,
        $C8, $F9, $27, $AE, $D3, $CA, $75, $22, $57
    )
);
_EC_SECG_PRIME_160R2: TEC_SECG_PRIME_160R2 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:21; cofactor:1
    );
    data:(
        (* seed *)
        $B9, $9B, $99, $B0, $99, $B3, $23, $E0, $27, $09, $A4, $D6,
        $96, $E6, $76, $87, $56, $15, $17, $51,
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FE, $FF, $FF, $AC, $73,
        (* a *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FE, $FF, $FF, $AC, $70,
        (* b *)
        $00, $B4, $E1, $34, $D3, $FB, $59, $EB, $8B, $AB, $57, $27,
        $49, $04, $66, $4D, $5A, $F5, $03, $88, $BA,
        (* x *)
        $00, $52, $DC, $B0, $34, $29, $3A, $11, $7E, $1F, $4F, $F1,
        $1B, $30, $F7, $19, $9D, $31, $44, $CE, $6D,
        (* y *)
        $00, $fe, $af, $fe, $f2, $e3, $31, $f2, $96, $e0, $71, $fa,
        $0d, $f9, $98, $2c, $fe, $a7, $d4, $3f, $2e,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $35,
        $1E, $E7, $86, $A8, $18, $F3, $A1, $A1, $6B
    )
);
_EC_SECG_PRIME_192K1: TEC_SECG_PRIME_192K1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:0; param_len:24; cofactor:1
    );
    data:(
        (* no seed *)
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FF, $FF, $EE, $37,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $03,
        (* x *)
        $DB, $4F, $F1, $0E, $C0, $57, $E9, $AE, $26, $B0, $7D, $02,
        $80, $B7, $F4, $34, $1D, $A5, $D1, $B1, $EA, $E0, $6C, $7D,
        (* y *)
        $9b, $2f, $2f, $6d, $9c, $56, $28, $a7, $84, $41, $63, $d0,
        $15, $be, $86, $34, $40, $82, $aa, $88, $d9, $5e, $2f, $9d,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE,
        $26, $F2, $FC, $17, $0F, $69, $46, $6A, $74, $DE, $FD, $8D
    )
);
_EC_SECG_PRIME_224K1: TEC_SECG_PRIME_224K1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:0; param_len:29; cofactor:1
    );
    data:(
        (* no seed *)
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FE, $FF, $FF, $E5, $6D,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $05,
        (* x *)
        $00, $A1, $45, $5B, $33, $4D, $F0, $99, $DF, $30, $FC, $28,
        $A1, $69, $A4, $67, $E9, $E4, $70, $75, $A9, $0F, $7E, $65,
        $0E, $B6, $B7, $A4, $5C,
        (* y *)
        $00, $7e, $08, $9f, $ed, $7f, $ba, $34, $42, $82, $ca, $fb,
        $d6, $f7, $e3, $19, $f7, $c0, $b0, $bd, $59, $e2, $ca, $4b,
        $db, $55, $6d, $61, $a5,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01, $DC, $E8, $D2, $EC, $61, $84, $CA, $F0, $A9,
        $71, $76, $9F, $B1, $F7
    )
);

_EC_NIST_PRIME_224: TEC_NIST_PRIME_224 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:28; cofactor:1
    );
    data:(
        (* seed *)
        $BD, $71, $34, $47, $99, $D5, $C7, $FC, $DC, $45, $B5, $9F,
        $A3, $B9, $AB, $8F, $6A, $94, $8B, $C5,
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE,
        (* b *)
        $B4, $05, $0A, $85, $0C, $04, $B3, $AB, $F5, $41, $32, $56,
        $50, $44, $B0, $B7, $D7, $BF, $D8, $BA, $27, $0B, $39, $43,
        $23, $55, $FF, $B4,
        (* x *)
        $B7, $0E, $0C, $BD, $6B, $B4, $BF, $7F, $32, $13, $90, $B9,
        $4A, $03, $C1, $D3, $56, $C2, $11, $22, $34, $32, $80, $D6,
        $11, $5C, $1D, $21,
        (* y *)
        $bd, $37, $63, $88, $b5, $f7, $23, $fb, $4c, $22, $df, $e6,
        $cd, $43, $75, $a0, $5a, $07, $47, $64, $44, $d5, $81, $99,
        $85, $00, $7e, $34,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $16, $A2, $E0, $B8, $F0, $3E, $13, $DD, $29, $45,
        $5C, $5C, $2A, $3D
    )
);
_EC_SECG_PRIME_256K1: TEC_SECG_PRIME_256K1 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:0; param_len:32; cofactor:1
    );
    data:(
        (* no seed *)
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FC, $2F,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $07,
        (* x *)
        $79, $BE, $66, $7E, $F9, $DC, $BB, $AC, $55, $A0, $62, $95,
        $CE, $87, $0B, $07, $02, $9B, $FC, $DB, $2D, $CE, $28, $D9,
        $59, $F2, $81, $5B, $16, $F8, $17, $98,
        (* y *)
        $48, $3a, $da, $77, $26, $a3, $c4, $65, $5d, $a4, $fb, $fc,
        $0e, $11, $08, $a8, $fd, $17, $b4, $48, $a6, $85, $54, $19,
        $9c, $47, $d0, $8f, $fb, $10, $d4, $b8,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $BA, $AE, $DC, $E6, $AF, $48, $A0, $3B,
        $BF, $D2, $5E, $8C, $D0, $36, $41, $41
    )
);
_EC_NIST_PRIME_384: TEC_NIST_PRIME_384 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:48;cofactor: 1
    );
    data:(
        (* seed *)
        $A3, $35, $92, $6A, $A3, $19, $A2, $7A, $1D, $00, $89, $6A,
        $67, $73, $A4, $82, $7A, $CD, $AC, $73,
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF,
        $00, $00, $00, $00, $00, $00, $00, $00, $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF,
        $00, $00, $00, $00, $00, $00, $00, $00, $FF, $FF, $FF, $FC,
        (* b *)
        $B3, $31, $2F, $A7, $E2, $3E, $E7, $E4, $98, $8E, $05, $6B,
        $E3, $F8, $2D, $19, $18, $1D, $9C, $6E, $FE, $81, $41, $12,
        $03, $14, $08, $8F, $50, $13, $87, $5A, $C6, $56, $39, $8D,
        $8A, $2E, $D1, $9D, $2A, $85, $C8, $ED, $D3, $EC, $2A, $EF,
        (* x *)
        $AA, $87, $CA, $22, $BE, $8B, $05, $37, $8E, $B1, $C7, $1E,
        $F3, $20, $AD, $74, $6E, $1D, $3B, $62, $8B, $A7, $9B, $98,
        $59, $F7, $41, $E0, $82, $54, $2A, $38, $55, $02, $F2, $5D,
        $BF, $55, $29, $6C, $3A, $54, $5E, $38, $72, $76, $0A, $B7,
        (* y *)
        $36, $17, $de, $4a, $96, $26, $2c, $6f, $5d, $9e, $98, $bf,
        $92, $92, $dc, $29, $f8, $f4, $1d, $bd, $28, $9a, $14, $7c,
        $e9, $da, $31, $13, $b5, $f0, $b8, $c0, $0a, $60, $b1, $ce,
        $1d, $7e, $81, $9d, $7a, $43, $1d, $7c, $90, $ea, $0e, $5f,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $C7, $63, $4D, $81, $F4, $37, $2D, $DF, $58, $1A, $0D, $B2,
        $48, $B0, $A7, $7A, $EC, $EC, $19, $6A, $CC, $C5, $29, $73
    )
);
_EC_NIST_PRIME_521: TEC_NIST_PRIME_521 = (
    h:(
        field_type:NID_X9_62_prime_field;seed_len: 20;param_len: 66;cofactor: 1
    );
    data:(
        (* seed *)
        $D0, $9E, $88, $00, $29, $1C, $B8, $53, $96, $CC, $67, $17,
        $39, $32, $84, $AA, $A0, $DA, $64, $BA,
        (* p *)
        $01, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $01, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $00, $51, $95, $3E, $B9, $61, $8E, $1C, $9A, $1F, $92, $9A,
        $21, $A0, $B6, $85, $40, $EE, $A2, $DA, $72, $5B, $99, $B3,
        $15, $F3, $B8, $B4, $89, $91, $8E, $F1, $09, $E1, $56, $19,
        $39, $51, $EC, $7E, $93, $7B, $16, $52, $C0, $BD, $3B, $B1,
        $BF, $07, $35, $73, $DF, $88, $3D, $2C, $34, $F1, $EF, $45,
        $1F, $D4, $6B, $50, $3F, $00,
        (* x *)
        $00, $C6, $85, $8E, $06, $B7, $04, $04, $E9, $CD, $9E, $3E,
        $CB, $66, $23, $95, $B4, $42, $9C, $64, $81, $39, $05, $3F,
        $B5, $21, $F8, $28, $AF, $60, $6B, $4D, $3D, $BA, $A1, $4B,
        $5E, $77, $EF, $E7, $59, $28, $FE, $1D, $C1, $27, $A2, $FF,
        $A8, $DE, $33, $48, $B3, $C1, $85, $6A, $42, $9B, $F9, $7E,
        $7E, $31, $C2, $E5, $BD, $66,
        (* y *)
        $01, $18, $39, $29, $6a, $78, $9a, $3b, $c0, $04, $5c, $8a,
        $5f, $b4, $2c, $7d, $1b, $d9, $98, $f5, $44, $49, $57, $9b,
        $44, $68, $17, $af, $bd, $17, $27, $3e, $66, $2c, $97, $ee,
        $72, $99, $5e, $f4, $26, $40, $c5, $50, $b9, $01, $3f, $ad,
        $07, $61, $35, $3c, $70, $86, $a2, $72, $c2, $40, $88, $be,
        $94, $76, $9f, $d1, $66, $50,
        (* order *)
        $01, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FA, $51, $86,
        $87, $83, $BF, $2F, $96, $6B, $7F, $CC, $01, $48, $F7, $09,
        $A5, $D0, $3B, $B5, $C9, $B8, $89, $9C, $47, $AE, $BB, $6F,
        $B7, $1E, $91, $38, $64, $09
    )
);
_EC_NIST_PRIME_192: TEC_NIST_PRIME_192 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:24; cofactor:1
    );
    data:(
        (* seed *)
        $30, $45, $AE, $6F, $C8, $42, $2F, $64, $ED, $57, $95, $28,
        $D3, $81, $20, $EA, $E1, $21, $96, $D5,
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $64, $21, $05, $19, $E5, $9C, $80, $E7, $0F, $A7, $E9, $AB,
        $72, $24, $30, $49, $FE, $B8, $DE, $EC, $C1, $46, $B9, $B1,
        (* x *)
        $18, $8D, $A8, $0E, $B0, $30, $90, $F6, $7C, $BF, $20, $EB,
        $43, $A1, $88, $00, $F4, $FF, $0A, $FD, $82, $FF, $10, $12,
        (* y *)
        $07, $19, $2b, $95, $ff, $c8, $da, $78, $63, $10, $11, $ed,
        $6b, $24, $cd, $d5, $73, $f9, $77, $a1, $1e, $79, $48, $11,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $99, $DE, $F8, $36, $14, $6B, $C9, $B1, $B4, $D2, $28, $31
    )
);
_EC_X9_62_PRIME_192V2: TEC_X9_62_PRIME_192V2 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:24; cofactor:1
    );
    data:(
        (* seed *)
        $31, $A9, $2E, $E2, $02, $9F, $D1, $0D, $90, $1B, $11, $3E,
        $99, $07, $10, $F0, $D2, $1A, $C6, $B6,
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $CC, $22, $D6, $DF, $B9, $5C, $6B, $25, $E4, $9C, $0D, $63,
        $64, $A4, $E5, $98, $0C, $39, $3A, $A2, $16, $68, $D9, $53,
        (* x *)
        $EE, $A2, $BA, $E7, $E1, $49, $78, $42, $F2, $DE, $77, $69,
        $CF, $E9, $C9, $89, $C0, $72, $AD, $69, $6F, $48, $03, $4A,
        (* y *)
        $65, $74, $d1, $1d, $69, $b6, $ec, $7a, $67, $2b, $b8, $2a,
        $08, $3d, $f2, $f2, $b0, $84, $7d, $e9, $70, $b2, $de, $15,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE,
        $5F, $B1, $A7, $24, $DC, $80, $41, $86, $48, $D8, $DD, $31
    )
);
_EC_X9_62_PRIME_192V3: TEC_X9_62_PRIME_192V3 = (
    h:(
        field_type:NID_X9_62_prime_field; seed_len:20; param_len:24;cofactor: 1
    );
    data:(
        (* seed *)
        $C4, $69, $68, $44, $35, $DE, $B3, $78, $C4, $B6, $5C, $A9,
        $59, $1E, $2A, $57, $63, $05, $9A, $2E,
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $22, $12, $3D, $C2, $39, $5A, $05, $CA, $A7, $42, $3D, $AE,
        $CC, $C9, $47, $60, $A7, $D4, $62, $25, $6B, $D5, $69, $16,
        (* x *)
        $7D, $29, $77, $81, $00, $C6, $5A, $1D, $A1, $78, $37, $16,
        $58, $8D, $CE, $2B, $8B, $4A, $EE, $8E, $22, $8F, $18, $96,
        (* y *)
        $38, $a9, $0f, $22, $63, $73, $37, $33, $4b, $49, $dc, $b6,
        $6a, $6d, $c8, $f9, $97, $8a, $ca, $76, $48, $a9, $43, $b0,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7A, $62, $D0, $31, $C8, $3F, $42, $94, $F6, $40, $EC, $13
    )
);
_EC_X9_62_PRIME_239V1: TEC_X9_62_PRIME_239V1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len:20; param_len:30; cofactor:1
    );
    data:(
        (* seed *)
        $E4, $3B, $B4, $60, $F0, $B8, $0C, $C0, $C0, $B0, $75, $79,
        $8E, $94, $80, $60, $F8, $32, $1B, $7D,
        (* p *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $6B, $01, $6C, $3B, $DC, $F1, $89, $41, $D0, $D6, $54, $92,
        $14, $75, $CA, $71, $A9, $DB, $2F, $B2, $7D, $1D, $37, $79,
        $61, $85, $C2, $94, $2C, $0A,
        (* x *)
        $0F, $FA, $96, $3C, $DC, $A8, $81, $6C, $CC, $33, $B8, $64,
        $2B, $ED, $F9, $05, $C3, $D3, $58, $57, $3D, $3F, $27, $FB,
        $BD, $3B, $3C, $B9, $AA, $AF,
        (* y *)
        $7d, $eb, $e8, $e4, $e9, $0a, $5d, $ae, $6e, $40, $54, $ca,
        $53, $0b, $a0, $46, $54, $b3, $68, $18, $ce, $22, $6b, $39,
        $fc, $cb, $7b, $02, $f1, $ae,
        (* order *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $9E, $5E, $9A, $9F, $5D, $90, $71, $FB, $D1,
        $52, $26, $88, $90, $9D, $0B
    )
);
_EC_X9_62_PRIME_239V2: TEC_X9_62_PRIME_239V2 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len:20; param_len: 30;cofactor: 1
    );
    data:(
        (* seed *)
        $E8, $B4, $01, $16, $04, $09, $53, $03, $CA, $3B, $80, $99,
        $98, $2B, $E0, $9F, $CB, $9A, $E6, $16,
        (* p *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $61, $7F, $AB, $68, $32, $57, $6C, $BB, $FE, $D5, $0D, $99,
        $F0, $24, $9C, $3F, $EE, $58, $B9, $4B, $A0, $03, $8C, $7A,
        $E8, $4C, $8C, $83, $2F, $2C,
        (* x *)
        $38, $AF, $09, $D9, $87, $27, $70, $51, $20, $C9, $21, $BB,
        $5E, $9E, $26, $29, $6A, $3C, $DC, $F2, $F3, $57, $57, $A0,
        $EA, $FD, $87, $B8, $30, $E7,
        (* y *)
        $5b, $01, $25, $e4, $db, $ea, $0e, $c7, $20, $6d, $a0, $fc,
        $01, $d9, $b0, $81, $32, $9f, $b5, $55, $de, $6e, $f4, $60,
        $23, $7d, $ff, $8b, $e4, $ba,
        (* order *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $80, $00, $00, $CF, $A7, $E8, $59, $43, $77, $D4, $14, $C0,
        $38, $21, $BC, $58, $20, $63
    )
);
_EC_X9_62_PRIME_239V3: TEC_X9_62_PRIME_239V3 = (
    h:(
        field_type: NID_X9_62_prime_field;seed_len: 20;param_len: 30;cofactor: 1
    );
    data:(
        (* seed *)
        $7D, $73, $74, $16, $8F, $FE, $34, $71, $B6, $0A, $85, $76,
        $86, $A1, $94, $75, $D3, $BF, $A2, $FF,
        (* p *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $FF, $FF, $FF, $80, $00, $00, $00, $00, $00,
        $7F, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $25, $57, $05, $FA, $2A, $30, $66, $54, $B1, $F4, $CB, $03,
        $D6, $A7, $50, $A3, $0C, $25, $01, $02, $D4, $98, $87, $17,
        $D9, $BA, $15, $AB, $6D, $3E,
        (* x *)
        $67, $68, $AE, $8E, $18, $BB, $92, $CF, $CF, $00, $5C, $94,
        $9A, $A2, $C6, $D9, $48, $53, $D0, $E6, $60, $BB, $F8, $54,
        $B1, $C9, $50, $5F, $E9, $5A,
        (* y *)
        $16, $07, $e6, $89, $8f, $39, $0c, $06, $bc, $1d, $55, $2b,
        $ad, $22, $6f, $3b, $6f, $cf, $e4, $8b, $6e, $81, $84, $99,
        $af, $18, $e3, $ed, $6c, $f3,
        (* order *)
        $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $7F, $FF, $FF, $97, $5D, $EB, $41, $B3, $A6, $05, $7C, $3C,
        $43, $21, $46, $52, $65, $51
    )
);
_EC_X9_62_PRIME_256V1: TEC_X9_62_PRIME_256V1 = (
    h:(
        field_type: NID_X9_62_prime_field;seed_len: 20;param_len: 32;cofactor: 1
    );
    data:(
        (* seed *)
        $C4, $9D, $36, $08, $86, $E7, $04, $93, $6A, $66, $78, $E1,
        $13, $9D, $26, $B7, $81, $9F, $7E, $90,
        (* p *)
        $FF, $FF, $FF, $FF, $00, $00, $00, $01, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        (* a *)
        $FF, $FF, $FF, $FF, $00, $00, $00, $01, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC,
        (* b *)
        $5A, $C6, $35, $D8, $AA, $3A, $93, $E7, $B3, $EB, $BD, $55,
        $76, $98, $86, $BC, $65, $1D, $06, $B0, $CC, $53, $B0, $F6,
        $3B, $CE, $3C, $3E, $27, $D2, $60, $4B,
        (* x *)
        $6B, $17, $D1, $F2, $E1, $2C, $42, $47, $F8, $BC, $E6, $E5,
        $63, $A4, $40, $F2, $77, $03, $7D, $81, $2D, $EB, $33, $A0,
        $F4, $A1, $39, $45, $D8, $98, $C2, $96,
        (* y *)
        $4f, $e3, $42, $e2, $fe, $1a, $7f, $9b, $8e, $e7, $eb, $4a,
        $7c, $0f, $9e, $16, $2b, $ce, $33, $57, $6b, $31, $5e, $ce,
        $cb, $b6, $40, $68, $37, $bf, $51, $f5,
        (* order *)
        $FF, $FF, $FF, $FF, $00, $00, $00, $00, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $BC, $E6, $FA, $AD, $A7, $17, $9E, $84,
        $F3, $B9, $CA, $C2, $FC, $63, $25, $51
    )
);

_EC_SECG_CHAR2_113R1: TEC_SECG_CHAR2_113R1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field;seed_len: 20;param_len: 15;cofactor: 2
    );
    data:(
        (* seed *)
        $10, $E7, $23, $AB, $14, $D6, $96, $E6, $76, $87, $56, $15,
        $17, $56, $FE, $BF, $8F, $CB, $49, $A9,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $02, $01,
        (* a *)
        $00, $30, $88, $25, $0C, $A6, $E7, $C7, $FE, $64, $9C, $E8,
        $58, $20, $F7,
        (* b *)
        $00, $E8, $BE, $E4, $D3, $E2, $26, $07, $44, $18, $8B, $E0,
        $E9, $C7, $23,
        (* x *)
        $00, $9D, $73, $61, $6F, $35, $F4, $AB, $14, $07, $D7, $35,
        $62, $C1, $0F,
        (* y *)
        $00, $A5, $28, $30, $27, $79, $58, $EE, $84, $D1, $31, $5E,
        $D3, $18, $86,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $D9, $CC, $EC, $8A,
        $39, $E5, $6F
    )
);
_EC_SECG_CHAR2_113R2: TEC_SECG_CHAR2_113R2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 15; cofactor: 2
    );
    data:(
        (* seed *)
        $10, $C0, $FB, $15, $76, $08, $60, $DE, $F1, $EE, $F4, $D6,
        $96, $E6, $76, $87, $56, $15, $17, $5D,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $02, $01,
        (* a *)
        $00, $68, $99, $18, $DB, $EC, $7E, $5A, $0D, $D6, $DF, $C0,
        $AA, $55, $C7,
        (* b *)
        $00, $95, $E9, $A9, $EC, $9B, $29, $7B, $D4, $BF, $36, $E0,
        $59, $18, $4F,
        (* x *)
        $01, $A5, $7A, $6A, $7B, $26, $CA, $5E, $F5, $2F, $CD, $B8,
        $16, $47, $97,
        (* y *)
        $00, $B3, $AD, $C9, $4E, $D1, $FE, $67, $4C, $06, $E6, $95,
        $BA, $BA, $1D,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $01, $08, $78, $9B, $24,
        $96, $AF, $93
    )
);
_EC_SECG_CHAR2_131R1: TEC_SECG_CHAR2_131R1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 17; cofactor: 2
    );
    data:(
        (* seed *)
        $4D, $69, $6E, $67, $68, $75, $61, $51, $75, $98, $5B, $D3,
        $AD, $BA, $DA, $21, $B4, $3A, $97, $E2,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01, $0D,
        (* a *)
        $07, $A1, $1B, $09, $A7, $6B, $56, $21, $44, $41, $8F, $F3,
        $FF, $8C, $25, $70, $B8,
        (* b *)
        $02, $17, $C0, $56, $10, $88, $4B, $63, $B9, $C6, $C7, $29,
        $16, $78, $F9, $D3, $41,
        (* x *)
        $00, $81, $BA, $F9, $1F, $DF, $98, $33, $C4, $0F, $9C, $18,
        $13, $43, $63, $83, $99,
        (* y *)
        $07, $8C, $6E, $7E, $A3, $8C, $00, $1F, $73, $C8, $13, $4B,
        $1B, $4E, $F9, $E1, $50,
        (* order *)
        $04, $00, $00, $00, $00, $00, $00, $00, $02, $31, $23, $95,
        $3A, $94, $64, $B5, $4D
    )
);
_EC_SECG_CHAR2_131R2: TEC_SECG_CHAR2_131R2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 17; cofactor: 2
    );
    data:(
        (* seed *)
        $98, $5B, $D3, $AD, $BA, $D4, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $5A, $21, $B4, $3A, $97, $E3,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01, $0D,
        (* a *)
        $03, $E5, $A8, $89, $19, $D7, $CA, $FC, $BF, $41, $5F, $07,
        $C2, $17, $65, $73, $B2,
        (* b *)
        $04, $B8, $26, $6A, $46, $C5, $56, $57, $AC, $73, $4C, $E3,
        $8F, $01, $8F, $21, $92,
        (* x *)
        $03, $56, $DC, $D8, $F2, $F9, $50, $31, $AD, $65, $2D, $23,
        $95, $1B, $B3, $66, $A8,
        (* y *)
        $06, $48, $F0, $6D, $86, $79, $40, $A5, $36, $6D, $9E, $26,
        $5D, $E9, $EB, $24, $0F,
        (* order *)
        $04, $00, $00, $00, $00, $00, $00, $00, $01, $69, $54, $A2,
        $33, $04, $9B, $A9, $8F
    )
);
 _EC_NIST_CHAR2_163K: TEC_NIST_CHAR2_163K = (
    h:(
        field_type: NID_X9_62_characteristic_two_field;seed_len: 0; param_len: 21; cofactor: 2
    );
    data:(
        (* no seed *)
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $C9,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* x *)
        $02, $FE, $13, $C0, $53, $7B, $BC, $11, $AC, $AA, $07, $D7,
        $93, $DE, $4E, $6D, $5E, $5C, $94, $EE, $E8,
        (* y *)
        $02, $89, $07, $0F, $B0, $5D, $38, $FF, $58, $32, $1F, $2E,
        $80, $05, $36, $D5, $38, $CC, $DA, $A3, $D9,
        (* order *)
        $04, $00, $00, $00, $00, $00, $00, $00, $00, $00, $02, $01,
        $08, $A2, $E0, $CC, $0D, $99, $F8, $A5, $EF
    )
);
_EC_SECG_CHAR2_163R1: TEC_SECG_CHAR2_163R1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 21; cofactor: 2
    );
    data:(
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $C9,
        (* a *)
        $07, $B6, $88, $2C, $AA, $EF, $A8, $4F, $95, $54, $FF, $84,
        $28, $BD, $88, $E2, $46, $D2, $78, $2A, $E2,
        (* b *)
        $07, $13, $61, $2D, $CD, $DC, $B4, $0A, $AB, $94, $6B, $DA,
        $29, $CA, $91, $F7, $3A, $F9, $58, $AF, $D9,
        (* x *)
        $03, $69, $97, $96, $97, $AB, $43, $89, $77, $89, $56, $67,
        $89, $56, $7F, $78, $7A, $78, $76, $A6, $54,
        (* y *)
        $00, $43, $5E, $DB, $42, $EF, $AF, $B2, $98, $9D, $51, $FE,
        $FC, $E3, $C8, $09, $88, $F4, $1F, $F8, $83,
        (* order *)
        $03, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $48,
        $AA, $B6, $89, $C2, $9C, $A7, $10, $27, $9B
    )
);
 _EC_NIST_CHAR2_163B: TEC_NIST_CHAR2_163B = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 21; cofactor: 2
    );
    data:(
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $C9,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* b *)
        $02, $0A, $60, $19, $07, $B8, $C9, $53, $CA, $14, $81, $EB,
        $10, $51, $2F, $78, $74, $4A, $32, $05, $FD,
        (* x *)
        $03, $F0, $EB, $A1, $62, $86, $A2, $D5, $7E, $A0, $99, $11,
        $68, $D4, $99, $46, $37, $E8, $34, $3E, $36,
        (* y *)
        $00, $D5, $1F, $BC, $6C, $71, $A0, $09, $4F, $A2, $CD, $D5,
        $45, $B1, $1C, $5C, $0C, $79, $73, $24, $F1,
        (* order *)
        $04, $00, $00, $00, $00, $00, $00, $00, $00, $00, $02, $92,
        $FE, $77, $E7, $0C, $12, $A4, $23, $4C, $33
    )
);
_EC_SECG_CHAR2_193R1: TEC_SECG_CHAR2_193R1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 25; cofactor: 2
    );
    data:(
        (* seed *)
        $10, $3F, $AE, $C7, $4D, $69, $6E, $67, $68, $75, $61, $51,
        $75, $77, $7F, $C5, $B1, $91, $EF, $30,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $80,
        $01,
        (* a *)
        $00, $17, $85, $8F, $EB, $7A, $98, $97, $51, $69, $E1, $71,
        $F7, $7B, $40, $87, $DE, $09, $8A, $C8, $A9, $11, $DF, $7B,
        $01,
        (* b *)
        $00, $FD, $FB, $49, $BF, $E6, $C3, $A8, $9F, $AC, $AD, $AA,
        $7A, $1E, $5B, $BC, $7C, $C1, $C2, $E5, $D8, $31, $47, $88,
        $14,
        (* x *)
        $01, $F4, $81, $BC, $5F, $0F, $F8, $4A, $74, $AD, $6C, $DF,
        $6F, $DE, $F4, $BF, $61, $79, $62, $53, $72, $D8, $C0, $C5,
        $E1,
        (* y *)
        $00, $25, $E3, $99, $F2, $90, $37, $12, $CC, $F3, $EA, $9E,
        $3A, $1A, $D1, $7F, $B0, $B3, $20, $1B, $6A, $F7, $CE, $1B,
        $05,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $C7, $F3, $4A, $77, $8F, $44, $3A, $CC, $92, $0E, $BA,
        $49
    )
);
_EC_SECG_CHAR2_193R2: TEC_SECG_CHAR2_193R2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 25; cofactor: 2
    );
    data:(
        (* seed *)
        $10, $B7, $B4, $D6, $96, $E6, $76, $87, $56, $15, $17, $51,
        $37, $C8, $A1, $6F, $D0, $DA, $22, $11,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $80,
        $01,
        (* a *)
        $01, $63, $F3, $5A, $51, $37, $C2, $CE, $3E, $A6, $ED, $86,
        $67, $19, $0B, $0B, $C4, $3E, $CD, $69, $97, $77, $02, $70,
        $9B,
        (* b *)
        $00, $C9, $BB, $9E, $89, $27, $D4, $D6, $4C, $37, $7E, $2A,
        $B2, $85, $6A, $5B, $16, $E3, $EF, $B7, $F6, $1D, $43, $16,
        $AE,
        (* x *)
        $00, $D9, $B6, $7D, $19, $2E, $03, $67, $C8, $03, $F3, $9E,
        $1A, $7E, $82, $CA, $14, $A6, $51, $35, $0A, $AE, $61, $7E,
        $8F,
        (* y *)
        $01, $CE, $94, $33, $56, $07, $C3, $04, $AC, $29, $E7, $DE,
        $FB, $D9, $CA, $01, $F5, $96, $F9, $27, $22, $4C, $DE, $CF,
        $6C,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $01, $5A, $AB, $56, $1B, $00, $54, $13, $CC, $D4, $EE, $99,
        $D5
    )
);
_EC_NIST_CHAR2_233K: TEC_NIST_CHAR2_233K = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 30; cofactor: 4
    );
    data:(
        (* no seed *)
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $04, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* x *)
        $01, $72, $32, $BA, $85, $3A, $7E, $73, $1A, $F1, $29, $F2,
        $2F, $F4, $14, $95, $63, $A4, $19, $C2, $6B, $F5, $0A, $4C,
        $9D, $6E, $EF, $AD, $61, $26,
        (* y *)
        $01, $DB, $53, $7D, $EC, $E8, $19, $B7, $F7, $0F, $55, $5A,
        $67, $C4, $27, $A8, $CD, $9B, $F1, $8A, $EB, $9B, $56, $E0,
        $C1, $10, $56, $FA, $E6, $A3,
        (* order *)
        $00, $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $06, $9D, $5B, $B9, $15, $BC, $D4, $6E, $FB,
        $1A, $D5, $F1, $73, $AB, $DF
    )
);
 _EC_NIST_CHAR2_233B: TEC_NIST_CHAR2_233B = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 30; cofactor: 2
    );
    data:(
        (* seed *)
        $74, $D5, $9F, $F0, $7F, $6B, $41, $3D, $0E, $A1, $4B, $34,
        $4B, $20, $A2, $DB, $04, $9B, $50, $C3,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $04, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* b *)
        $00, $66, $64, $7E, $DE, $6C, $33, $2C, $7F, $8C, $09, $23,
        $BB, $58, $21, $3B, $33, $3B, $20, $E9, $CE, $42, $81, $FE,
        $11, $5F, $7D, $8F, $90, $AD,
        (* x *)
        $00, $FA, $C9, $DF, $CB, $AC, $83, $13, $BB, $21, $39, $F1,
        $BB, $75, $5F, $EF, $65, $BC, $39, $1F, $8B, $36, $F8, $F8,
        $EB, $73, $71, $FD, $55, $8B,
        (* y *)
        $01, $00, $6A, $08, $A4, $19, $03, $35, $06, $78, $E5, $85,
        $28, $BE, $BF, $8A, $0B, $EF, $F8, $67, $A7, $CA, $36, $71,
        $6F, $7E, $01, $F8, $10, $52,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $13, $E9, $74, $E7, $2F, $8A, $69, $22, $03,
        $1D, $26, $03, $CF, $E0, $D7
    )
);
_EC_SECG_CHAR2_239K1: TEC_SECG_CHAR2_239K1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 30; cofactor: 4
    );
    data:(
        (* no seed *)
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $40, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* x *)
        $29, $A0, $B6, $A8, $87, $A9, $83, $E9, $73, $09, $88, $A6,
        $87, $27, $A8, $B2, $D1, $26, $C4, $4C, $C2, $CC, $7B, $2A,
        $65, $55, $19, $30, $35, $DC,
        (* y *)
        $76, $31, $08, $04, $F1, $2E, $54, $9B, $DB, $01, $1C, $10,
        $30, $89, $E7, $35, $10, $AC, $B2, $75, $FC, $31, $2A, $5D,
        $C6, $B7, $65, $53, $F0, $CA,
        (* order *)
        $20, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $5A, $79, $FE, $C6, $7C, $B6, $E9, $1F, $1C,
        $1D, $A8, $00, $E4, $78, $A5
    )
);
_EC_NIST_CHAR2_283K: TEC_NIST_CHAR2_283K = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0;param_len: 36; cofactor: 4
    );
    data:(
        (* no seed *)
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $10, $A1,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* x *)
        $05, $03, $21, $3F, $78, $CA, $44, $88, $3F, $1A, $3B, $81,
        $62, $F1, $88, $E5, $53, $CD, $26, $5F, $23, $C1, $56, $7A,
        $16, $87, $69, $13, $B0, $C2, $AC, $24, $58, $49, $28, $36,
        (* y *)
        $01, $CC, $DA, $38, $0F, $1C, $9E, $31, $8D, $90, $F9, $5D,
        $07, $E5, $42, $6F, $E8, $7E, $45, $C0, $E8, $18, $46, $98,
        $E4, $59, $62, $36, $4E, $34, $11, $61, $77, $DD, $22, $59,
        (* order *)
        $01, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $E9, $AE, $2E, $D0, $75, $77,
        $26, $5D, $FF, $7F, $94, $45, $1E, $06, $1E, $16, $3C, $61
    )
);
_EC_NIST_CHAR2_283B: TEC_NIST_CHAR2_283B = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 36; cofactor: 2
    );
    data:(
        (* seed *)
        $77, $E2, $B0, $73, $70, $EB, $0F, $83, $2A, $6D, $D5, $B6,
        $2D, $FC, $88, $CD, $06, $BB, $84, $BE,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $10, $A1,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* b *)
        $02, $7B, $68, $0A, $C8, $B8, $59, $6D, $A5, $A4, $AF, $8A,
        $19, $A0, $30, $3F, $CA, $97, $FD, $76, $45, $30, $9F, $A2,
        $A5, $81, $48, $5A, $F6, $26, $3E, $31, $3B, $79, $A2, $F5,
        (* x *)
        $05, $F9, $39, $25, $8D, $B7, $DD, $90, $E1, $93, $4F, $8C,
        $70, $B0, $DF, $EC, $2E, $ED, $25, $B8, $55, $7E, $AC, $9C,
        $80, $E2, $E1, $98, $F8, $CD, $BE, $CD, $86, $B1, $20, $53,
        (* y *)
        $03, $67, $68, $54, $FE, $24, $14, $1C, $B9, $8F, $E6, $D4,
        $B2, $0D, $02, $B4, $51, $6F, $F7, $02, $35, $0E, $DD, $B0,
        $82, $67, $79, $C8, $13, $F0, $DF, $45, $BE, $81, $12, $F4,
        (* order *)
        $03, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $EF, $90, $39, $96, $60, $FC,
        $93, $8A, $90, $16, $5B, $04, $2A, $7C, $EF, $AD, $B3, $07
    )
);
_EC_NIST_CHAR2_409K: TEC_NIST_CHAR2_409K = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 52; cofactor: 4
    );
    data:(
        (* no seed *)
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $80, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* x *)
        $00, $60, $F0, $5F, $65, $8F, $49, $C1, $AD, $3A, $B1, $89,
        $0F, $71, $84, $21, $0E, $FD, $09, $87, $E3, $07, $C8, $4C,
        $27, $AC, $CF, $B8, $F9, $F6, $7C, $C2, $C4, $60, $18, $9E,
        $B5, $AA, $AA, $62, $EE, $22, $2E, $B1, $B3, $55, $40, $CF,
        $E9, $02, $37, $46,
        (* y *)
        $01, $E3, $69, $05, $0B, $7C, $4E, $42, $AC, $BA, $1D, $AC,
        $BF, $04, $29, $9C, $34, $60, $78, $2F, $91, $8E, $A4, $27,
        $E6, $32, $51, $65, $E9, $EA, $10, $E3, $DA, $5F, $6C, $42,
        $E9, $C5, $52, $15, $AA, $9C, $A2, $7A, $58, $63, $EC, $48,
        $D8, $E0, $28, $6B,
        (* order *)
        $00, $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FE, $5F, $83, $B2, $D4, $EA, $20, $40, $0E, $C4,
        $55, $7D, $5E, $D3, $E3, $E7, $CA, $5B, $4B, $5C, $83, $B8,
        $E0, $1E, $5F, $CF
    )
);
_EC_NIST_CHAR2_409B: TEC_NIST_CHAR2_409B = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 52; cofactor: 2
    );
    data:(
        (* seed *)
        $40, $99, $B5, $A4, $57, $F9, $D6, $9F, $79, $21, $3D, $09,
        $4C, $4B, $CD, $4D, $42, $62, $21, $0B,
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $80, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* b *)
        $00, $21, $A5, $C2, $C8, $EE, $9F, $EB, $5C, $4B, $9A, $75,
        $3B, $7B, $47, $6B, $7F, $D6, $42, $2E, $F1, $F3, $DD, $67,
        $47, $61, $FA, $99, $D6, $AC, $27, $C8, $A9, $A1, $97, $B2,
        $72, $82, $2F, $6C, $D5, $7A, $55, $AA, $4F, $50, $AE, $31,
        $7B, $13, $54, $5F,
        (* x *)
        $01, $5D, $48, $60, $D0, $88, $DD, $B3, $49, $6B, $0C, $60,
        $64, $75, $62, $60, $44, $1C, $DE, $4A, $F1, $77, $1D, $4D,
        $B0, $1F, $FE, $5B, $34, $E5, $97, $03, $DC, $25, $5A, $86,
        $8A, $11, $80, $51, $56, $03, $AE, $AB, $60, $79, $4E, $54,
        $BB, $79, $96, $A7,
        (* y *)
        $00, $61, $B1, $CF, $AB, $6B, $E5, $F3, $2B, $BF, $A7, $83,
        $24, $ED, $10, $6A, $76, $36, $B9, $C5, $A7, $BD, $19, $8D,
        $01, $58, $AA, $4F, $54, $88, $D0, $8F, $38, $51, $4F, $1F,
        $DF, $4B, $4F, $40, $D2, $18, $1B, $36, $81, $C3, $64, $BA,
        $02, $73, $C7, $06,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01, $E2, $AA, $D6, $A6, $12, $F3, $33, $07, $BE,
        $5F, $A4, $7C, $3C, $9E, $05, $2F, $83, $81, $64, $CD, $37,
        $D9, $A2, $11, $73
    )
);
_EC_NIST_CHAR2_571K: TEC_NIST_CHAR2_571K = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 72; cofactor: 4
    );
    data:(
        (* no seed *)
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $04, $25,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* x *)
        $02, $6E, $B7, $A8, $59, $92, $3F, $BC, $82, $18, $96, $31,
        $F8, $10, $3F, $E4, $AC, $9C, $A2, $97, $00, $12, $D5, $D4,
        $60, $24, $80, $48, $01, $84, $1C, $A4, $43, $70, $95, $84,
        $93, $B2, $05, $E6, $47, $DA, $30, $4D, $B4, $CE, $B0, $8C,
        $BB, $D1, $BA, $39, $49, $47, $76, $FB, $98, $8B, $47, $17,
        $4D, $CA, $88, $C7, $E2, $94, $52, $83, $A0, $1C, $89, $72,
        (* y *)
        $03, $49, $DC, $80, $7F, $4F, $BF, $37, $4F, $4A, $EA, $DE,
        $3B, $CA, $95, $31, $4D, $D5, $8C, $EC, $9F, $30, $7A, $54,
        $FF, $C6, $1E, $FC, $00, $6D, $8A, $2C, $9D, $49, $79, $C0,
        $AC, $44, $AE, $A7, $4F, $BE, $BB, $B9, $F7, $72, $AE, $DC,
        $B6, $20, $B0, $1A, $7B, $A7, $AF, $1B, $32, $04, $30, $C8,
        $59, $19, $84, $F6, $01, $CD, $4C, $14, $3E, $F1, $C7, $A3,
        (* order *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $13, $18, $50, $E1, $F1, $9A, $63, $E4, $B3, $91, $A8, $DB,
        $91, $7F, $41, $38, $B6, $30, $D8, $4B, $E5, $D6, $39, $38,
        $1E, $91, $DE, $B4, $5C, $FE, $77, $8F, $63, $7C, $10, $01
    )
);
_EC_NIST_CHAR2_571B: TEC_NIST_CHAR2_571B = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 72; cofactor: 2
    );
    data:(
        (* seed *)
        $2A, $A0, $58, $F7, $3A, $0E, $33, $AB, $48, $6B, $0F, $61,
        $04, $10, $C5, $3A, $7F, $13, $23, $10,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $04, $25,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* b *)
        $02, $F4, $0E, $7E, $22, $21, $F2, $95, $DE, $29, $71, $17,
        $B7, $F3, $D6, $2F, $5C, $6A, $97, $FF, $CB, $8C, $EF, $F1,
        $CD, $6B, $A8, $CE, $4A, $9A, $18, $AD, $84, $FF, $AB, $BD,
        $8E, $FA, $59, $33, $2B, $E7, $AD, $67, $56, $A6, $6E, $29,
        $4A, $FD, $18, $5A, $78, $FF, $12, $AA, $52, $0E, $4D, $E7,
        $39, $BA, $CA, $0C, $7F, $FE, $FF, $7F, $29, $55, $72, $7A,
        (* x *)
        $03, $03, $00, $1D, $34, $B8, $56, $29, $6C, $16, $C0, $D4,
        $0D, $3C, $D7, $75, $0A, $93, $D1, $D2, $95, $5F, $A8, $0A,
        $A5, $F4, $0F, $C8, $DB, $7B, $2A, $BD, $BD, $E5, $39, $50,
        $F4, $C0, $D2, $93, $CD, $D7, $11, $A3, $5B, $67, $FB, $14,
        $99, $AE, $60, $03, $86, $14, $F1, $39, $4A, $BF, $A3, $B4,
        $C8, $50, $D9, $27, $E1, $E7, $76, $9C, $8E, $EC, $2D, $19,
        (* y *)
        $03, $7B, $F2, $73, $42, $DA, $63, $9B, $6D, $CC, $FF, $FE,
        $B7, $3D, $69, $D7, $8C, $6C, $27, $A6, $00, $9C, $BB, $CA,
        $19, $80, $F8, $53, $39, $21, $E8, $A6, $84, $42, $3E, $43,
        $BA, $B0, $8A, $57, $62, $91, $AF, $8F, $46, $1B, $B2, $A8,
        $B3, $53, $1D, $2F, $04, $85, $C1, $9B, $16, $E2, $F1, $51,
        $6E, $23, $DD, $3C, $1A, $48, $27, $AF, $1B, $8A, $C1, $5B,
        (* order *)
        $03, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $E6, $61, $CE, $18, $FF, $55, $98, $73, $08, $05, $9B, $18,
        $68, $23, $85, $1E, $C7, $DD, $9C, $A1, $16, $1D, $E9, $3D,
        $51, $74, $D6, $6E, $83, $82, $E9, $BB, $2F, $E8, $4E, $47
    )
);
_EC_X9_62_CHAR2_163V1: TEC_X9_62_CHAR2_163V1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 21; cofactor: 2
    );
    data:(
        (* seed *)
        $D2, $C0, $FB, $15, $76, $08, $60, $DE, $F1, $EE, $F4, $D6,
        $96, $E6, $76, $87, $56, $15, $17, $54,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $01, $07,
        (* a *)
        $07, $25, $46, $B5, $43, $52, $34, $A4, $22, $E0, $78, $96,
        $75, $F4, $32, $C8, $94, $35, $DE, $52, $42,
        (* b *)
        $00, $C9, $51, $7D, $06, $D5, $24, $0D, $3C, $FF, $38, $C7,
        $4B, $20, $B6, $CD, $4D, $6F, $9D, $D4, $D9,
        (* x *)
        $07, $AF, $69, $98, $95, $46, $10, $3D, $79, $32, $9F, $CC,
        $3D, $74, $88, $0F, $33, $BB, $E8, $03, $CB,
        (* y *)
        $01, $EC, $23, $21, $1B, $59, $66, $AD, $EA, $1D, $3F, $87,
        $F7, $EA, $58, $48, $AE, $F0, $B7, $CA, $9F,
        (* order *)
        $04, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $E6,
        $0F, $C8, $82, $1C, $C7, $4D, $AE, $AF, $C1
    )
);

_EC_X9_62_CHAR2_163V2: TEC_X9_62_CHAR2_163V2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 21; cofactor: 2
    );
    data:(
        (* seed *)
        $53, $81, $4C, $05, $0D, $44, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $58, $0C, $A4, $E2, $9F, $FD,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $01, $07,
        (* a *)
        $01, $08, $B3, $9E, $77, $C4, $B1, $08, $BE, $D9, $81, $ED,
        $0E, $89, $0E, $11, $7C, $51, $1C, $F0, $72,
        (* b *)
        $06, $67, $AC, $EB, $38, $AF, $4E, $48, $8C, $40, $74, $33,
        $FF, $AE, $4F, $1C, $81, $16, $38, $DF, $20,
        (* x *)
        $00, $24, $26, $6E, $4E, $B5, $10, $6D, $0A, $96, $4D, $92,
        $C4, $86, $0E, $26, $71, $DB, $9B, $6C, $C5,
        (* y *)
        $07, $9F, $68, $4D, $DF, $66, $84, $C5, $CD, $25, $8B, $38,
        $90, $02, $1B, $23, $86, $DF, $D1, $9F, $C5,
        (* order *)
        $03, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FD, $F6,
        $4D, $E1, $15, $1A, $DB, $B7, $8F, $10, $A7
    )
);
_EC_X9_62_CHAR2_163V3: TEC_X9_62_CHAR2_163V3 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 21; cofactor: 2
    );
    data:(
        (* seed *)
        $50, $CB, $F1, $D9, $5C, $A9, $4D, $69, $6E, $67, $68, $75,
        $61, $51, $75, $F1, $6A, $36, $A3, $B8,
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $01, $07,
        (* a *)
        $07, $A5, $26, $C6, $3D, $3E, $25, $A2, $56, $A0, $07, $69,
        $9F, $54, $47, $E3, $2A, $E4, $56, $B5, $0E,
        (* b *)
        $03, $F7, $06, $17, $98, $EB, $99, $E2, $38, $FD, $6F, $1B,
        $F9, $5B, $48, $FE, $EB, $48, $54, $25, $2B,
        (* x *)
        $02, $F9, $F8, $7B, $7C, $57, $4D, $0B, $DE, $CF, $8A, $22,
        $E6, $52, $47, $75, $F9, $8C, $DE, $BD, $CB,
        (* y *)
        $05, $B9, $35, $59, $0C, $15, $5E, $17, $EA, $48, $EB, $3F,
        $F3, $71, $8B, $89, $3D, $F5, $9A, $05, $D0,
        (* order *)
        $03, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $1A,
        $EE, $14, $0F, $11, $0A, $FF, $96, $13, $09
    )
);
 _EC_X9_62_CHAR2_176V1: TEC_X9_62_CHAR2_176V1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len:23; cofactor:  $FF6E
    );
    data:(
        (* no seed *)
        (* p *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $08, $00, $00, $00, $00, $07,
        (* a *)
        $00, $E4, $E6, $DB, $29, $95, $06, $5C, $40, $7D, $9D, $39,
        $B8, $D0, $96, $7B, $96, $70, $4B, $A8, $E9, $C9, $0B,
        (* b *)
        $00, $5D, $DA, $47, $0A, $BE, $64, $14, $DE, $8E, $C1, $33,
        $AE, $28, $E9, $BB, $D7, $FC, $EC, $0A, $E0, $FF, $F2,
        (* x *)
        $00, $8D, $16, $C2, $86, $67, $98, $B6, $00, $F9, $F0, $8B,
        $B4, $A8, $E8, $60, $F3, $29, $8C, $E0, $4A, $57, $98,
        (* y *)
        $00, $6F, $A4, $53, $9C, $2D, $AD, $DD, $D6, $BA, $B5, $16,
        $7D, $61, $B4, $36, $E1, $D9, $2B, $B1, $6A, $56, $2C,
        (* order *)
        $00, $00, $01, $00, $92, $53, $73, $97, $EC, $A4, $F6, $14,
        $57, $99, $D6, $2B, $0A, $19, $CE, $06, $FE, $26, $AD
    )
);
_EC_X9_62_CHAR2_191V1: TEC_X9_62_CHAR2_191V1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len:24; cofactor: 2
    );
    data:(
        (* seed *)
        $4E, $13, $CA, $54, $27, $44, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $55, $2F, $27, $9A, $8C, $84,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $02, $01,
        (* a *)
        $28, $66, $53, $7B, $67, $67, $52, $63, $6A, $68, $F5, $65,
        $54, $E1, $26, $40, $27, $6B, $64, $9E, $F7, $52, $62, $67,
        (* b *)
        $2E, $45, $EF, $57, $1F, $00, $78, $6F, $67, $B0, $08, $1B,
        $94, $95, $A3, $D9, $54, $62, $F5, $DE, $0A, $A1, $85, $EC,
        (* x *)
        $36, $B3, $DA, $F8, $A2, $32, $06, $F9, $C4, $F2, $99, $D7,
        $B2, $1A, $9C, $36, $91, $37, $F2, $C8, $4A, $E1, $AA, $0D,
        (* y *)
        $76, $5B, $E7, $34, $33, $B3, $F9, $5E, $33, $29, $32, $E7,
        $0E, $A2, $45, $CA, $24, $18, $EA, $0E, $F9, $80, $18, $FB,
        (* order *)
        $40, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $04, $A2, $0E, $90, $C3, $90, $67, $C8, $93, $BB, $B9, $A5
    )
);
_EC_X9_62_CHAR2_191V2: TEC_X9_62_CHAR2_191V2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 24; cofactor: 4
    );
    data:(
        (* seed *)
        $08, $71, $EF, $2F, $EF, $24, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $58, $BE, $E0, $D9, $5C, $15,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $02, $01,
        (* a *)
        $40, $10, $28, $77, $4D, $77, $77, $C7, $B7, $66, $6D, $13,
        $66, $EA, $43, $20, $71, $27, $4F, $89, $FF, $01, $E7, $18,
        (* b *)
        $06, $20, $04, $8D, $28, $BC, $BD, $03, $B6, $24, $9C, $99,
        $18, $2B, $7C, $8C, $D1, $97, $00, $C3, $62, $C4, $6A, $01,
        (* x *)
        $38, $09, $B2, $B7, $CC, $1B, $28, $CC, $5A, $87, $92, $6A,
        $AD, $83, $FD, $28, $78, $9E, $81, $E2, $C9, $E3, $BF, $10,
        (* y *)
        $17, $43, $43, $86, $62, $6D, $14, $F3, $DB, $F0, $17, $60,
        $D9, $21, $3A, $3E, $1C, $F3, $7A, $EC, $43, $7D, $66, $8A,
        (* order *)
        $20, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $50, $50, $8C, $B8, $9F, $65, $28, $24, $E0, $6B, $81, $73
    )
);
 _EC_X9_62_CHAR2_191V3: TEC_X9_62_CHAR2_191V3 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 24; cofactor: 6
    );
    data:(
        (* seed *)
        $E0, $53, $51, $2D, $C6, $84, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $50, $67, $AE, $78, $6D, $1F,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $02, $01,
        (* a *)
        $6C, $01, $07, $47, $56, $09, $91, $22, $22, $10, $56, $91,
        $1C, $77, $D7, $7E, $77, $A7, $77, $E7, $E7, $E7, $7F, $CB,
        (* b *)
        $71, $FE, $1A, $F9, $26, $CF, $84, $79, $89, $EF, $EF, $8D,
        $B4, $59, $F6, $63, $94, $D9, $0F, $32, $AD, $3F, $15, $E8,
        (* x *)
        $37, $5D, $4C, $E2, $4F, $DE, $43, $44, $89, $DE, $87, $46,
        $E7, $17, $86, $01, $50, $09, $E6, $6E, $38, $A9, $26, $DD,
        (* y *)
        $54, $5A, $39, $17, $61, $96, $57, $5D, $98, $59, $99, $36,
        $6E, $6A, $D3, $4C, $E0, $A7, $7C, $D7, $12, $7B, $06, $BE,
        (* order *)
        $15, $55, $55, $55, $55, $55, $55, $55, $55, $55, $55, $55,
        $61, $0C, $0B, $19, $68, $12, $BF, $B6, $28, $8A, $3E, $A3
    )
);
_EC_X9_62_CHAR2_208W1: TEC_X9_62_CHAR2_208W1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 27; cofactor: $FE48
    );
    data:(
        (* no seed *)
        (* p *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $08, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $07,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00,
        (* b *)
        $00, $C8, $61, $9E, $D4, $5A, $62, $E6, $21, $2E, $11, $60,
        $34, $9E, $2B, $FA, $84, $44, $39, $FA, $FC, $2A, $3F, $D1,
        $63, $8F, $9E,
        (* x *)
        $00, $89, $FD, $FB, $E4, $AB, $E1, $93, $DF, $95, $59, $EC,
        $F0, $7A, $C0, $CE, $78, $55, $4E, $27, $84, $EB, $8C, $1E,
        $D1, $A5, $7A,
        (* y *)
        $00, $0F, $55, $B5, $1A, $06, $E7, $8E, $9A, $C3, $8A, $03,
        $5F, $F5, $20, $D8, $B0, $17, $81, $BE, $B1, $A6, $BB, $08,
        $61, $7D, $E3,
        (* order *)
        $00, $00, $01, $01, $BA, $F9, $5C, $97, $23, $C5, $7B, $6C,
        $21, $DA, $2E, $FF, $2D, $5E, $D5, $88, $BD, $D5, $71, $7E,
        $21, $2F, $9D
    )
);
_EC_X9_62_CHAR2_239V1: TEC_X9_62_CHAR2_239V1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 30; cofactor: 4
    );
    data:(
        (* seed *)
        $D3, $4B, $9A, $4D, $69, $6E, $67, $68, $75, $61, $51, $75,
        $CA, $71, $B9, $20, $BF, $EF, $B0, $5D,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $10, $00, $00, $00, $01,
        (* a *)
        $32, $01, $08, $57, $07, $7C, $54, $31, $12, $3A, $46, $B8,
        $08, $90, $67, $56, $F5, $43, $42, $3E, $8D, $27, $87, $75,
        $78, $12, $57, $78, $AC, $76,
        (* b *)
        $79, $04, $08, $F2, $EE, $DA, $F3, $92, $B0, $12, $ED, $EF,
        $B3, $39, $2F, $30, $F4, $32, $7C, $0C, $A3, $F3, $1F, $C3,
        $83, $C4, $22, $AA, $8C, $16,
        (* x *)
        $57, $92, $70, $98, $FA, $93, $2E, $7C, $0A, $96, $D3, $FD,
        $5B, $70, $6E, $F7, $E5, $F5, $C1, $56, $E1, $6B, $7E, $7C,
        $86, $03, $85, $52, $E9, $1D,
        (* y *)
        $61, $D8, $EE, $50, $77, $C3, $3F, $EC, $F6, $F1, $A1, $6B,
        $26, $8D, $E4, $69, $C3, $C7, $74, $4E, $A9, $A9, $71, $64,
        $9F, $C7, $A9, $61, $63, $05,
        (* order *)
        $20, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $0F, $4D, $42, $FF, $E1, $49, $2A, $49, $93,
        $F1, $CA, $D6, $66, $E4, $47
    )
);
_EC_X9_62_CHAR2_239V2: TEC_X9_62_CHAR2_239V2 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 30; cofactor: 6
    );
    data:(
        (* seed *)
        $2A, $A6, $98, $2F, $DF, $A4, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $5D, $26, $67, $27, $27, $7D,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $10, $00, $00, $00, $01,
        (* a *)
        $42, $30, $01, $77, $57, $A7, $67, $FA, $E4, $23, $98, $56,
        $9B, $74, $63, $25, $D4, $53, $13, $AF, $07, $66, $26, $64,
        $79, $B7, $56, $54, $E6, $5F,
        (* b *)
        $50, $37, $EA, $65, $41, $96, $CF, $F0, $CD, $82, $B2, $C1,
        $4A, $2F, $CF, $2E, $3F, $F8, $77, $52, $85, $B5, $45, $72,
        $2F, $03, $EA, $CD, $B7, $4B,
        (* x *)
        $28, $F9, $D0, $4E, $90, $00, $69, $C8, $DC, $47, $A0, $85,
        $34, $FE, $76, $D2, $B9, $00, $B7, $D7, $EF, $31, $F5, $70,
        $9F, $20, $0C, $4C, $A2, $05,
        (* y *)
        $56, $67, $33, $4C, $45, $AF, $F3, $B5, $A0, $3B, $AD, $9D,
        $D7, $5E, $2C, $71, $A9, $93, $62, $56, $7D, $54, $53, $F7,
        $FA, $6E, $22, $7E, $C8, $33,
        (* order *)
        $15, $55, $55, $55, $55, $55, $55, $55, $55, $55, $55, $55,
        $55, $55, $55, $3C, $6F, $28, $85, $25, $9C, $31, $E3, $FC,
        $DF, $15, $46, $24, $52, $2D
    )
);
_EC_X9_62_CHAR2_239V3: TEC_X9_62_CHAR2_239V3 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 30;cofactor: $A
    );
    data:(
        (* seed *)
        $9E, $07, $6F, $4D, $69, $6E, $67, $68, $75, $61, $51, $75,
        $E1, $1E, $9F, $DD, $77, $F9, $20, $41,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $10, $00, $00, $00, $01,
        (* a *)
        $01, $23, $87, $74, $66, $6A, $67, $76, $6D, $66, $76, $F7,
        $78, $E6, $76, $B6, $69, $99, $17, $66, $66, $E6, $87, $66,
        $6D, $87, $66, $C6, $6A, $9F,
        (* b *)
        $6A, $94, $19, $77, $BA, $9F, $6A, $43, $51, $99, $AC, $FC,
        $51, $06, $7E, $D5, $87, $F5, $19, $C5, $EC, $B5, $41, $B8,
        $E4, $41, $11, $DE, $1D, $40,
        (* x *)
        $70, $F6, $E9, $D0, $4D, $28, $9C, $4E, $89, $91, $3C, $E3,
        $53, $0B, $FD, $E9, $03, $97, $7D, $42, $B1, $46, $D5, $39,
        $BF, $1B, $DE, $4E, $9C, $92,
        (* y *)
        $2E, $5A, $0E, $AF, $6E, $5E, $13, $05, $B9, $00, $4D, $CE,
        $5C, $0E, $D7, $FE, $59, $A3, $56, $08, $F3, $38, $37, $C8,
        $16, $D8, $0B, $79, $F4, $61,
        (* order *)
        $0C, $CC, $CC, $CC, $CC, $CC, $CC, $CC, $CC, $CC, $CC, $CC,
        $CC, $CC, $CC, $AC, $49, $12, $D2, $D9, $DF, $90, $3E, $F9,
        $88, $8B, $8A, $0E, $4C, $FF
    )
);
_EC_X9_62_CHAR2_272W1: TEC_X9_62_CHAR2_272W1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 35;cofactor: $FF06
    );
    data:(
        (* no seed *)
        (* p *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01, $00, $00, $00, $00, $00, $00, $0B,
        (* a *)
        $00, $91, $A0, $91, $F0, $3B, $5F, $BA, $4A, $B2, $CC, $F4,
        $9C, $4E, $DD, $22, $0F, $B0, $28, $71, $2D, $42, $BE, $75,
        $2B, $2C, $40, $09, $4D, $BA, $CD, $B5, $86, $FB, $20,
        (* b *)
        $00, $71, $67, $EF, $C9, $2B, $B2, $E3, $CE, $7C, $8A, $AA,
        $FF, $34, $E1, $2A, $9C, $55, $70, $03, $D7, $C7, $3A, $6F,
        $AF, $00, $3F, $99, $F6, $CC, $84, $82, $E5, $40, $F7,
        (* x *)
        $00, $61, $08, $BA, $BB, $2C, $EE, $BC, $F7, $87, $05, $8A,
        $05, $6C, $BE, $0C, $FE, $62, $2D, $77, $23, $A2, $89, $E0,
        $8A, $07, $AE, $13, $EF, $0D, $10, $D1, $71, $DD, $8D,
        (* y *)
        $00, $10, $C7, $69, $57, $16, $85, $1E, $EF, $6B, $A7, $F6,
        $87, $2E, $61, $42, $FB, $D2, $41, $B8, $30, $FF, $5E, $FC,
        $AC, $EC, $CA, $B0, $5E, $02, $00, $5D, $DE, $9D, $23,
        (* order *)
        $00, $00, $01, $00, $FA, $F5, $13, $54, $E0, $E3, $9E, $48,
        $92, $DF, $6E, $31, $9C, $72, $C8, $16, $16, $03, $FA, $45,
        $AA, $7B, $99, $8A, $16, $7B, $8F, $1E, $62, $95, $21
    )
);
_EC_X9_62_CHAR2_304W1: TEC_X9_62_CHAR2_304W1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 39;cofactor: $FE2E
    );
    data:(
        (* no seed *)
        (* p *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $08, $07,
        (* a *)
        $00, $FD, $0D, $69, $31, $49, $A1, $18, $F6, $51, $E6, $DC,
        $E6, $80, $20, $85, $37, $7E, $5F, $88, $2D, $1B, $51, $0B,
        $44, $16, $00, $74, $C1, $28, $80, $78, $36, $5A, $03, $96,
        $C8, $E6, $81,
        (* b *)
        $00, $BD, $DB, $97, $E5, $55, $A5, $0A, $90, $8E, $43, $B0,
        $1C, $79, $8E, $A5, $DA, $A6, $78, $8F, $1E, $A2, $79, $4E,
        $FC, $F5, $71, $66, $B8, $C1, $40, $39, $60, $1E, $55, $82,
        $73, $40, $BE,
        (* x *)
        $00, $19, $7B, $07, $84, $5E, $9B, $E2, $D9, $6A, $DB, $0F,
        $5F, $3C, $7F, $2C, $FF, $BD, $7A, $3E, $B8, $B6, $FE, $C3,
        $5C, $7F, $D6, $7F, $26, $DD, $F6, $28, $5A, $64, $4F, $74,
        $0A, $26, $14,
        (* y *)
        $00, $E1, $9F, $BE, $B7, $6E, $0D, $A1, $71, $51, $7E, $CF,
        $40, $1B, $50, $28, $9B, $F0, $14, $10, $32, $88, $52, $7A,
        $9B, $41, $6A, $10, $5E, $80, $26, $0B, $54, $9F, $DC, $1B,
        $92, $C0, $3B,
        (* order *)
        $00, $00, $01, $01, $D5, $56, $57, $2A, $AB, $AC, $80, $01,
        $01, $D5, $56, $57, $2A, $AB, $AC, $80, $01, $02, $2D, $5C,
        $91, $DD, $17, $3F, $8F, $B5, $61, $DA, $68, $99, $16, $44,
        $43, $05, $1D
    )
);
_EC_X9_62_CHAR2_359V1: TEC_X9_62_CHAR2_359V1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 20; param_len: 45;cofactor: $4C
    );
    data:(
        (* seed *)
        $2B, $35, $49, $20, $B7, $24, $D6, $96, $E6, $76, $87, $56,
        $15, $17, $58, $5B, $A1, $33, $2D, $C6,
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $10, $00, $00, $00, $00, $00, $00, $00, $01,
        (* a *)
        $56, $67, $67, $6A, $65, $4B, $20, $75, $4F, $35, $6E, $A9,
        $20, $17, $D9, $46, $56, $7C, $46, $67, $55, $56, $F1, $95,
        $56, $A0, $46, $16, $B5, $67, $D2, $23, $A5, $E0, $56, $56,
        $FB, $54, $90, $16, $A9, $66, $56, $A5, $57,
        (* b *)
        $24, $72, $E2, $D0, $19, $7C, $49, $36, $3F, $1F, $E7, $F5,
        $B6, $DB, $07, $5D, $52, $B6, $94, $7D, $13, $5D, $8C, $A4,
        $45, $80, $5D, $39, $BC, $34, $56, $26, $08, $96, $87, $74,
        $2B, $63, $29, $E7, $06, $80, $23, $19, $88,
        (* x *)
        $3C, $25, $8E, $F3, $04, $77, $67, $E7, $ED, $E0, $F1, $FD,
        $AA, $79, $DA, $EE, $38, $41, $36, $6A, $13, $2E, $16, $3A,
        $CE, $D4, $ED, $24, $01, $DF, $9C, $6B, $DC, $DE, $98, $E8,
        $E7, $07, $C0, $7A, $22, $39, $B1, $B0, $97,
        (* y *)
        $53, $D7, $E0, $85, $29, $54, $70, $48, $12, $1E, $9C, $95,
        $F3, $79, $1D, $D8, $04, $96, $39, $48, $F3, $4F, $AE, $7B,
        $F4, $4E, $A8, $23, $65, $DC, $78, $68, $FE, $57, $E4, $AE,
        $2D, $E2, $11, $30, $5A, $40, $71, $04, $BD,
        (* order *)
        $01, $AF, $28, $6B, $CA, $1A, $F2, $86, $BC, $A1, $AF, $28,
        $6B, $CA, $1A, $F2, $86, $BC, $A1, $AF, $28, $6B, $C9, $FB,
        $8F, $6B, $85, $C5, $56, $89, $2C, $20, $A7, $EB, $96, $4F,
        $E7, $71, $9E, $74, $F4, $90, $75, $8D, $3B
    )
);
_EC_X9_62_CHAR2_368W1: TEC_X9_62_CHAR2_368W1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 47;cofactor: $FF70
    );
    data:(
        (* no seed *)
        (* p *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $20, $00, $00, $00, $00, $00, $00, $00, $00, $00, $07,
        (* a *)
        $00, $E0, $D2, $EE, $25, $09, $52, $06, $F5, $E2, $A4, $F9,
        $ED, $22, $9F, $1F, $25, $6E, $79, $A0, $E2, $B4, $55, $97,
        $0D, $8D, $0D, $86, $5B, $D9, $47, $78, $C5, $76, $D6, $2F,
        $0A, $B7, $51, $9C, $CD, $2A, $1A, $90, $6A, $E3, $0D,
        (* b *)
        $00, $FC, $12, $17, $D4, $32, $0A, $90, $45, $2C, $76, $0A,
        $58, $ED, $CD, $30, $C8, $DD, $06, $9B, $3C, $34, $45, $38,
        $37, $A3, $4E, $D5, $0C, $B5, $49, $17, $E1, $C2, $11, $2D,
        $84, $D1, $64, $F4, $44, $F8, $F7, $47, $86, $04, $6A,
        (* x *)
        $00, $10, $85, $E2, $75, $53, $81, $DC, $CC, $E3, $C1, $55,
        $7A, $FA, $10, $C2, $F0, $C0, $C2, $82, $56, $46, $C5, $B3,
        $4A, $39, $4C, $BC, $FA, $8B, $C1, $6B, $22, $E7, $E7, $89,
        $E9, $27, $BE, $21, $6F, $02, $E1, $FB, $13, $6A, $5F,
        (* y *)
        $00, $7B, $3E, $B1, $BD, $DC, $BA, $62, $D5, $D8, $B2, $05,
        $9B, $52, $57, $97, $FC, $73, $82, $2C, $59, $05, $9C, $62,
        $3A, $45, $FF, $38, $43, $CE, $E8, $F8, $7C, $D1, $85, $5A,
        $DA, $A8, $1E, $2A, $07, $50, $B8, $0F, $DA, $23, $10,
        (* order *)
        $00, $00, $01, $00, $90, $51, $2D, $A9, $AF, $72, $B0, $83,
        $49, $D9, $8A, $5D, $D4, $C7, $B0, $53, $2E, $CA, $51, $CE,
        $03, $E2, $D1, $0F, $3B, $7A, $C5, $79, $BD, $87, $E9, $09,
        $AE, $40, $A6, $F1, $31, $E9, $CF, $CE, $5B, $D9, $67
    )
);
_EC_X9_62_CHAR2_431R1: TEC_X9_62_CHAR2_431R1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 54;cofactor: $2760
    );
    data:(
        (* no seed *)
        (* p *)
        $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $01,
        (* a *)
        $1A, $82, $7E, $F0, $0D, $D6, $FC, $0E, $23, $4C, $AF, $04,
        $6C, $6A, $5D, $8A, $85, $39, $5B, $23, $6C, $C4, $AD, $2C,
        $F3, $2A, $0C, $AD, $BD, $C9, $DD, $F6, $20, $B0, $EB, $99,
        $06, $D0, $95, $7F, $6C, $6F, $EA, $CD, $61, $54, $68, $DF,
        $10, $4D, $E2, $96, $CD, $8F,
        (* b *)
        $10, $D9, $B4, $A3, $D9, $04, $7D, $8B, $15, $43, $59, $AB,
        $FB, $1B, $7F, $54, $85, $B0, $4C, $EB, $86, $82, $37, $DD,
        $C9, $DE, $DA, $98, $2A, $67, $9A, $5A, $91, $9B, $62, $6D,
        $4E, $50, $A8, $DD, $73, $1B, $10, $7A, $99, $62, $38, $1F,
        $B5, $D8, $07, $BF, $26, $18,
        (* x *)
        $12, $0F, $C0, $5D, $3C, $67, $A9, $9D, $E1, $61, $D2, $F4,
        $09, $26, $22, $FE, $CA, $70, $1B, $E4, $F5, $0F, $47, $58,
        $71, $4E, $8A, $87, $BB, $F2, $A6, $58, $EF, $8C, $21, $E7,
        $C5, $EF, $E9, $65, $36, $1F, $6C, $29, $99, $C0, $C2, $47,
        $B0, $DB, $D7, $0C, $E6, $B7,
        (* y *)
        $20, $D0, $AF, $89, $03, $A9, $6F, $8D, $5F, $A2, $C2, $55,
        $74, $5D, $3C, $45, $1B, $30, $2C, $93, $46, $D9, $B7, $E4,
        $85, $E7, $BC, $E4, $1F, $6B, $59, $1F, $3E, $8F, $6A, $DD,
        $CB, $B0, $BC, $4C, $2F, $94, $7A, $7D, $E1, $A8, $9B, $62,
        $5D, $6A, $59, $8B, $37, $60,
        (* order *)
        $00, $03, $40, $34, $03, $40, $34, $03, $40, $34, $03, $40,
        $34, $03, $40, $34, $03, $40, $34, $03, $40, $34, $03, $40,
        $34, $03, $40, $34, $03, $23, $C3, $13, $FA, $B5, $05, $89,
        $70, $3B, $5E, $C6, $8D, $35, $87, $FE, $C6, $0D, $16, $1C,
        $C1, $49, $C1, $AD, $4A, $91
    )
);
_EC_WTLS_1: TEC_WTLS_1 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 15; cofactor: 2
    );
    data:(
        (* no seed *)
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $02, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01,
        (* x *)
        $01, $66, $79, $79, $A4, $0B, $A4, $97, $E5, $D5, $C2, $70,
        $78, $06, $17,
        (* y *)
        $00, $F4, $4B, $4A, $F1, $EC, $C2, $63, $0E, $08, $78, $5C,
        $EB, $CC, $15,
        (* order *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FD, $BF, $91, $AF,
        $6D, $EA, $73
    )
);
_EC_IPSEC_155_ID3: TEC_IPSEC_155_ID3 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 20; cofactor: 3
    );
    data:(
        (* no seed *)
        (* p *)
        $08, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $40, $00, $00, $00, $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $07, $33, $8f,
        (* x *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $7b,
        (* y *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $01, $c8,
        (* order *)
        $02, $AA, $AA, $AA, $AA, $AA, $AA, $AA, $AA, $AA, $C7, $F3,
        $C7, $88, $1B, $D0, $86, $8F, $A8, $6C
    )
);
_EC_IPSEC_185_ID4: TEC_IPSEC_185_ID4 = (
    h:(
        field_type: NID_X9_62_characteristic_two_field; seed_len: 0; param_len: 24; cofactor: 2
    );
    data:(
        (* no seed *)
        (* p *)
        $02, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $20, $00, $00, $00, $00, $00, $00, $00, $01,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $1e, $e9,
        (* x *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $18,
        (* y *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $0d,
        (* order *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $ED, $F9, $7C, $44, $DB, $9F, $24, $20, $BA, $FC, $A7, $5E
    )
);
_EC_brainpoolP160r1: TEC_brainpoolP160r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 20; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $E9, $5E, $4A, $5F, $73, $70, $59, $DC, $60, $DF, $C7, $AD,
        $95, $B3, $D8, $13, $95, $15, $62, $0F,
        (* a *)
        $34, $0E, $7B, $E2, $A2, $80, $EB, $74, $E2, $BE, $61, $BA,
        $DA, $74, $5D, $97, $E8, $F7, $C3, $00,
        (* b *)
        $1E, $58, $9A, $85, $95, $42, $34, $12, $13, $4F, $AA, $2D,
        $BD, $EC, $95, $C8, $D8, $67, $5E, $58,
        (* x *)
        $BE, $D5, $AF, $16, $EA, $3F, $6A, $4F, $62, $93, $8C, $46,
        $31, $EB, $5A, $F7, $BD, $BC, $DB, $C3,
        (* y *)
        $16, $67, $CB, $47, $7A, $1A, $8E, $C3, $38, $F9, $47, $41,
        $66, $9C, $97, $63, $16, $DA, $63, $21,
        (* order *)
        $E9, $5E, $4A, $5F, $73, $70, $59, $DC, $60, $DF, $59, $91,
        $D4, $50, $29, $40, $9E, $60, $FC, $09
    )
);
_EC_brainpoolP160t1: TEC_brainpoolP160t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 20; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $E9, $5E, $4A, $5F, $73, $70, $59, $DC, $60, $DF, $C7, $AD,
        $95, $B3, $D8, $13, $95, $15, $62, $0F,
        (* a *)
        $E9, $5E, $4A, $5F, $73, $70, $59, $DC, $60, $DF, $C7, $AD,
        $95, $B3, $D8, $13, $95, $15, $62, $0C,
        (* b *)
        $7A, $55, $6B, $6D, $AE, $53, $5B, $7B, $51, $ED, $2C, $4D,
        $7D, $AA, $7A, $0B, $5C, $55, $F3, $80,
        (* x *)
        $B1, $99, $B1, $3B, $9B, $34, $EF, $C1, $39, $7E, $64, $BA,
        $EB, $05, $AC, $C2, $65, $FF, $23, $78,
        (* y *)
        $AD, $D6, $71, $8B, $7C, $7C, $19, $61, $F0, $99, $1B, $84,
        $24, $43, $77, $21, $52, $C9, $E0, $AD,
        (* order *)
        $E9, $5E, $4A, $5F, $73, $70, $59, $DC, $60, $DF, $59, $91,
        $D4, $50, $29, $40, $9E, $60, $FC, $09
    )
);
_EC_brainpoolP192r1: TEC_brainpoolP192r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 24; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $C3, $02, $F4, $1D, $93, $2A, $36, $CD, $A7, $A3, $46, $30,
        $93, $D1, $8D, $B7, $8F, $CE, $47, $6D, $E1, $A8, $62, $97,
        (* a *)
        $6A, $91, $17, $40, $76, $B1, $E0, $E1, $9C, $39, $C0, $31,
        $FE, $86, $85, $C1, $CA, $E0, $40, $E5, $C6, $9A, $28, $EF,
        (* b *)
        $46, $9A, $28, $EF, $7C, $28, $CC, $A3, $DC, $72, $1D, $04,
        $4F, $44, $96, $BC, $CA, $7E, $F4, $14, $6F, $BF, $25, $C9,
        (* x *)
        $C0, $A0, $64, $7E, $AA, $B6, $A4, $87, $53, $B0, $33, $C5,
        $6C, $B0, $F0, $90, $0A, $2F, $5C, $48, $53, $37, $5F, $D6,
        (* y *)
        $14, $B6, $90, $86, $6A, $BD, $5B, $B8, $8B, $5F, $48, $28,
        $C1, $49, $00, $02, $E6, $77, $3F, $A2, $FA, $29, $9B, $8F,
        (* order *)
        $C3, $02, $F4, $1D, $93, $2A, $36, $CD, $A7, $A3, $46, $2F,
        $9E, $9E, $91, $6B, $5B, $E8, $F1, $02, $9A, $C4, $AC, $C1
    )
);
_EC_brainpoolP192t1: TEC_brainpoolP192t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 24; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $C3, $02, $F4, $1D, $93, $2A, $36, $CD, $A7, $A3, $46, $30,
        $93, $D1, $8D, $B7, $8F, $CE, $47, $6D, $E1, $A8, $62, $97,
        (* a *)
        $C3, $02, $F4, $1D, $93, $2A, $36, $CD, $A7, $A3, $46, $30,
        $93, $D1, $8D, $B7, $8F, $CE, $47, $6D, $E1, $A8, $62, $94,
        (* b *)
        $13, $D5, $6F, $FA, $EC, $78, $68, $1E, $68, $F9, $DE, $B4,
        $3B, $35, $BE, $C2, $FB, $68, $54, $2E, $27, $89, $7B, $79,
        (* x *)
        $3A, $E9, $E5, $8C, $82, $F6, $3C, $30, $28, $2E, $1F, $E7,
        $BB, $F4, $3F, $A7, $2C, $44, $6A, $F6, $F4, $61, $81, $29,
        (* y *)
        $09, $7E, $2C, $56, $67, $C2, $22, $3A, $90, $2A, $B5, $CA,
        $44, $9D, $00, $84, $B7, $E5, $B3, $DE, $7C, $CC, $01, $C9,
        (* order *)
        $C3, $02, $F4, $1D, $93, $2A, $36, $CD, $A7, $A3, $46, $2F,
        $9E, $9E, $91, $6B, $5B, $E8, $F1, $02, $9A, $C4, $AC, $C1
    )
);
 _EC_WTLS_8: TEC_WTLS_8 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 15; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FD, $E7,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $03,
        (* x *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $01,
        (* y *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $02,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $01, $EC, $EA, $55, $1A,
        $D8, $37, $E9
    )
);
 _EC_WTLS_9: TEC_WTLS_9 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 21; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $00, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $FF, $FF, $FC, $80, $8F,
        (* a *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $00,
        (* b *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $03,
        (* x *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $01,
        (* y *)
        $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $00, $00, $00, $00, $00, $02,
        (* order *)
        $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $CD,
        $C9, $8A, $E0, $E2, $DE, $57, $4A, $BF, $33
    )
);
 _EC_WTLS_12: TEC_WTLS_12 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 28; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FF, $00, $00, $00, $00, $00, $00, $00, $00,
        $00, $00, $00, $01,
        (* a *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $FF, $FE,
        (* b *)
        $B4, $05, $0A, $85, $0C, $04, $B3, $AB, $F5, $41, $32, $56,
        $50, $44, $B0, $B7, $D7, $BF, $D8, $BA, $27, $0B, $39, $43,
        $23, $55, $FF, $B4,
        (* x *)
        $B7, $0E, $0C, $BD, $6B, $B4, $BF, $7F, $32, $13, $90, $B9,
        $4A, $03, $C1, $D3, $56, $C2, $11, $22, $34, $32, $80, $D6,
        $11, $5C, $1D, $21,
        (* y *)
        $bd, $37, $63, $88, $b5, $f7, $23, $fb, $4c, $22, $df, $e6,
        $cd, $43, $75, $a0, $5a, $07, $47, $64, $44, $d5, $81, $99,
        $85, $00, $7e, $34,
        (* order *)
        $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
        $FF, $FF, $16, $A2, $E0, $B8, $F0, $3E, $13, $DD, $29, $45,
        $5C, $5C, $2A, $3D
    )
);
_EC_brainpoolP224r1: TEC_brainpoolP224r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 28; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $D7, $C1, $34, $AA, $26, $43, $66, $86, $2A, $18, $30, $25,
        $75, $D1, $D7, $87, $B0, $9F, $07, $57, $97, $DA, $89, $F5,
        $7E, $C8, $C0, $FF,
        (* a *)
        $68, $A5, $E6, $2C, $A9, $CE, $6C, $1C, $29, $98, $03, $A6,
        $C1, $53, $0B, $51, $4E, $18, $2A, $D8, $B0, $04, $2A, $59,
        $CA, $D2, $9F, $43,
        (* b *)
        $25, $80, $F6, $3C, $CF, $E4, $41, $38, $87, $07, $13, $B1,
        $A9, $23, $69, $E3, $3E, $21, $35, $D2, $66, $DB, $B3, $72,
        $38, $6C, $40, $0B,
        (* x *)
        $0D, $90, $29, $AD, $2C, $7E, $5C, $F4, $34, $08, $23, $B2,
        $A8, $7D, $C6, $8C, $9E, $4C, $E3, $17, $4C, $1E, $6E, $FD,
        $EE, $12, $C0, $7D,
        (* y *)
        $58, $AA, $56, $F7, $72, $C0, $72, $6F, $24, $C6, $B8, $9E,
        $4E, $CD, $AC, $24, $35, $4B, $9E, $99, $CA, $A3, $F6, $D3,
        $76, $14, $02, $CD,
        (* order *)
        $D7, $C1, $34, $AA, $26, $43, $66, $86, $2A, $18, $30, $25,
        $75, $D0, $FB, $98, $D1, $16, $BC, $4B, $6D, $DE, $BC, $A3,
        $A5, $A7, $93, $9F
    )
);
 _EC_brainpoolP224t1: TEC_brainpoolP224t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 28; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $D7, $C1, $34, $AA, $26, $43, $66, $86, $2A, $18, $30, $25,
        $75, $D1, $D7, $87, $B0, $9F, $07, $57, $97, $DA, $89, $F5,
        $7E, $C8, $C0, $FF,
        (* a *)
        $D7, $C1, $34, $AA, $26, $43, $66, $86, $2A, $18, $30, $25,
        $75, $D1, $D7, $87, $B0, $9F, $07, $57, $97, $DA, $89, $F5,
        $7E, $C8, $C0, $FC,
        (* b *)
        $4B, $33, $7D, $93, $41, $04, $CD, $7B, $EF, $27, $1B, $F6,
        $0C, $ED, $1E, $D2, $0D, $A1, $4C, $08, $B3, $BB, $64, $F1,
        $8A, $60, $88, $8D,
        (* x *)
        $6A, $B1, $E3, $44, $CE, $25, $FF, $38, $96, $42, $4E, $7F,
        $FE, $14, $76, $2E, $CB, $49, $F8, $92, $8A, $C0, $C7, $60,
        $29, $B4, $D5, $80,
        (* y *)
        $03, $74, $E9, $F5, $14, $3E, $56, $8C, $D2, $3F, $3F, $4D,
        $7C, $0D, $4B, $1E, $41, $C8, $CC, $0D, $1C, $6A, $BD, $5F,
        $1A, $46, $DB, $4C,
        (* order *)
        $D7, $C1, $34, $AA, $26, $43, $66, $86, $2A, $18, $30, $25,
        $75, $D0, $FB, $98, $D1, $16, $BC, $4B, $6D, $DE, $BC, $A3,
        $A5, $A7, $93, $9F
    )
);
_EC_brainpoolP256r1: TEC_brainpoolP256r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 32; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $A9, $FB, $57, $DB, $A1, $EE, $A9, $BC, $3E, $66, $0A, $90,
        $9D, $83, $8D, $72, $6E, $3B, $F6, $23, $D5, $26, $20, $28,
        $20, $13, $48, $1D, $1F, $6E, $53, $77,
        (* a *)
        $7D, $5A, $09, $75, $FC, $2C, $30, $57, $EE, $F6, $75, $30,
        $41, $7A, $FF, $E7, $FB, $80, $55, $C1, $26, $DC, $5C, $6C,
        $E9, $4A, $4B, $44, $F3, $30, $B5, $D9,
        (* b *)
        $26, $DC, $5C, $6C, $E9, $4A, $4B, $44, $F3, $30, $B5, $D9,
        $BB, $D7, $7C, $BF, $95, $84, $16, $29, $5C, $F7, $E1, $CE,
        $6B, $CC, $DC, $18, $FF, $8C, $07, $B6,
        (* x *)
        $8B, $D2, $AE, $B9, $CB, $7E, $57, $CB, $2C, $4B, $48, $2F,
        $FC, $81, $B7, $AF, $B9, $DE, $27, $E1, $E3, $BD, $23, $C2,
        $3A, $44, $53, $BD, $9A, $CE, $32, $62,
        (* y *)
        $54, $7E, $F8, $35, $C3, $DA, $C4, $FD, $97, $F8, $46, $1A,
        $14, $61, $1D, $C9, $C2, $77, $45, $13, $2D, $ED, $8E, $54,
        $5C, $1D, $54, $C7, $2F, $04, $69, $97,
        (* order *)
        $A9, $FB, $57, $DB, $A1, $EE, $A9, $BC, $3E, $66, $0A, $90,
        $9D, $83, $8D, $71, $8C, $39, $7A, $A3, $B5, $61, $A6, $F7,
        $90, $1E, $0E, $82, $97, $48, $56, $A7
    )
);
 _EC_brainpoolP256t1: TEC_brainpoolP256t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 32; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $A9, $FB, $57, $DB, $A1, $EE, $A9, $BC, $3E, $66, $0A, $90,
        $9D, $83, $8D, $72, $6E, $3B, $F6, $23, $D5, $26, $20, $28,
        $20, $13, $48, $1D, $1F, $6E, $53, $77,
        (* a *)
        $A9, $FB, $57, $DB, $A1, $EE, $A9, $BC, $3E, $66, $0A, $90,
        $9D, $83, $8D, $72, $6E, $3B, $F6, $23, $D5, $26, $20, $28,
        $20, $13, $48, $1D, $1F, $6E, $53, $74,
        (* b *)
        $66, $2C, $61, $C4, $30, $D8, $4E, $A4, $FE, $66, $A7, $73,
        $3D, $0B, $76, $B7, $BF, $93, $EB, $C4, $AF, $2F, $49, $25,
        $6A, $E5, $81, $01, $FE, $E9, $2B, $04,
        (* x *)
        $A3, $E8, $EB, $3C, $C1, $CF, $E7, $B7, $73, $22, $13, $B2,
        $3A, $65, $61, $49, $AF, $A1, $42, $C4, $7A, $AF, $BC, $2B,
        $79, $A1, $91, $56, $2E, $13, $05, $F4,
        (* y *)
        $2D, $99, $6C, $82, $34, $39, $C5, $6D, $7F, $7B, $22, $E1,
        $46, $44, $41, $7E, $69, $BC, $B6, $DE, $39, $D0, $27, $00,
        $1D, $AB, $E8, $F3, $5B, $25, $C9, $BE,
        (* order *)
        $A9, $FB, $57, $DB, $A1, $EE, $A9, $BC, $3E, $66, $0A, $90,
        $9D, $83, $8D, $71, $8C, $39, $7A, $A3, $B5, $61, $A6, $F7,
        $90, $1E, $0E, $82, $97, $48, $56, $A7
    )
);

_EC_brainpoolP320r1: TEC_brainpoolP320r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 40; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $D3, $5E, $47, $20, $36, $BC, $4F, $B7, $E1, $3C, $78, $5E,
        $D2, $01, $E0, $65, $F9, $8F, $CF, $A6, $F6, $F4, $0D, $EF,
        $4F, $92, $B9, $EC, $78, $93, $EC, $28, $FC, $D4, $12, $B1,
        $F1, $B3, $2E, $27,
        (* a *)
        $3E, $E3, $0B, $56, $8F, $BA, $B0, $F8, $83, $CC, $EB, $D4,
        $6D, $3F, $3B, $B8, $A2, $A7, $35, $13, $F5, $EB, $79, $DA,
        $66, $19, $0E, $B0, $85, $FF, $A9, $F4, $92, $F3, $75, $A9,
        $7D, $86, $0E, $B4,
        (* b *)
        $52, $08, $83, $94, $9D, $FD, $BC, $42, $D3, $AD, $19, $86,
        $40, $68, $8A, $6F, $E1, $3F, $41, $34, $95, $54, $B4, $9A,
        $CC, $31, $DC, $CD, $88, $45, $39, $81, $6F, $5E, $B4, $AC,
        $8F, $B1, $F1, $A6,
        (* x *)
        $43, $BD, $7E, $9A, $FB, $53, $D8, $B8, $52, $89, $BC, $C4,
        $8E, $E5, $BF, $E6, $F2, $01, $37, $D1, $0A, $08, $7E, $B6,
        $E7, $87, $1E, $2A, $10, $A5, $99, $C7, $10, $AF, $8D, $0D,
        $39, $E2, $06, $11,
        (* y *)
        $14, $FD, $D0, $55, $45, $EC, $1C, $C8, $AB, $40, $93, $24,
        $7F, $77, $27, $5E, $07, $43, $FF, $ED, $11, $71, $82, $EA,
        $A9, $C7, $78, $77, $AA, $AC, $6A, $C7, $D3, $52, $45, $D1,
        $69, $2E, $8E, $E1,
        (* order *)
        $D3, $5E, $47, $20, $36, $BC, $4F, $B7, $E1, $3C, $78, $5E,
        $D2, $01, $E0, $65, $F9, $8F, $CF, $A5, $B6, $8F, $12, $A3,
        $2D, $48, $2E, $C7, $EE, $86, $58, $E9, $86, $91, $55, $5B,
        $44, $C5, $93, $11
    )
);
_EC_brainpoolP320t1: TEC_brainpoolP320t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 40; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $D3, $5E, $47, $20, $36, $BC, $4F, $B7, $E1, $3C, $78, $5E,
        $D2, $01, $E0, $65, $F9, $8F, $CF, $A6, $F6, $F4, $0D, $EF,
        $4F, $92, $B9, $EC, $78, $93, $EC, $28, $FC, $D4, $12, $B1,
        $F1, $B3, $2E, $27,
        (* a *)
        $D3, $5E, $47, $20, $36, $BC, $4F, $B7, $E1, $3C, $78, $5E,
        $D2, $01, $E0, $65, $F9, $8F, $CF, $A6, $F6, $F4, $0D, $EF,
        $4F, $92, $B9, $EC, $78, $93, $EC, $28, $FC, $D4, $12, $B1,
        $F1, $B3, $2E, $24,
        (* b *)
        $A7, $F5, $61, $E0, $38, $EB, $1E, $D5, $60, $B3, $D1, $47,
        $DB, $78, $20, $13, $06, $4C, $19, $F2, $7E, $D2, $7C, $67,
        $80, $AA, $F7, $7F, $B8, $A5, $47, $CE, $B5, $B4, $FE, $F4,
        $22, $34, $03, $53,
        (* x *)
        $92, $5B, $E9, $FB, $01, $AF, $C6, $FB, $4D, $3E, $7D, $49,
        $90, $01, $0F, $81, $34, $08, $AB, $10, $6C, $4F, $09, $CB,
        $7E, $E0, $78, $68, $CC, $13, $6F, $FF, $33, $57, $F6, $24,
        $A2, $1B, $ED, $52,
        (* y *)
        $63, $BA, $3A, $7A, $27, $48, $3E, $BF, $66, $71, $DB, $EF,
        $7A, $BB, $30, $EB, $EE, $08, $4E, $58, $A0, $B0, $77, $AD,
        $42, $A5, $A0, $98, $9D, $1E, $E7, $1B, $1B, $9B, $C0, $45,
        $5F, $B0, $D2, $C3,
        (* order *)
        $D3, $5E, $47, $20, $36, $BC, $4F, $B7, $E1, $3C, $78, $5E,
        $D2, $01, $E0, $65, $F9, $8F, $CF, $A5, $B6, $8F, $12, $A3,
        $2D, $48, $2E, $C7, $EE, $86, $58, $E9, $86, $91, $55, $5B,
        $44, $C5, $93, $11
    )
);
_EC_brainpoolP384r1: TEC_brainpoolP384r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 48; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $8C, $B9, $1E, $82, $A3, $38, $6D, $28, $0F, $5D, $6F, $7E,
        $50, $E6, $41, $DF, $15, $2F, $71, $09, $ED, $54, $56, $B4,
        $12, $B1, $DA, $19, $7F, $B7, $11, $23, $AC, $D3, $A7, $29,
        $90, $1D, $1A, $71, $87, $47, $00, $13, $31, $07, $EC, $53,
        (* a *)
        $7B, $C3, $82, $C6, $3D, $8C, $15, $0C, $3C, $72, $08, $0A,
        $CE, $05, $AF, $A0, $C2, $BE, $A2, $8E, $4F, $B2, $27, $87,
        $13, $91, $65, $EF, $BA, $91, $F9, $0F, $8A, $A5, $81, $4A,
        $50, $3A, $D4, $EB, $04, $A8, $C7, $DD, $22, $CE, $28, $26,
        (* b *)
        $04, $A8, $C7, $DD, $22, $CE, $28, $26, $8B, $39, $B5, $54,
        $16, $F0, $44, $7C, $2F, $B7, $7D, $E1, $07, $DC, $D2, $A6,
        $2E, $88, $0E, $A5, $3E, $EB, $62, $D5, $7C, $B4, $39, $02,
        $95, $DB, $C9, $94, $3A, $B7, $86, $96, $FA, $50, $4C, $11,
        (* x *)
        $1D, $1C, $64, $F0, $68, $CF, $45, $FF, $A2, $A6, $3A, $81,
        $B7, $C1, $3F, $6B, $88, $47, $A3, $E7, $7E, $F1, $4F, $E3,
        $DB, $7F, $CA, $FE, $0C, $BD, $10, $E8, $E8, $26, $E0, $34,
        $36, $D6, $46, $AA, $EF, $87, $B2, $E2, $47, $D4, $AF, $1E,
        (* y *)
        $8A, $BE, $1D, $75, $20, $F9, $C2, $A4, $5C, $B1, $EB, $8E,
        $95, $CF, $D5, $52, $62, $B7, $0B, $29, $FE, $EC, $58, $64,
        $E1, $9C, $05, $4F, $F9, $91, $29, $28, $0E, $46, $46, $21,
        $77, $91, $81, $11, $42, $82, $03, $41, $26, $3C, $53, $15,
        (* order *)
        $8C, $B9, $1E, $82, $A3, $38, $6D, $28, $0F, $5D, $6F, $7E,
        $50, $E6, $41, $DF, $15, $2F, $71, $09, $ED, $54, $56, $B3,
        $1F, $16, $6E, $6C, $AC, $04, $25, $A7, $CF, $3A, $B6, $AF,
        $6B, $7F, $C3, $10, $3B, $88, $32, $02, $E9, $04, $65, $65
    )
);
_EC_brainpoolP384t1: TEC_brainpoolP384t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 48; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $8C, $B9, $1E, $82, $A3, $38, $6D, $28, $0F, $5D, $6F, $7E,
        $50, $E6, $41, $DF, $15, $2F, $71, $09, $ED, $54, $56, $B4,
        $12, $B1, $DA, $19, $7F, $B7, $11, $23, $AC, $D3, $A7, $29,
        $90, $1D, $1A, $71, $87, $47, $00, $13, $31, $07, $EC, $53,
        (* a *)
        $8C, $B9, $1E, $82, $A3, $38, $6D, $28, $0F, $5D, $6F, $7E,
        $50, $E6, $41, $DF, $15, $2F, $71, $09, $ED, $54, $56, $B4,
        $12, $B1, $DA, $19, $7F, $B7, $11, $23, $AC, $D3, $A7, $29,
        $90, $1D, $1A, $71, $87, $47, $00, $13, $31, $07, $EC, $50,
        (* b *)
        $7F, $51, $9E, $AD, $A7, $BD, $A8, $1B, $D8, $26, $DB, $A6,
        $47, $91, $0F, $8C, $4B, $93, $46, $ED, $8C, $CD, $C6, $4E,
        $4B, $1A, $BD, $11, $75, $6D, $CE, $1D, $20, $74, $AA, $26,
        $3B, $88, $80, $5C, $ED, $70, $35, $5A, $33, $B4, $71, $EE,
        (* x *)
        $18, $DE, $98, $B0, $2D, $B9, $A3, $06, $F2, $AF, $CD, $72,
        $35, $F7, $2A, $81, $9B, $80, $AB, $12, $EB, $D6, $53, $17,
        $24, $76, $FE, $CD, $46, $2A, $AB, $FF, $C4, $FF, $19, $1B,
        $94, $6A, $5F, $54, $D8, $D0, $AA, $2F, $41, $88, $08, $CC,
        (* y *)
        $25, $AB, $05, $69, $62, $D3, $06, $51, $A1, $14, $AF, $D2,
        $75, $5A, $D3, $36, $74, $7F, $93, $47, $5B, $7A, $1F, $CA,
        $3B, $88, $F2, $B6, $A2, $08, $CC, $FE, $46, $94, $08, $58,
        $4D, $C2, $B2, $91, $26, $75, $BF, $5B, $9E, $58, $29, $28,
        (* order *)
        $8C, $B9, $1E, $82, $A3, $38, $6D, $28, $0F, $5D, $6F, $7E,
        $50, $E6, $41, $DF, $15, $2F, $71, $09, $ED, $54, $56, $B3,
        $1F, $16, $6E, $6C, $AC, $04, $25, $A7, $CF, $3A, $B6, $AF,
        $6B, $7F, $C3, $10, $3B, $88, $32, $02, $E9, $04, $65, $65
    )
);
_EC_brainpoolP512r1: TEC_brainpoolP512r1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 64; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $AA, $DD, $9D, $B8, $DB, $E9, $C4, $8B, $3F, $D4, $E6, $AE,
        $33, $C9, $FC, $07, $CB, $30, $8D, $B3, $B3, $C9, $D2, $0E,
        $D6, $63, $9C, $CA, $70, $33, $08, $71, $7D, $4D, $9B, $00,
        $9B, $C6, $68, $42, $AE, $CD, $A1, $2A, $E6, $A3, $80, $E6,
        $28, $81, $FF, $2F, $2D, $82, $C6, $85, $28, $AA, $60, $56,
        $58, $3A, $48, $F3,
        (* a *)
        $78, $30, $A3, $31, $8B, $60, $3B, $89, $E2, $32, $71, $45,
        $AC, $23, $4C, $C5, $94, $CB, $DD, $8D, $3D, $F9, $16, $10,
        $A8, $34, $41, $CA, $EA, $98, $63, $BC, $2D, $ED, $5D, $5A,
        $A8, $25, $3A, $A1, $0A, $2E, $F1, $C9, $8B, $9A, $C8, $B5,
        $7F, $11, $17, $A7, $2B, $F2, $C7, $B9, $E7, $C1, $AC, $4D,
        $77, $FC, $94, $CA,
        (* b *)
        $3D, $F9, $16, $10, $A8, $34, $41, $CA, $EA, $98, $63, $BC,
        $2D, $ED, $5D, $5A, $A8, $25, $3A, $A1, $0A, $2E, $F1, $C9,
        $8B, $9A, $C8, $B5, $7F, $11, $17, $A7, $2B, $F2, $C7, $B9,
        $E7, $C1, $AC, $4D, $77, $FC, $94, $CA, $DC, $08, $3E, $67,
        $98, $40, $50, $B7, $5E, $BA, $E5, $DD, $28, $09, $BD, $63,
        $80, $16, $F7, $23,
        (* x *)
        $81, $AE, $E4, $BD, $D8, $2E, $D9, $64, $5A, $21, $32, $2E,
        $9C, $4C, $6A, $93, $85, $ED, $9F, $70, $B5, $D9, $16, $C1,
        $B4, $3B, $62, $EE, $F4, $D0, $09, $8E, $FF, $3B, $1F, $78,
        $E2, $D0, $D4, $8D, $50, $D1, $68, $7B, $93, $B9, $7D, $5F,
        $7C, $6D, $50, $47, $40, $6A, $5E, $68, $8B, $35, $22, $09,
        $BC, $B9, $F8, $22,
        (* y *)
        $7D, $DE, $38, $5D, $56, $63, $32, $EC, $C0, $EA, $BF, $A9,
        $CF, $78, $22, $FD, $F2, $09, $F7, $00, $24, $A5, $7B, $1A,
        $A0, $00, $C5, $5B, $88, $1F, $81, $11, $B2, $DC, $DE, $49,
        $4A, $5F, $48, $5E, $5B, $CA, $4B, $D8, $8A, $27, $63, $AE,
        $D1, $CA, $2B, $2F, $A8, $F0, $54, $06, $78, $CD, $1E, $0F,
        $3A, $D8, $08, $92,
        (* order *)
        $AA, $DD, $9D, $B8, $DB, $E9, $C4, $8B, $3F, $D4, $E6, $AE,
        $33, $C9, $FC, $07, $CB, $30, $8D, $B3, $B3, $C9, $D2, $0E,
        $D6, $63, $9C, $CA, $70, $33, $08, $70, $55, $3E, $5C, $41,
        $4C, $A9, $26, $19, $41, $86, $61, $19, $7F, $AC, $10, $47,
        $1D, $B1, $D3, $81, $08, $5D, $DA, $DD, $B5, $87, $96, $82,
        $9C, $A9, $00, $69
    )
);
_EC_brainpoolP512t1: TEC_brainpoolP512t1 = (
    h:(
        field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 64; cofactor: 1
    );
    data:(
        (* no seed *)
        (* p *)
        $AA, $DD, $9D, $B8, $DB, $E9, $C4, $8B, $3F, $D4, $E6, $AE,
        $33, $C9, $FC, $07, $CB, $30, $8D, $B3, $B3, $C9, $D2, $0E,
        $D6, $63, $9C, $CA, $70, $33, $08, $71, $7D, $4D, $9B, $00,
        $9B, $C6, $68, $42, $AE, $CD, $A1, $2A, $E6, $A3, $80, $E6,
        $28, $81, $FF, $2F, $2D, $82, $C6, $85, $28, $AA, $60, $56,
        $58, $3A, $48, $F3,
        (* a *)
        $AA, $DD, $9D, $B8, $DB, $E9, $C4, $8B, $3F, $D4, $E6, $AE,
        $33, $C9, $FC, $07, $CB, $30, $8D, $B3, $B3, $C9, $D2, $0E,
        $D6, $63, $9C, $CA, $70, $33, $08, $71, $7D, $4D, $9B, $00,
        $9B, $C6, $68, $42, $AE, $CD, $A1, $2A, $E6, $A3, $80, $E6,
        $28, $81, $FF, $2F, $2D, $82, $C6, $85, $28, $AA, $60, $56,
        $58, $3A, $48, $F0,
        (* b *)
        $7C, $BB, $BC, $F9, $44, $1C, $FA, $B7, $6E, $18, $90, $E4,
        $68, $84, $EA, $E3, $21, $F7, $0C, $0B, $CB, $49, $81, $52,
        $78, $97, $50, $4B, $EC, $3E, $36, $A6, $2B, $CD, $FA, $23,
        $04, $97, $65, $40, $F6, $45, $00, $85, $F2, $DA, $E1, $45,
        $C2, $25, $53, $B4, $65, $76, $36, $89, $18, $0E, $A2, $57,
        $18, $67, $42, $3E,
        (* x *)
        $64, $0E, $CE, $5C, $12, $78, $87, $17, $B9, $C1, $BA, $06,
        $CB, $C2, $A6, $FE, $BA, $85, $84, $24, $58, $C5, $6D, $DE,
        $9D, $B1, $75, $8D, $39, $C0, $31, $3D, $82, $BA, $51, $73,
        $5C, $DB, $3E, $A4, $99, $AA, $77, $A7, $D6, $94, $3A, $64,
        $F7, $A3, $F2, $5F, $E2, $6F, $06, $B5, $1B, $AA, $26, $96,
        $FA, $90, $35, $DA,
        (* y *)
        $5B, $53, $4B, $D5, $95, $F5, $AF, $0F, $A2, $C8, $92, $37,
        $6C, $84, $AC, $E1, $BB, $4E, $30, $19, $B7, $16, $34, $C0,
        $11, $31, $15, $9C, $AE, $03, $CE, $E9, $D9, $93, $21, $84,
        $BE, $EF, $21, $6B, $D7, $1D, $F2, $DA, $DF, $86, $A6, $27,
        $30, $6E, $CF, $F9, $6D, $BB, $8B, $AC, $E1, $98, $B6, $1E,
        $00, $F8, $B3, $32,
        (* order *)
        $AA, $DD, $9D, $B8, $DB, $E9, $C4, $8B, $3F, $D4, $E6, $AE,
        $33, $C9, $FC, $07, $CB, $30, $8D, $B3, $B3, $C9, $D2, $0E,
        $D6, $63, $9C, $CA, $70, $33, $08, $70, $55, $3E, $5C, $41,
        $4C, $A9, $26, $19, $41, $86, $61, $19, $7F, $AC, $10, $47,
        $1D, $B1, $D3, $81, $08, $5D, $DA, $DD, $B5, $87, $96, $82,
        $9C, $A9, $00, $69
    )
);
_EC_sm2p256v1: TEC_sm2p256v1 = (
    h:(
       field_type: NID_X9_62_prime_field; seed_len: 0; param_len: 32; cofactor: 1
    );
    data:(
        (* no seed *)

        (* p *)
        $ff, $ff, $ff, $fe, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
        $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $00, $00, $00, $00,
        $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
        (* a *)
        $ff, $ff, $ff, $fe, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
        $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $00, $00, $00, $00,
        $ff, $ff, $ff, $ff, $ff, $ff, $ff, $fc,
        (* b *)
        $28, $e9, $fa, $9e, $9d, $9f, $5e, $34, $4d, $5a, $9e, $4b,
        $cf, $65, $09, $a7, $f3, $97, $89, $f5, $15, $ab, $8f, $92,
        $dd, $bc, $bd, $41, $4d, $94, $0e, $93,
        (* x *)
        $32, $c4, $ae, $2c, $1f, $19, $81, $19, $5f, $99, $04, $46,
        $6a, $39, $c9, $94, $8f, $e3, $0b, $bf, $f2, $66, $0b, $e1,
        $71, $5a, $45, $89, $33, $4c, $74, $c7,
        (* y *)
        $bc, $37, $36, $a2, $f4, $f6, $77, $9c, $59, $bd, $ce, $e3,
        $6b, $69, $21, $53, $d0, $a9, $87, $7c, $c6, $2a, $47, $40,
        $02, $df, $32, $e5, $21, $39, $f0, $a0,
        (* order *)
        $ff, $ff, $ff, $fe, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
        $ff, $ff, $ff, $ff, $72, $03, $df, $6b, $21, $c6, $05, $2b,
        $53, $bb, $f4, $09, $39, $d5, $41, $23
    )
);

  curve_list: array[0..81] of Tec_list_element =(
(* prime field curves
     secg curves *)
    (nid: NID_secp112r1; data:@_EC_SECG_PRIME_112R1.h; meth:nil;
     comment:'SECG/WTLS curve over a 112 bit prime field'),
    (nid: NID_secp112r2; data:@_EC_SECG_PRIME_112R2.h; meth:nil;
     comment:'SECG curve over a 112 bit prime field'),
    (nid: NID_secp128r1; data:@_EC_SECG_PRIME_128R1.h; meth:nil;
     comment:'SECG curve over a 128 bit prime field'),
    (nid: NID_secp128r2; data:@_EC_SECG_PRIME_128R2.h; meth:nil;
     comment:'SECG curve over a 128 bit prime field'),
    (nid: NID_secp160k1; data:@_EC_SECG_PRIME_160K1.h; meth:nil;
     comment:'SECG curve over a 160 bit prime field'),
    (nid: NID_secp160r1; data:@_EC_SECG_PRIME_160R1.h; meth:nil;
     comment:'SECG curve over a 160 bit prime field'),
    (nid: NID_secp160r2; data:@_EC_SECG_PRIME_160R2.h; meth:nil;
     comment:'SECG/WTLS curve over a 160 bit prime field'),
    (* SECG secp192r1 is the same as X9.62 prime192v1 and hence omitted *)
    (nid: NID_secp192k1; data:@_EC_SECG_PRIME_192K1.h; meth:nil;
     comment:'SECG curve over a 192 bit prime field'),
    (nid: NID_secp224k1; data:@_EC_SECG_PRIME_224K1.h; meth:nil;
     comment:'SECG curve over a 224 bit prime field'),
{$ifndef OPENSSL_NO_EC_NISTP_64_GCC_128}
    (nid: NID_secp224r1; data:@_EC_NIST_PRIME_224.h; meth:EC_GFp_nistp224_method;
     comment:'NIST/SECG curve over a 224 bit prime field'),
{$else}
    (nid: NID_secp224r1; data:@_EC_NIST_PRIME_224.h; meth:nil;
     comment:'NIST/SECG curve over a 224 bit prime field'),
{$endif}
    (nid: NID_secp256k1; data:@_EC_SECG_PRIME_256K1.h; meth:nil;
     comment:'SECG curve over a 256 bit prime field'),
    (* SECG secp256r1 is the same as X9.62 prime256v1 and hence omitted *)
    (nid: NID_secp384r1; data:@_EC_NIST_PRIME_384.h;
{$if defined(S390X_EC_ASM)}
     EC_GFp_s390x_nistp384_method;
{$else}
     meth:nil;
{$endif}
     comment:'NIST/SECG curve over a 384 bit prime field'),
    (nid: NID_secp521r1; data:@_EC_NIST_PRIME_521.h;
{$if defined(S390X_EC_ASM)}
     EC_GFp_s390x_nistp521_method;
{$elif !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)}
     EC_GFp_nistp521_method;
{$else}
     meth:nil;
{$endif}
     comment:'NIST/SECG curve over a 521 bit prime field'),
    (* X9.62 curves *)
    (nid: NID_X9_62_prime192v1; data:@_EC_NIST_PRIME_192.h; meth:nil;
     comment:'NIST/X9.62/SECG curve over a 192 bit prime field'),
    (nid: NID_X9_62_prime192v2; data:@_EC_X9_62_PRIME_192V2.h; meth:nil;
     comment:'X9.62 curve over a 192 bit prime field'),
    (nid: NID_X9_62_prime192v3; data:@_EC_X9_62_PRIME_192V3.h; meth:nil;
     comment:'X9.62 curve over a 192 bit prime field'),
    (nid: NID_X9_62_prime239v1; data:@_EC_X9_62_PRIME_239V1.h; meth:nil;
     comment:'X9.62 curve over a 239 bit prime field'),
    (nid: NID_X9_62_prime239v2; data:@_EC_X9_62_PRIME_239V2.h; meth:nil;
     comment:'X9.62 curve over a 239 bit prime field'),
    (nid: NID_X9_62_prime239v3; data:@_EC_X9_62_PRIME_239V3.h; meth:nil;
     comment:'X9.62 curve over a 239 bit prime field'),
    (nid: NID_X9_62_prime256v1; data:@_EC_X9_62_PRIME_256V1.h;
{$if defined(ECP_NISTZ256_ASM)}
     EC_GFp_nistz256_method;
{$elif defined(S390X_EC_ASM)}
     EC_GFp_s390x_nistp256_method;
{$elif not defined(OPENSSL_NO_EC_NISTP_64_GCC_128)}
     EC_GFp_nistp256_method;
{$else}
     meth:nil;
{$endif}
     comment:'X9.62/SECG curve over a 256 bit prime field'),
{$ifndef OPENSSL_NO_EC2M}
    (* characteristic two field curves *)
    (* NIST/SECG curves *)
    (nid: NID_sect113r1; data:@_EC_SECG_CHAR2_113R1.h; meth:nil;
     comment:'SECG curve over a 113 bit binary field'),
    (nid: NID_sect113r2; data:@_EC_SECG_CHAR2_113R2.h; meth:nil;
     comment:'SECG curve over a 113 bit binary field'),
    (nid: NID_sect131r1; data:@_EC_SECG_CHAR2_131R1.h; meth:nil;
     comment:'SECG/WTLS curve over a 131 bit binary field'),
    (nid: NID_sect131r2; data:@_EC_SECG_CHAR2_131R2.h; meth:nil;
     comment:'SECG curve over a 131 bit binary field'),
    (nid: NID_sect163k1; data:@_EC_NIST_CHAR2_163K.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 163 bit binary field'),
    (nid: NID_sect163r1; data:@_EC_SECG_CHAR2_163R1.h; meth:nil;
     comment:'SECG curve over a 163 bit binary field'),
    (nid: NID_sect163r2; data:@_EC_NIST_CHAR2_163B.h; meth:nil;
     comment:'NIST/SECG curve over a 163 bit binary field'),
    (nid: NID_sect193r1; data:@_EC_SECG_CHAR2_193R1.h; meth:nil;
     comment:'SECG curve over a 193 bit binary field'),
    (nid: NID_sect193r2; data:@_EC_SECG_CHAR2_193R2.h; meth:nil;
     comment:'SECG curve over a 193 bit binary field'),
    (nid: NID_sect233k1; data:@_EC_NIST_CHAR2_233K.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 233 bit binary field'),
    (nid: NID_sect233r1; data:@_EC_NIST_CHAR2_233B.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 233 bit binary field'),
    (nid: NID_sect239k1; data:@_EC_SECG_CHAR2_239K1.h; meth:nil;
     comment:'SECG curve over a 239 bit binary field'),
    (nid: NID_sect283k1; data:@_EC_NIST_CHAR2_283K.h; meth:nil;
     comment:'NIST/SECG curve over a 283 bit binary field'),
    (nid: NID_sect283r1; data:@_EC_NIST_CHAR2_283B.h; meth:nil;
     comment:'NIST/SECG curve over a 283 bit binary field'),
    (nid: NID_sect409k1; data:@_EC_NIST_CHAR2_409K.h; meth:nil;
     comment:'NIST/SECG curve over a 409 bit binary field'),
    (nid: NID_sect409r1; data:@_EC_NIST_CHAR2_409B.h; meth:nil;
     comment:'NIST/SECG curve over a 409 bit binary field'),
    (nid: NID_sect571k1; data:@_EC_NIST_CHAR2_571K.h; meth:nil;
     comment:'NIST/SECG curve over a 571 bit binary field'),
    (nid: NID_sect571r1; data:@_EC_NIST_CHAR2_571B.h; meth:nil;
     comment:'NIST/SECG curve over a 571 bit binary field'),
    (* X9.62 curves *)
    (nid: NID_X9_62_c2pnb163v1; data:@_EC_X9_62_CHAR2_163V1.h; meth:nil;
     comment:'X9.62 curve over a 163 bit binary field'),
    (nid: NID_X9_62_c2pnb163v2; data:@_EC_X9_62_CHAR2_163V2.h; meth:nil;
     comment:'X9.62 curve over a 163 bit binary field'),
    (nid: NID_X9_62_c2pnb163v3; data:@_EC_X9_62_CHAR2_163V3.h; meth:nil;
     comment:'X9.62 curve over a 163 bit binary field'),
    (nid: NID_X9_62_c2pnb176v1; data:@_EC_X9_62_CHAR2_176V1.h; meth:nil;
     comment:'X9.62 curve over a 176 bit binary field'),
    (nid: NID_X9_62_c2tnb191v1; data:@_EC_X9_62_CHAR2_191V1.h; meth:nil;
     comment:'X9.62 curve over a 191 bit binary field'),
    (nid: NID_X9_62_c2tnb191v2; data:@_EC_X9_62_CHAR2_191V2.h; meth:nil;
     comment:'X9.62 curve over a 191 bit binary field'),
    (nid: NID_X9_62_c2tnb191v3; data:@_EC_X9_62_CHAR2_191V3.h; meth:nil;
     comment:'X9.62 curve over a 191 bit binary field'),
    (nid: NID_X9_62_c2pnb208w1; data:@_EC_X9_62_CHAR2_208W1.h; meth:nil;
     comment:'X9.62 curve over a 208 bit binary field'),
    (nid: NID_X9_62_c2tnb239v1; data:@_EC_X9_62_CHAR2_239V1.h; meth:nil;
     comment:'X9.62 curve over a 239 bit binary field'),
    (nid: NID_X9_62_c2tnb239v2; data:@_EC_X9_62_CHAR2_239V2.h; meth:nil;
     comment:'X9.62 curve over a 239 bit binary field'),
    (nid: NID_X9_62_c2tnb239v3; data:@_EC_X9_62_CHAR2_239V3.h; meth:nil;
     comment:'X9.62 curve over a 239 bit binary field'),
    (nid: NID_X9_62_c2pnb272w1; data:@_EC_X9_62_CHAR2_272W1.h; meth:nil;
     comment:'X9.62 curve over a 272 bit binary field'),
    (nid: NID_X9_62_c2pnb304w1; data:@_EC_X9_62_CHAR2_304W1.h; meth:nil;
     comment:'X9.62 curve over a 304 bit binary field'),
    (nid: NID_X9_62_c2tnb359v1; data:@_EC_X9_62_CHAR2_359V1.h; meth:nil;
     comment:'X9.62 curve over a 359 bit binary field'),
    (nid: NID_X9_62_c2pnb368w1; data:@_EC_X9_62_CHAR2_368W1.h; meth:nil;
     comment:'X9.62 curve over a 368 bit binary field'),
    (nid: NID_X9_62_c2tnb431r1; data:@_EC_X9_62_CHAR2_431R1.h; meth:nil;
     comment:'X9.62 curve over a 431 bit binary field'),
    (*
     * the WAP/WTLS curves [unlike SECG; spec has its own OIDs for curves
     * from X9.62]
     *)
    (nid: NID_wap_wsg_idm_ecid_wtls1; data:@_EC_WTLS_1.h; meth:nil;
     comment:'WTLS curve over a 113 bit binary field'),
    (nid: NID_wap_wsg_idm_ecid_wtls3; data:@_EC_NIST_CHAR2_163K.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 163 bit binary field'),
    (nid: NID_wap_wsg_idm_ecid_wtls4; data:@_EC_SECG_CHAR2_113R1.h; meth:nil;
     comment:'SECG curve over a 113 bit binary field'),
    (nid: NID_wap_wsg_idm_ecid_wtls5; data:@_EC_X9_62_CHAR2_163V1.h; meth:nil;
     comment:'X9.62 curve over a 163 bit binary field'),
{$endif}
    (nid: NID_wap_wsg_idm_ecid_wtls6; data:@_EC_SECG_PRIME_112R1.h; meth:nil;
     comment:'SECG/WTLS curve over a 112 bit prime field'),
    (nid: NID_wap_wsg_idm_ecid_wtls7; data:@_EC_SECG_PRIME_160R2.h; meth:nil;
     comment:'SECG/WTLS curve over a 160 bit prime field'),
    (nid: NID_wap_wsg_idm_ecid_wtls8; data:@_EC_WTLS_8.h; meth:nil;
     comment:'WTLS curve over a 112 bit prime field'),
    (nid: NID_wap_wsg_idm_ecid_wtls9; data:@_EC_WTLS_9.h; meth:nil;
     comment:'WTLS curve over a 160 bit prime field'),
{$ifndef OPENSSL_NO_EC2M}
    (nid: NID_wap_wsg_idm_ecid_wtls1; data:@_EC_NIST_CHAR2_233K.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 233 bit binary field'),
    (nid: NID_wap_wsg_idm_ecid_wtls11; data:@_EC_NIST_CHAR2_233B.h; meth:nil;
     comment:'NIST/SECG/WTLS curve over a 233 bit binary field'),
{$endif}
    (nid: NID_wap_wsg_idm_ecid_wtls12; data:@_EC_WTLS_12.h; meth:nil;
     comment:'WTLS curve over a 224 bit prime field'),
{$ifndef OPENSSL_NO_EC2M}
    (* IPSec curves *)
    (nid: NID_ipsec3; data:@_EC_IPSEC_155_ID3.h; meth:nil;
     comment:#10#9'IPSec/IKE/Oakley curve #3 over a 155 bit binary field.'#10+
     #9'Not suitable for ECDSA.'#10#9'Questionable extension field!'),
    (nid: NID_ipsec4; data:@_EC_IPSEC_185_ID4.h; meth:nil;
     comment:#10#9'IPSec/IKE/Oakley curve #4 over a 185 bit binary field.'#10+
     #9'Not suitable for ECDSA.'#10#9'Questionable extension field!'),
{$endif}
    (* brainpool curves *)
    (nid: NID_brainpoolP160r1; data:@_EC_brainpoolP160r1.h; meth:nil;
     comment:'RFC 5639 curve over a 160 bit prime field'),
    (nid: NID_brainpoolP160t1; data:@_EC_brainpoolP160t1.h; meth:nil;
     comment:'RFC 5639 curve over a 160 bit prime field'),
    (nid: NID_brainpoolP192r1; data:@_EC_brainpoolP192r1.h; meth:nil;
     comment:'RFC 5639 curve over a 192 bit prime field'),
    (nid: NID_brainpoolP192t1; data:@_EC_brainpoolP192t1.h; meth:nil;
     comment:'RFC 5639 curve over a 192 bit prime field'),
    (nid: NID_brainpoolP224r1; data:@_EC_brainpoolP224r1.h; meth:nil;
     comment:'RFC 5639 curve over a 224 bit prime field'),
    (nid: NID_brainpoolP224t1; data:@_EC_brainpoolP224t1.h; meth:nil;
     comment:'RFC 5639 curve over a 224 bit prime field'),
    (nid: NID_brainpoolP256r1; data:@_EC_brainpoolP256r1.h; meth:nil;
     comment:'RFC 5639 curve over a 256 bit prime field'),
    (nid: NID_brainpoolP256t1; data:@_EC_brainpoolP256t1.h; meth:nil;
     comment:'RFC 5639 curve over a 256 bit prime field'),
    (nid: NID_brainpoolP320r1; data:@_EC_brainpoolP320r1.h; meth:nil;
     comment:'RFC 5639 curve over a 320 bit prime field'),
    (nid: NID_brainpoolP320t1; data:@_EC_brainpoolP320t1.h; meth:nil;
     comment:'RFC 5639 curve over a 320 bit prime field'),
    (nid: NID_brainpoolP384r1; data:@_EC_brainpoolP384r1.h; meth:nil;
     comment:'RFC 5639 curve over a 384 bit prime field'),
    (nid: NID_brainpoolP384t1; data:@_EC_brainpoolP384t1.h; meth:nil;
     comment:'RFC 5639 curve over a 384 bit prime field'),
    (nid: NID_brainpoolP512r1; data:@_EC_brainpoolP512r1.h; meth:nil;
     comment:'RFC 5639 curve over a 512 bit prime field'),
    (nid: NID_brainpoolP512t1; data:@_EC_brainpoolP512t1.h; meth:nil;
     comment:'RFC 5639 curve over a 512 bit prime field'),
{$ifndef OPENSSL_NO_SM2}
    (nid: NID_sm2; data:@_EC_sm2p256v1.h; meth:nil;
     comment:'SM2 curve over a 256 bit prime field')
{$endif}
);
NUM_BN_FIELDS = 6;
function ossl_ec_curve_nid_from_params(const group : PEC_GROUP; ctx : PBN_CTX):integer;
 function EC_curve_nist2nid(const name : PUTF8Char):integer;
function EC_GROUP_new_by_curve_name( nid : integer):PEC_GROUP;
function EC_curve_nid2nist( nid : integer):PUTF8Char;

implementation

uses
     openssl3.err, openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.ec.ec_cvt, openssl3.crypto.asn1.a_object,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.mem,

     openssl3.crypto.objects.obj_dat, openssl3.crypto.ec.ec_support;





function EC_curve_nid2nist( nid : integer):PUTF8Char;
begin
    Result := ossl_ec_curve_nid2nist_int(nid);
end;




function EC_GROUP_new_by_curve_name( nid : integer):PEC_GROUP;
begin
    Result := EC_GROUP_new_by_curve_name_ex(nil, nil, nid);
end;




function EC_curve_nist2nid(const name : PUTF8Char):integer;
begin
    Result := ossl_ec_curve_nist2nid_int(name);
end;

function ossl_ec_curve_nid_from_params(const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
  ret, nid, len, field_type, param_len         : integer;

  i,
  seed_len    : size_t;

  seed,
  params_seed,
  params,
  param_bytes : PByte;
  data        : PEC_CURVE_DATA;
  generator   : PEC_POINT;
  cofactor    : PBIGNUM;

  curve       : Tec_list_element;
  bn          : array[0..(NUM_BN_FIELDS)-1] of PBIGNUM;
  label _end;
begin
{$POINTERMATH ON}
    ret := -1;
    param_bytes := nil;
    generator := nil;
     cofactor := nil;
    { An array of BIGNUMs for (p, a, b, x, y, order) }
    bn[0] := nil;bn[1] := nil;bn[2] := nil;bn[3] := nil;
    bn[4] := nil;bn[5] := nil;

    { Use the optional named curve nid as a search field }
    nid := EC_GROUP_get_curve_name(group);
    field_type := EC_GROUP_get_field_type(group);
    seed_len := EC_GROUP_get_seed_len(group);
    seed := EC_GROUP_get0_seed(group);
    cofactor := EC_GROUP_get0_cofactor(group);
    BN_CTX_start(ctx);
    {
     * The built-in curves contains data fields (p, a, b, x, y, order) that are
     * all zero-padded to be the same size. The size of the padding is
     * determined by either the number of bytes in the field modulus (p) or the
     * EC group order, whichever is larger.
     }
    param_len := BN_num_bytes(group.order);
    len := BN_num_bytes(group.field);
    if len > param_len then param_len := len;
    { Allocate space to store the padded data for (p, a, b, x, y, order)  }
    param_bytes := OPENSSL_malloc(param_len * NUM_BN_FIELDS);
    if param_bytes = nil then goto _end ;
    { Create the bignums }
    for i := 0 to NUM_BN_FIELDS-1 do
    begin
        curve := curve_list[i];
        bn[i] := BN_CTX_get(ctx );
        if bn[i] = nil then
            goto _end ;
    end;
    {
     * Fill in the bn array with the same values as the internal curves
     * i.e. the values are p, a, b, x, y, order.
     }
    { Get p, a and b }
    generator := EC_GROUP_get0_generator(group);
    if not ( (EC_GROUP_get_curve(group, bn[0], bn[1], bn[2], ctx )>0)  and
             (generator <> nil)
        { Get x and y }
         and (EC_POINT_get_affine_coordinates(group, generator, bn[3], bn[4], ctx)>0)
        { Get order }
         and  (EC_GROUP_get_order(group, bn[5], ctx)>0) ) then
        goto _end ;
   {
     * Convert the bignum array to bytes that are joined together to form
     * a single buffer that contains data for all fields.
     * (p, a, b, x, y, order) are all zero padded to be the same size.
     }
    for i := 0 to NUM_BN_FIELDS-1 do
    begin
        if BN_bn2binpad(bn[i], @param_bytes[i*param_len], param_len) <= 0  then
            goto _end ;
    end;
    for i := 0 to curve_list_length-1 do
    begin
        data := curve.data;
        { Get the raw order byte data }
        params_seed := PByte(data + 1); { skip header }
        params := params_seed + data.seed_len;
        { Look for unique fields in the fixed curve data }
        if (data.field_type = field_type)
             and  (param_len = data.param_len )
             and  ( (nid <= 0)  or  (nid = curve.nid) ) { check the optional cofactor (ignore if its zero) }
             and  ( (BN_is_zero(cofactor)) or
                    ( BN_is_word(cofactor, BN_ULONG(curve.data.cofactor)))
                  )
            { Check the optional seed (ignore if its not set) }
             and  ( (data.seed_len = 0)  or  (seed_len = 0) or
                    ( (size_t(data.seed_len) = seed_len)
                      and  (memcmp(params_seed, seed, seed_len) = 0) ) )
            { Check that the groups params match the built-in curve params }
             and  (memcmp(param_bytes, params, param_len * NUM_BN_FIELDS)
                             = 0) then
        begin
            ret := curve.nid;
            goto _end ;
        end;
    end;
    { Gets here if the group was not found }
    ret := NID_undef;
_end:
    OPENSSL_free(param_bytes);
    BN_CTX_end(ctx);
    Result := ret;
{$POINTERMATH ON}
end;

function ec_group_new_from_data(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; curve : Tec_list_element):PEC_GROUP;
var
  group     : PEC_GROUP;
  PT        : PEC_POINT;
  ctx       : PBN_CTX;

  p,
  a,
  b,
  x,
  y,
  order     : PBIGNUM;
  ok,
  seed_len,
  param_len : integer;
  meth      : PEC_METHOD;
  data      : PEC_CURVE_DATA;
  params    : PByte;
  asn1obj   : PASN1_OBJECT;
  meth1      : PEC_METHOD;
  label _err;
begin
{$POINTERMATH ON}
    group := nil;
    P := nil;
    ctx := nil;
    p := nil;
    a := nil;
    b := nil;
    x := nil;
    y := nil;
    order := nil;
    ok := 0;
    { If no curve data curve method must handle everything }
    if curve.data = nil then
    begin
       if curve.meth <> nil then
          meth1 :=  curve.meth()
       else
          meth1 := nil;

       Exit(ossl_ec_group_new_ex(libctx, propq, meth1));
    end;
    ctx := BN_CTX_new_ex(libctx );
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    data := curve.data;
    seed_len := data.seed_len;
    param_len := data.param_len;
    params := PByte (data + 1); { skip header }
    params  := params + seed_len;
    p := BN_bin2bn(params + 0 * param_len, param_len, nil);
    a := BN_bin2bn(params + 1 * param_len, param_len, nil);
    b := BN_bin2bn(params + 2 * param_len, param_len, nil);
    if (p = nil)
         or  (a = nil)
         or  (b = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;

    if Assigned(curve.meth) then
    begin
        meth := curve.meth();
        group := ossl_ec_group_new_ex(libctx, propq, meth);
        if (group = nil )   or
            ( 0>= group.meth.group_set_curve(group, p, a, b, ctx))  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end
    else
    if (data.field_type = NID_X9_62_prime_field)  then
    begin
        group := EC_GROUP_new_curve_GFp(p, a, b, ctx );
        if group = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end
{$IFNDEF OPENSSL_NO_EC2M}
    else begin                       { field_type =
                                 * NID_X9_62_characteristic_two_field }
        group := EC_GROUP_new_curve_GF2m(p, a, b, ctx);
        if group = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end;
{$ENDIF}
    EC_GROUP_set_curve_name(group, curve.nid);
    PT := EC_POINT_new(group);
    if Pt = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    x := BN_bin2bn(params + 3 * param_len, param_len, nil );
    y := BN_bin2bn(params + 4 * param_len, param_len, nil);
    if (x = nil) or  (y = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    if 0>= EC_POINT_set_affine_coordinates(group, PT, x, y, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    order := BN_bin2bn(params + 5 * param_len, param_len, nil);
    if (order  = nil)
         or (0>= BN_set_word(x, BN_ULONG(data.cofactor))) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    if  0>= EC_GROUP_set_generator(group, PT, order, x)  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if seed_len>0 then
    begin
        if  0>= EC_GROUP_set_seed(group, params - seed_len, seed_len) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end;
{$IFNDEF FIPS_MODULE}
    if EC_GROUP_get_asn1_flag(group)= OPENSSL_EC_NAMED_CURVE  then
    begin
        {
         * Some curves don't have an associated OID: for those we should not
         * default to `OPENSSL_EC_NAMED_CURVE` encoding of parameters and
         * instead set the ASN1 flag to `OPENSSL_EC_EXPLICIT_CURVE`.
         *
         * Note that `OPENSSL_EC_NAMED_CURVE` is set as the default ASN1 flag on
         * `EC_GROUP_new()`, when we don't have enough elements to determine if
         * an OID for the curve name actually exists.
         * We could implement this check on `EC_GROUP_set_curve_name()` but
         * overloading the simple setter with this lookup could have a negative
         * performance impact and unexpected consequences.
         }
        asn1obj := OBJ_nid2obj(curve.nid);
        if asn1obj = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_OBJ_LIB);
            goto _err ;
        end;
        if OBJ_length(asn1obj) = 0  then
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
        ASN1_OBJECT_free(asn1obj);
    end;
{$ELSE}
     {* Inside the FIPS module we do not support explicit curves anyway
     * so the above check is not necessary.
     *
     * Skipping it is also necessary because `OBJ_length()` and
     * `ASN1_OBJECT_free()` are not available within the FIPS module
     * boundaries.
     }
{$ENDIF}
    ok := 1;
 _err:
    if  0>= ok then
    begin
        EC_GROUP_free(group);
        group := nil;
    end;
    EC_POINT_free(PT);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    Result := group;
 {$POINTERMATH OFF}
end;


function ec_curve_nid2curve( nid : integer):Pec_list_element;
var
  i : size_t;
begin
    if nid <= 0 then Exit(nil);
    for i := 0 to curve_list_length-1 do
    begin
        if curve_list[i].nid = nid then
           Exit(@curve_list[i]);
    end;
    Result := nil;
end;

function EC_GROUP_new_by_curve_name_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; nid : integer):PEC_GROUP;
var
  ret : PEC_GROUP;
  curve : Pec_list_element;
begin
    ret := nil;
    curve := ec_curve_nid2curve(nid );
    ret := ec_group_new_from_data(libctx, propq, curve^);
    if (curve =  nil)
         or  (ret = nil) then
    begin
{$IFNDEF FIPS_MODULE}
      ERR_raise_data(ERR_LIB_EC, EC_R_UNKNOWN_GROUP,
                      Format('name=%s', [OBJ_nid2sn(nid)]));
{$ELSE}
      ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_GROUP);
{$ENDIF}
        Exit(nil);
    end;
    Result := ret;
end;


initialization

   curve_list_length := Length(curve_list);
end.
