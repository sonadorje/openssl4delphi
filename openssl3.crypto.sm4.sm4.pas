unit openssl3.crypto.sm4.sm4;

interface
 uses OpenSSL.Api;

type
  Tfn = function( X : uint32):uint32;
  function ossl_sm4_set_key(const key : PByte; ks : PSM4_KEY):integer;

const // 1d arrays
  SM4_KEY_SCHEDULE  = 32;
  FK : array[0..3] of uint32 = (
    $a3b1bac6, $56aa3350, $677d9197, $b27022dc );

  CK : array[0..31] of uint32 = (
    $00070E15, $1C232A31, $383F464D, $545B6269, $70777E85, $8C939AA1,
    $A8AFB6BD, $C4CBD2D9, $E0E7EEF5, $FC030A11, $181F262D, $343B4249,
    $50575E65, $6C737A81, $888F969D, $A4ABB2B9, $C0C7CED5, $DCE3EAF1,
    $F8FF060D, $141B2229, $30373E45, $4C535A61, $686F767D, $848B9299,
    $A0A7AEB5, $BCC3CAD1, $D8DFE6ED, $F4FB0209, $10171E25, $2C333A41,
    $484F565D, $646B7279 );

 SM4_S : array[0..255] of byte = (
    $D6, $90, $E9, $FE, $CC, $E1, $3D, $B7, $16, $B6, $14, $C2, $28, $FB,
    $2C, $05, $2B, $67, $9A, $76, $2A, $BE, $04, $C3, $AA, $44, $13, $26,
    $49, $86, $06, $99, $9C, $42, $50, $F4, $91, $EF, $98, $7A, $33, $54,
    $0B, $43, $ED, $CF, $AC, $62, $E4, $B3, $1C, $A9, $C9, $08, $E8, $95,
    $80, $DF, $94, $FA, $75, $8F, $3F, $A6, $47, $07, $A7, $FC, $F3, $73,
    $17, $BA, $83, $59, $3C, $19, $E6, $85, $4F, $A8, $68, $6B, $81, $B2,
    $71, $64, $DA, $8B, $F8, $EB, $0F, $4B, $70, $56, $9D, $35, $1E, $24,
    $0E, $5E, $63, $58, $D1, $A2, $25, $22, $7C, $3B, $01, $21, $78, $87,
    $D4, $00, $46, $57, $9F, $D3, $27, $52, $4C, $36, $02, $E7, $A0, $C4,
    $C8, $9E, $EA, $BF, $8A, $D2, $40, $C7, $38, $B5, $A3, $F7, $F2, $CE,
    $F9, $61, $15, $A1, $E0, $AE, $5D, $A4, $9B, $34, $1A, $55, $AD, $93,
    $32, $30, $F5, $8C, $B1, $E3, $1D, $F6, $E2, $2E, $82, $66, $CA, $60,
    $C0, $29, $23, $AB, $0D, $53, $4E, $6F, $D5, $DB, $37, $45, $DE, $FD,
    $8E, $2F, $03, $FF, $6A, $72, $6D, $6C, $5B, $51, $8D, $1B, $AF, $92,
    $BB, $DD, $BC, $7F, $11, $D9, $5C, $41, $1F, $10, $5A, $D8, $0A, $C1,
    $31, $88, $A5, $CD, $7B, $BD, $2D, $74, $D0, $12, $B8, $E5, $B4, $B0,
    $89, $69, $97, $4A, $0C, $96, $77, $7E, $65, $B9, $F1, $09, $C5, $6E,
    $C6, $84, $18, $F0, $7D, $EC, $3A, $DC, $4D, $20, $79, $EE, $5F, $3E,
    $D7, $CB, $39, $48 );

     SM4_SBOX_T : array[0..255] of uint32 = (
    $8ED55B5B, $D0924242, $4DEAA7A7, $06FDFBFB, $FCCF3333, $65E28787,
    $C93DF4F4, $6BB5DEDE, $4E165858, $6EB4DADA, $44145050, $CAC10B0B,
    $8828A0A0, $17F8EFEF, $9C2CB0B0, $11051414, $872BACAC, $FB669D9D,
    $F2986A6A, $AE77D9D9, $822AA8A8, $46BCFAFA, $14041010, $CFC00F0F,
    $02A8AAAA, $54451111, $5F134C4C, $BE269898, $6D482525, $9E841A1A,
    $1E061818, $FD9B6666, $EC9E7272, $4A430909, $10514141, $24F7D3D3,
    $D5934646, $53ECBFBF, $F89A6262, $927BE9E9, $FF33CCCC, $04555151,
    $270B2C2C, $4F420D0D, $59EEB7B7, $F3CC3F3F, $1CAEB2B2, $EA638989,
    $74E79393, $7FB1CECE, $6C1C7070, $0DABA6A6, $EDCA2727, $28082020,
    $48EBA3A3, $C1975656, $80820202, $A3DC7F7F, $C4965252, $12F9EBEB,
    $A174D5D5, $B38D3E3E, $C33FFCFC, $3EA49A9A, $5B461D1D, $1B071C1C,
    $3BA59E9E, $0CFFF3F3, $3FF0CFCF, $BF72CDCD, $4B175C5C, $52B8EAEA,
    $8F810E0E, $3D586565, $CC3CF0F0, $7D196464, $7EE59B9B, $91871616,
    $734E3D3D, $08AAA2A2, $C869A1A1, $C76AADAD, $85830606, $7AB0CACA,
    $B570C5C5, $F4659191, $B2D96B6B, $A7892E2E, $18FBE3E3, $47E8AFAF,
    $330F3C3C, $674A2D2D, $B071C1C1, $0E575959, $E99F7676, $E135D4D4,
    $661E7878, $B4249090, $360E3838, $265F7979, $EF628D8D, $38596161,
    $95D24747, $2AA08A8A, $B1259494, $AA228888, $8C7DF1F1, $D73BECEC,
    $05010404, $A5218484, $9879E1E1, $9B851E1E, $84D75353, $00000000,
    $5E471919, $0B565D5D, $E39D7E7E, $9FD04F4F, $BB279C9C, $1A534949,
    $7C4D3131, $EE36D8D8, $0A020808, $7BE49F9F, $20A28282, $D4C71313,
    $E8CB2323, $E69C7A7A, $42E9ABAB, $43BDFEFE, $A2882A2A, $9AD14B4B,
    $40410101, $DBC41F1F, $D838E0E0, $61B7D6D6, $2FA18E8E, $2BF4DFDF,
    $3AF1CBCB, $F6CD3B3B, $1DFAE7E7, $E5608585, $41155454, $25A38686,
    $60E38383, $16ACBABA, $295C7575, $34A69292, $F7996E6E, $E434D0D0,
    $721A6868, $01545555, $19AFB6B6, $DF914E4E, $FA32C8C8, $F030C0C0,
    $21F6D7D7, $BC8E3232, $75B3C6C6, $6FE08F8F, $691D7474, $2EF5DBDB,
    $6AE18B8B, $962EB8B8, $8A800A0A, $FE679999, $E2C92B2B, $E0618181,
    $C0C30303, $8D29A4A4, $AF238C8C, $07A9AEAE, $390D3434, $1F524D4D,
    $764F3939, $D36EBDBD, $81D65757, $B7D86F6F, $EB37DCDC, $51441515,
    $A6DD7B7B, $09FEF7F7, $B68C3A3A, $932FBCBC, $0F030C0C, $03FCFFFF,
    $C26BA9A9, $BA73C9C9, $D96CB5B5, $DC6DB1B1, $375A6D6D, $15504545,
    $B98F3636, $771B6C6C, $13ADBEBE, $DA904A4A, $57B9EEEE, $A9DE7777,
    $4CBEF2F2, $837EFDFD, $55114444, $BDDA6767, $2C5D7171, $45400505,
    $631F7C7C, $50104040, $325B6969, $B8DB6363, $220A2828, $C5C20707,
    $F531C4C4, $A88A2222, $31A79696, $F9CE3737, $977AEDED, $49BFF6F6,
    $992DB4B4, $A475D1D1, $90D34343, $5A124848, $58BAE2E2, $71E69797,
    $64B6D2D2, $70B2C2C2, $AD8B2626, $CD68A5A5, $CB955E5E, $624B2929,
    $3C0C3030, $CE945A5A, $AB76DDDD, $867FF9F9, $F1649595, $5DBBE6E6,
    $35F2C7C7, $2D092424, $D1C61717, $D66FB9B9, $DEC51B1B, $94861212,
    $78186060, $30F3C3C3, $897CF5F5, $5CEFB3B3, $D23AE8E8, $ACDF7373,
    $794C3535, $A0208080, $9D78E5E5, $56EDBBBB, $235E7D7D, $C63EF8F8,
    $8BD45F5F, $E7C82F2F, $DD39E4E4, $68492121 );

 function load_uint32_be(const b : PByte; n : uint32):uint32;
 function rotl( a : uint32; n : byte):uint32;
 procedure ossl_sm4_encrypt(const _in : PByte; _out : PByte;const ks : PSM4_KEY);
 function SM4_T_slow( X : uint32):uint32;
 function SM4_T( X : uint32):uint32;
 procedure store_uint32_be( v : uint32; b : PByte);

procedure ossl_sm4_decrypt(const _in : PByte; _out : PByte;const ks : PSM4_KEY);

implementation


procedure ossl_sm4_decrypt(const _in : PByte; _out : PByte;const ks : PSM4_KEY);
var
  B0, B1, B2, B3 : uint32;
  procedure SM4_RNDS(k0, k1, k2, k3: Int; F: Tfn);
  begin
     B0  := B0 xor (F(B1 xor B2 xor B3 xor ks.rk[k0]));
     B1  := B1 xor (F(B0 xor B2 xor B3 xor ks.rk[k1]));
     B2  := B2 xor (F(B0 xor B1 xor B3 xor ks.rk[k2]));
     B3  := B3 xor (F(B0 xor B1 xor B2 xor ks.rk[k3]));
  end;
begin
    B0 := load_uint32_be(_in, 0);
    B1 := load_uint32_be(_in, 1);
    B2 := load_uint32_be(_in, 2);
    B3 := load_uint32_be(_in, 3);
    SM4_RNDS(31, 30, 29, 28, SM4_T_slow);
    SM4_RNDS(27, 26, 25, 24, SM4_T);
    SM4_RNDS(23, 22, 21, 20, SM4_T);
    SM4_RNDS(19, 18, 17, 16, SM4_T);
    SM4_RNDS(15, 14, 13, 12, SM4_T);
    SM4_RNDS(11, 10,  9,  8, SM4_T);
    SM4_RNDS( 7,  6,  5,  4, SM4_T);
    SM4_RNDS( 3,  2,  1,  0, SM4_T_slow);
    store_uint32_be(B3, _out);
    store_uint32_be(B2, _out + 4);
    store_uint32_be(B1, _out + 8);
    store_uint32_be(B0, _out + 12);
end;



procedure store_uint32_be( v : uint32; b : PByte);
begin
    b[0] := uint8(v  shr  24);
    b[1] := uint8(v  shr  16);
    b[2] := uint8(v  shr  8);
    b[3] := uint8(v);
end;



function SM4_T_slow( X : uint32):uint32;
var
  t : uint32;
begin
    t := 0;
    t  := t  or ((uint32_t(SM4_S[uint8(X  shr  24)]))  shl  24);
    t  := t  or ((uint32_t(SM4_S[uint8(X  shr  16)]))  shl  16);
    t  := t  or ((uint32_t(SM4_S[uint8(X  shr  8)]))  shl  8);
    t  := t  or (SM4_S[uint8(X)]);
    {
     * L linear transform
     }
    Result := t  xor  rotl(t, 2)  xor  rotl(t, 10)  xor  rotl(t, 18)  xor  rotl(t, 24);
end;


function SM4_T( X : uint32):uint32;
begin
    Exit(SM4_SBOX_T[uint8(X  shr  24)]  xor
           rotl(SM4_SBOX_T[uint8(X  shr  16)], 24)  xor
           rotl(SM4_SBOX_T[uint8(X  shr  8)], 16)  xor
           rotl(SM4_SBOX_T[uint8(X)], 8));
end;




procedure ossl_sm4_encrypt(const _in : PByte; _out : PByte;const ks : PSM4_KEY);
var
  B0, B1, B2, B3 : uint32;
  procedure SM4_RNDS(k0, k1, k2, k3: Int; F: Tfn);
  begin
     B0  := B0 xor (F(B1 xor B2 xor B3 xor ks.rk[k0]));
     B1  := B1 xor (F(B0 xor B2 xor B3 xor ks.rk[k1]));
     B2  := B2 xor (F(B0 xor B1 xor B3 xor ks.rk[k2]));
     B3  := B3 xor (F(B0 xor B1 xor B2 xor ks.rk[k3]));
  end;
begin
    B0 := load_uint32_be(_in, 0);
    B1 := load_uint32_be(_in, 1);
    B2 := load_uint32_be(_in, 2);
    B3 := load_uint32_be(_in, 3);
    {
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     }
    SM4_RNDS( 0,  1,  2,  3, SM4_T_slow);
    SM4_RNDS( 4,  5,  6,  7, SM4_T);
    SM4_RNDS( 8,  9, 10, 11, SM4_T);
    SM4_RNDS(12, 13, 14, 15, SM4_T);
    SM4_RNDS(16, 17, 18, 19, SM4_T);
    SM4_RNDS(20, 21, 22, 23, SM4_T);
    SM4_RNDS(24, 25, 26, 27, SM4_T);
    SM4_RNDS(28, 29, 30, 31, SM4_T_slow);
    store_uint32_be(B3, _out);
    store_uint32_be(B2, _out + 4);
    store_uint32_be(B1, _out + 8);
    store_uint32_be(B0, _out + 12);
end;


function rotl( a : uint32; n : byte):uint32;
begin
    Result := (a  shl  n) or (a  shr  (32 - n));
end;



function load_uint32_be(const b : PByte; n : uint32):uint32;
begin
    Result := (uint32(b[4 * n]) shl 24) or
           (uint32(b[4 * n + 1]) shl 16) or
           (uint32(b[4 * n + 2]) shl 8) or
           (uint32(b[4 * n + 3]));
end;


function ossl_sm4_set_key(const key : PByte; ks : PSM4_KEY):integer;
var
  K : array[0..3] of uint32;
  i : integer;
  X, t : uint32;
begin

    K[0] := load_uint32_be(key, 0)  xor  FK[0];
    K[1] := load_uint32_be(key, 1)  xor  FK[1];
    K[2] := load_uint32_be(key, 2)  xor  FK[2];
    K[3] := load_uint32_be(key, 3)  xor  FK[3];
    i := 0;
    while i <> SM4_KEY_SCHEDULE do
    begin
        X := K[(i + 1) mod 4]  xor  K[(i + 2) mod 4]  xor  K[(i + 3) mod 4]  xor  CK[i];
        t := 0;
        t  := t  or (uint32(SM4_S[ uint8(X  shr  24)]) shl 24);
        t  := t  or (uint32(SM4_S[ uint8(X  shr  16)]) shl 16);
        t  := t  or (uint32(SM4_S[ uint8(X  shr  8)]) shl 8);
        t  := t  or (SM4_S[ uint8(X)]);
        t := t  xor  rotl(t, 13)  xor  rotl(t, 23);
        K[i mod 4]  := K[i mod 4] xor t;
        ks.rk[i] := K[i mod 4];
        Inc(i);
    end;
    Result := 1;
end;


end.
