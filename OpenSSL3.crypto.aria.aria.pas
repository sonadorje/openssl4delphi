unit OpenSSL3.crypto.aria.aria;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
    ARIA_BLOCK_SIZE  =  16;

    Key_RC: array[0..4, 0..3] of uint32 = (
    ( $517cc1b7, $27220a94, $fe13abe8, $fa9a6ee0 ),
    ( $6db14acc, $9e21c820, $ff28b1d5, $ef5de2b0 ),
    ( $db92371d, $2126e970, $03249775, $04e8c90e ),
    ( $517cc1b7, $27220a94, $fe13abe8, $fa9a6ee0 ),
    ( $6db14acc, $9e21c820, $ff28b1d5, $ef5de2b0 )
);
   S1: array[0..255] of uint32 = (
    $00636363, $007c7c7c, $00777777, $007b7b7b,
    $00f2f2f2, $006b6b6b, $006f6f6f, $00c5c5c5,
    $00303030, $00010101, $00676767, $002b2b2b,
    $00fefefe, $00d7d7d7, $00ababab, $00767676,
    $00cacaca, $00828282, $00c9c9c9, $007d7d7d,
    $00fafafa, $00595959, $00474747, $00f0f0f0,
    $00adadad, $00d4d4d4, $00a2a2a2, $00afafaf,
    $009c9c9c, $00a4a4a4, $00727272, $00c0c0c0,
    $00b7b7b7, $00fdfdfd, $00939393, $00262626,
    $00363636, $003f3f3f, $00f7f7f7, $00cccccc,
    $00343434, $00a5a5a5, $00e5e5e5, $00f1f1f1,
    $00717171, $00d8d8d8, $00313131, $00151515,
    $00040404, $00c7c7c7, $00232323, $00c3c3c3,
    $00181818, $00969696, $00050505, $009a9a9a,
    $00070707, $00121212, $00808080, $00e2e2e2,
    $00ebebeb, $00272727, $00b2b2b2, $00757575,
    $00090909, $00838383, $002c2c2c, $001a1a1a,
    $001b1b1b, $006e6e6e, $005a5a5a, $00a0a0a0,
    $00525252, $003b3b3b, $00d6d6d6, $00b3b3b3,
    $00292929, $00e3e3e3, $002f2f2f, $00848484,
    $00535353, $00d1d1d1, $00000000, $00ededed,
    $00202020, $00fcfcfc, $00b1b1b1, $005b5b5b,
    $006a6a6a, $00cbcbcb, $00bebebe, $00393939,
    $004a4a4a, $004c4c4c, $00585858, $00cfcfcf,
    $00d0d0d0, $00efefef, $00aaaaaa, $00fbfbfb,
    $00434343, $004d4d4d, $00333333, $00858585,
    $00454545, $00f9f9f9, $00020202, $007f7f7f,
    $00505050, $003c3c3c, $009f9f9f, $00a8a8a8,
    $00515151, $00a3a3a3, $00404040, $008f8f8f,
    $00929292, $009d9d9d, $00383838, $00f5f5f5,
    $00bcbcbc, $00b6b6b6, $00dadada, $00212121,
    $00101010, $00ffffff, $00f3f3f3, $00d2d2d2,
    $00cdcdcd, $000c0c0c, $00131313, $00ececec,
    $005f5f5f, $00979797, $00444444, $00171717,
    $00c4c4c4, $00a7a7a7, $007e7e7e, $003d3d3d,
    $00646464, $005d5d5d, $00191919, $00737373,
    $00606060, $00818181, $004f4f4f, $00dcdcdc,
    $00222222, $002a2a2a, $00909090, $00888888,
    $00464646, $00eeeeee, $00b8b8b8, $00141414,
    $00dedede, $005e5e5e, $000b0b0b, $00dbdbdb,
    $00e0e0e0, $00323232, $003a3a3a, $000a0a0a,
    $00494949, $00060606, $00242424, $005c5c5c,
    $00c2c2c2, $00d3d3d3, $00acacac, $00626262,
    $00919191, $00959595, $00e4e4e4, $00797979,
    $00e7e7e7, $00c8c8c8, $00373737, $006d6d6d,
    $008d8d8d, $00d5d5d5, $004e4e4e, $00a9a9a9,
    $006c6c6c, $00565656, $00f4f4f4, $00eaeaea,
    $00656565, $007a7a7a, $00aeaeae, $00080808,
    $00bababa, $00787878, $00252525, $002e2e2e,
    $001c1c1c, $00a6a6a6, $00b4b4b4, $00c6c6c6,
    $00e8e8e8, $00dddddd, $00747474, $001f1f1f,
    $004b4b4b, $00bdbdbd, $008b8b8b, $008a8a8a,
    $00707070, $003e3e3e, $00b5b5b5, $00666666,
    $00484848, $00030303, $00f6f6f6, $000e0e0e,
    $00616161, $00353535, $00575757, $00b9b9b9,
    $00868686, $00c1c1c1, $001d1d1d, $009e9e9e,
    $00e1e1e1, $00f8f8f8, $00989898, $00111111,
    $00696969, $00d9d9d9, $008e8e8e, $00949494,
    $009b9b9b, $001e1e1e, $00878787, $00e9e9e9,
    $00cecece, $00555555, $00282828, $00dfdfdf,
    $008c8c8c, $00a1a1a1, $00898989, $000d0d0d,
    $00bfbfbf, $00e6e6e6, $00424242, $00686868,
    $00414141, $00999999, $002d2d2d, $000f0f0f,
    $00b0b0b0, $00545454, $00bbbbbb, $00161616
);

  S2: array[0..255] of uint32 = (
    $e200e2e2, $4e004e4e, $54005454, $fc00fcfc,
    $94009494, $c200c2c2, $4a004a4a, $cc00cccc,
    $62006262, $0d000d0d, $6a006a6a, $46004646,
    $3c003c3c, $4d004d4d, $8b008b8b, $d100d1d1,
    $5e005e5e, $fa00fafa, $64006464, $cb00cbcb,
    $b400b4b4, $97009797, $be00bebe, $2b002b2b,
    $bc00bcbc, $77007777, $2e002e2e, $03000303,
    $d300d3d3, $19001919, $59005959, $c100c1c1,
    $1d001d1d, $06000606, $41004141, $6b006b6b,
    $55005555, $f000f0f0, $99009999, $69006969,
    $ea00eaea, $9c009c9c, $18001818, $ae00aeae,
    $63006363, $df00dfdf, $e700e7e7, $bb00bbbb,
    $00000000, $73007373, $66006666, $fb00fbfb,
    $96009696, $4c004c4c, $85008585, $e400e4e4,
    $3a003a3a, $09000909, $45004545, $aa00aaaa,
    $0f000f0f, $ee00eeee, $10001010, $eb00ebeb,
    $2d002d2d, $7f007f7f, $f400f4f4, $29002929,
    $ac00acac, $cf00cfcf, $ad00adad, $91009191,
    $8d008d8d, $78007878, $c800c8c8, $95009595,
    $f900f9f9, $2f002f2f, $ce00cece, $cd00cdcd,
    $08000808, $7a007a7a, $88008888, $38003838,
    $5c005c5c, $83008383, $2a002a2a, $28002828,
    $47004747, $db00dbdb, $b800b8b8, $c700c7c7,
    $93009393, $a400a4a4, $12001212, $53005353,
    $ff00ffff, $87008787, $0e000e0e, $31003131,
    $36003636, $21002121, $58005858, $48004848,
    $01000101, $8e008e8e, $37003737, $74007474,
    $32003232, $ca00caca, $e900e9e9, $b100b1b1,
    $b700b7b7, $ab00abab, $0c000c0c, $d700d7d7,
    $c400c4c4, $56005656, $42004242, $26002626,
    $07000707, $98009898, $60006060, $d900d9d9,
    $b600b6b6, $b900b9b9, $11001111, $40004040,
    $ec00ecec, $20002020, $8c008c8c, $bd00bdbd,
    $a000a0a0, $c900c9c9, $84008484, $04000404,
    $49004949, $23002323, $f100f1f1, $4f004f4f,
    $50005050, $1f001f1f, $13001313, $dc00dcdc,
    $d800d8d8, $c000c0c0, $9e009e9e, $57005757,
    $e300e3e3, $c300c3c3, $7b007b7b, $65006565,
    $3b003b3b, $02000202, $8f008f8f, $3e003e3e,
    $e800e8e8, $25002525, $92009292, $e500e5e5,
    $15001515, $dd00dddd, $fd00fdfd, $17001717,
    $a900a9a9, $bf00bfbf, $d400d4d4, $9a009a9a,
    $7e007e7e, $c500c5c5, $39003939, $67006767,
    $fe00fefe, $76007676, $9d009d9d, $43004343,
    $a700a7a7, $e100e1e1, $d000d0d0, $f500f5f5,
    $68006868, $f200f2f2, $1b001b1b, $34003434,
    $70007070, $05000505, $a300a3a3, $8a008a8a,
    $d500d5d5, $79007979, $86008686, $a800a8a8,
    $30003030, $c600c6c6, $51005151, $4b004b4b,
    $1e001e1e, $a600a6a6, $27002727, $f600f6f6,
    $35003535, $d200d2d2, $6e006e6e, $24002424,
    $16001616, $82008282, $5f005f5f, $da00dada,
    $e600e6e6, $75007575, $a200a2a2, $ef00efef,
    $2c002c2c, $b200b2b2, $1c001c1c, $9f009f9f,
    $5d005d5d, $6f006f6f, $80008080, $0a000a0a,
    $72007272, $44004444, $9b009b9b, $6c006c6c,
    $90009090, $0b000b0b, $5b005b5b, $33003333,
    $7d007d7d, $5a005a5a, $52005252, $f300f3f3,
    $61006161, $a100a1a1, $f700f7f7, $b000b0b0,
    $d600d6d6, $3f003f3f, $7c007c7c, $6d006d6d,
    $ed00eded, $14001414, $e000e0e0, $a500a5a5,
    $3d003d3d, $22002222, $b300b3b3, $f800f8f8,
    $89008989, $de00dede, $71007171, $1a001a1a,
    $af00afaf, $ba00baba, $b500b5b5, $81008181
);

  X1: array[0..255] of uint32 = (
    $52520052, $09090009, $6a6a006a, $d5d500d5,
    $30300030, $36360036, $a5a500a5, $38380038,
    $bfbf00bf, $40400040, $a3a300a3, $9e9e009e,
    $81810081, $f3f300f3, $d7d700d7, $fbfb00fb,
    $7c7c007c, $e3e300e3, $39390039, $82820082,
    $9b9b009b, $2f2f002f, $ffff00ff, $87870087,
    $34340034, $8e8e008e, $43430043, $44440044,
    $c4c400c4, $dede00de, $e9e900e9, $cbcb00cb,
    $54540054, $7b7b007b, $94940094, $32320032,
    $a6a600a6, $c2c200c2, $23230023, $3d3d003d,
    $eeee00ee, $4c4c004c, $95950095, $0b0b000b,
    $42420042, $fafa00fa, $c3c300c3, $4e4e004e,
    $08080008, $2e2e002e, $a1a100a1, $66660066,
    $28280028, $d9d900d9, $24240024, $b2b200b2,
    $76760076, $5b5b005b, $a2a200a2, $49490049,
    $6d6d006d, $8b8b008b, $d1d100d1, $25250025,
    $72720072, $f8f800f8, $f6f600f6, $64640064,
    $86860086, $68680068, $98980098, $16160016,
    $d4d400d4, $a4a400a4, $5c5c005c, $cccc00cc,
    $5d5d005d, $65650065, $b6b600b6, $92920092,
    $6c6c006c, $70700070, $48480048, $50500050,
    $fdfd00fd, $eded00ed, $b9b900b9, $dada00da,
    $5e5e005e, $15150015, $46460046, $57570057,
    $a7a700a7, $8d8d008d, $9d9d009d, $84840084,
    $90900090, $d8d800d8, $abab00ab, $00000000,
    $8c8c008c, $bcbc00bc, $d3d300d3, $0a0a000a,
    $f7f700f7, $e4e400e4, $58580058, $05050005,
    $b8b800b8, $b3b300b3, $45450045, $06060006,
    $d0d000d0, $2c2c002c, $1e1e001e, $8f8f008f,
    $caca00ca, $3f3f003f, $0f0f000f, $02020002,
    $c1c100c1, $afaf00af, $bdbd00bd, $03030003,
    $01010001, $13130013, $8a8a008a, $6b6b006b,
    $3a3a003a, $91910091, $11110011, $41410041,
    $4f4f004f, $67670067, $dcdc00dc, $eaea00ea,
    $97970097, $f2f200f2, $cfcf00cf, $cece00ce,
    $f0f000f0, $b4b400b4, $e6e600e6, $73730073,
    $96960096, $acac00ac, $74740074, $22220022,
    $e7e700e7, $adad00ad, $35350035, $85850085,
    $e2e200e2, $f9f900f9, $37370037, $e8e800e8,
    $1c1c001c, $75750075, $dfdf00df, $6e6e006e,
    $47470047, $f1f100f1, $1a1a001a, $71710071,
    $1d1d001d, $29290029, $c5c500c5, $89890089,
    $6f6f006f, $b7b700b7, $62620062, $0e0e000e,
    $aaaa00aa, $18180018, $bebe00be, $1b1b001b,
    $fcfc00fc, $56560056, $3e3e003e, $4b4b004b,
    $c6c600c6, $d2d200d2, $79790079, $20200020,
    $9a9a009a, $dbdb00db, $c0c000c0, $fefe00fe,
    $78780078, $cdcd00cd, $5a5a005a, $f4f400f4,
    $1f1f001f, $dddd00dd, $a8a800a8, $33330033,
    $88880088, $07070007, $c7c700c7, $31310031,
    $b1b100b1, $12120012, $10100010, $59590059,
    $27270027, $80800080, $ecec00ec, $5f5f005f,
    $60600060, $51510051, $7f7f007f, $a9a900a9,
    $19190019, $b5b500b5, $4a4a004a, $0d0d000d,
    $2d2d002d, $e5e500e5, $7a7a007a, $9f9f009f,
    $93930093, $c9c900c9, $9c9c009c, $efef00ef,
    $a0a000a0, $e0e000e0, $3b3b003b, $4d4d004d,
    $aeae00ae, $2a2a002a, $f5f500f5, $b0b000b0,
    $c8c800c8, $ebeb00eb, $bbbb00bb, $3c3c003c,
    $83830083, $53530053, $99990099, $61610061,
    $17170017, $2b2b002b, $04040004, $7e7e007e,
    $baba00ba, $77770077, $d6d600d6, $26260026,
    $e1e100e1, $69690069, $14140014, $63630063,
    $55550055, $21210021, $0c0c000c, $7d7d007d
);

  X2: array[0..255] of uint32 = (
    $30303000, $68686800, $99999900, $1b1b1b00,
    $87878700, $b9b9b900, $21212100, $78787800,
    $50505000, $39393900, $dbdbdb00, $e1e1e100,
    $72727200, $09090900, $62626200, $3c3c3c00,
    $3e3e3e00, $7e7e7e00, $5e5e5e00, $8e8e8e00,
    $f1f1f100, $a0a0a000, $cccccc00, $a3a3a300,
    $2a2a2a00, $1d1d1d00, $fbfbfb00, $b6b6b600,
    $d6d6d600, $20202000, $c4c4c400, $8d8d8d00,
    $81818100, $65656500, $f5f5f500, $89898900,
    $cbcbcb00, $9d9d9d00, $77777700, $c6c6c600,
    $57575700, $43434300, $56565600, $17171700,
    $d4d4d400, $40404000, $1a1a1a00, $4d4d4d00,
    $c0c0c000, $63636300, $6c6c6c00, $e3e3e300,
    $b7b7b700, $c8c8c800, $64646400, $6a6a6a00,
    $53535300, $aaaaaa00, $38383800, $98989800,
    $0c0c0c00, $f4f4f400, $9b9b9b00, $ededed00,
    $7f7f7f00, $22222200, $76767600, $afafaf00,
    $dddddd00, $3a3a3a00, $0b0b0b00, $58585800,
    $67676700, $88888800, $06060600, $c3c3c300,
    $35353500, $0d0d0d00, $01010100, $8b8b8b00,
    $8c8c8c00, $c2c2c200, $e6e6e600, $5f5f5f00,
    $02020200, $24242400, $75757500, $93939300,
    $66666600, $1e1e1e00, $e5e5e500, $e2e2e200,
    $54545400, $d8d8d800, $10101000, $cecece00,
    $7a7a7a00, $e8e8e800, $08080800, $2c2c2c00,
    $12121200, $97979700, $32323200, $ababab00,
    $b4b4b400, $27272700, $0a0a0a00, $23232300,
    $dfdfdf00, $efefef00, $cacaca00, $d9d9d900,
    $b8b8b800, $fafafa00, $dcdcdc00, $31313100,
    $6b6b6b00, $d1d1d100, $adadad00, $19191900,
    $49494900, $bdbdbd00, $51515100, $96969600,
    $eeeeee00, $e4e4e400, $a8a8a800, $41414100,
    $dadada00, $ffffff00, $cdcdcd00, $55555500,
    $86868600, $36363600, $bebebe00, $61616100,
    $52525200, $f8f8f800, $bbbbbb00, $0e0e0e00,
    $82828200, $48484800, $69696900, $9a9a9a00,
    $e0e0e000, $47474700, $9e9e9e00, $5c5c5c00,
    $04040400, $4b4b4b00, $34343400, $15151500,
    $79797900, $26262600, $a7a7a700, $dedede00,
    $29292900, $aeaeae00, $92929200, $d7d7d700,
    $84848400, $e9e9e900, $d2d2d200, $bababa00,
    $5d5d5d00, $f3f3f300, $c5c5c500, $b0b0b000,
    $bfbfbf00, $a4a4a400, $3b3b3b00, $71717100,
    $44444400, $46464600, $2b2b2b00, $fcfcfc00,
    $ebebeb00, $6f6f6f00, $d5d5d500, $f6f6f600,
    $14141400, $fefefe00, $7c7c7c00, $70707000,
    $5a5a5a00, $7d7d7d00, $fdfdfd00, $2f2f2f00,
    $18181800, $83838300, $16161600, $a5a5a500,
    $91919100, $1f1f1f00, $05050500, $95959500,
    $74747400, $a9a9a900, $c1c1c100, $5b5b5b00,
    $4a4a4a00, $85858500, $6d6d6d00, $13131300,
    $07070700, $4f4f4f00, $4e4e4e00, $45454500,
    $b2b2b200, $0f0f0f00, $c9c9c900, $1c1c1c00,
    $a6a6a600, $bcbcbc00, $ececec00, $73737300,
    $90909000, $7b7b7b00, $cfcfcf00, $59595900,
    $8f8f8f00, $a1a1a100, $f9f9f900, $2d2d2d00,
    $f2f2f200, $b1b1b100, $00000000, $94949400,
    $37373700, $9f9f9f00, $d0d0d000, $2e2e2e00,
    $9c9c9c00, $6e6e6e00, $28282800, $3f3f3f00,
    $80808000, $f0f0f000, $3d3d3d00, $d3d3d300,
    $25252500, $8a8a8a00, $b5b5b500, $e7e7e700,
    $42424200, $b3b3b300, $c7c7c700, $eaeaea00,
    $f7f7f700, $4c4c4c00, $11111100, $33333300,
    $03030300, $a2a2a200, $acacac00, $60606000
);

  function ossl_aria_set_encrypt_key(const userKey : PByte; bits : integer; key : PARIA_KEY):integer;
  function GET_U32_BE(X: PByte; Y: Byte): uint32;
  procedure ARIA_SBOX_LAYER1_WITH_PRE_DIFF(var T0, T1, T2, T3 : uint32);
  function rotl32(v: uint32; r: byte): UInt32;
  function rotr32(v: uint32; r: byte): UInt32;
  function GET_U8_BE(X: uint32; Y: byte): uint8;
  procedure ARIA_SUBST_DIFF_ODD(var T0, T1, T2, T3 : uint32);
  procedure ARIA_DIFF_WORD(var T0, T1, T2, T3 : uint32);
  function bswap32(v: uint32): UInt32;
  procedure ARIA_DIFF_BYTE(var T0, T1, T2, T3 : uint32);
  procedure ARIA_SBOX_LAYER2_WITH_PRE_DIFF(var T0, T1, T2, T3 : uint32);
  procedure _ARIA_GSRK(RK: PARIA_u128;  X, Y: PUint32; Q, R: Uint32);
  procedure ARIA_GSRK(RK: PARIA_u128;  X, Y: PUint32; N: Uint32);
  procedure ARIA_ADD_ROUND_KEY(RK: PARIA_u128;var  T0,T1,T2,T3: Uint32);
  procedure ARIA_SUBST_DIFF_EVEN(var T0,T1,T2,T3: Uint32);
  function MAKE_U32(V0, V1, V2, V3: uint8):uint32;
  procedure ossl_aria_encrypt(const _in : PByte; _out : PByte;const key : PARIA_KEY);
  procedure PUT_U32_BE(DEST: PByte; IDX, VAL: uint32);
  procedure ARIA_DEC_DIFF_BYTE(X: Uint32; var Y, TMP, TMP2: Uint32);
function ossl_aria_set_decrypt_key(const userKey : PByte; bits : integer; key : PARIA_KEY):integer;

implementation

procedure ARIA_DEC_DIFF_BYTE(X: Uint32; var Y, TMP, TMP2: Uint32);
begin
        TMP := (X);
        TMP2 := rotr32((TMP), 8);
        Y := (TMP2)  xor  rotr32((TMP)  xor  (TMP2), 16);
end;

function ossl_aria_set_decrypt_key(const userKey : PByte; bits : integer; key : PARIA_KEY):integer;
var
  rk_head, rk_tail : PARIA_u128;
  w1, w2, reg0, reg1, reg2, reg3, s0, s1, s2, s3 : uint32;
  r : integer;
begin
{$POINTERMATH ON}
    r := ossl_aria_set_encrypt_key(userKey, bits, key);
    if r <> 0 then begin
        Exit(r);
    end;
    rk_head := @key.rd_key;
    rk_tail := rk_head + key.rounds;
    reg0 := rk_head.u[0];
    reg1 := rk_head.u[1];
    reg2 := rk_head.u[2];
    reg3 := rk_head.u[3];
    memcpy(rk_head, rk_tail, ARIA_BLOCK_SIZE);
    rk_tail.u[0] := reg0;
    rk_tail.u[1] := reg1;
    rk_tail.u[2] := reg2;
    rk_tail.u[3] := reg3;
    Inc(rk_head);
    Dec(rk_tail);
    while rk_head < rk_tail do
    begin
        ARIA_DEC_DIFF_BYTE(rk_head.u[0], reg0, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_head.u[1], reg1, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_head.u[2], reg2, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_head.u[3], reg3, w1, w2);
        ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
        ARIA_DIFF_BYTE(reg0, reg1, reg2, reg3);
        ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
        s0 := reg0;
        s1 := reg1;
        s2 := reg2;
        s3 := reg3;
        ARIA_DEC_DIFF_BYTE(rk_tail.u[0], reg0, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_tail.u[1], reg1, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_tail.u[2], reg2, w1, w2);
        ARIA_DEC_DIFF_BYTE(rk_tail.u[3], reg3, w1, w2);
        ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
        ARIA_DIFF_BYTE(reg0, reg1, reg2, reg3);
        ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
        rk_head.u[0] := reg0;
        rk_head.u[1] := reg1;
        rk_head.u[2] := reg2;
        rk_head.u[3] := reg3;
        rk_tail.u[0] := s0;
        rk_tail.u[1] := s1;
        rk_tail.u[2] := s2;
        rk_tail.u[3] := s3;
        Inc(rk_head);
        Dec(rk_tail);
    end;
    ARIA_DEC_DIFF_BYTE(rk_head.u[0], reg0, w1, w2);
    ARIA_DEC_DIFF_BYTE(rk_head.u[1], reg1, w1, w2);
    ARIA_DEC_DIFF_BYTE(rk_head.u[2], reg2, w1, w2);
    ARIA_DEC_DIFF_BYTE(rk_head.u[3], reg3, w1, w2);
    ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
    ARIA_DIFF_BYTE(reg0, reg1, reg2, reg3);
    ARIA_DIFF_WORD(reg0, reg1, reg2, reg3);
    rk_tail.u[0] := reg0;
    rk_tail.u[1] := reg1;
    rk_tail.u[2] := reg2;
    rk_tail.u[3] := reg3;
    Result := 0;
{$POINTERMATH OFF}
end;

procedure PUT_U32_BE(DEST: PByte; IDX, VAL: uint32);
begin
        (Puint8(DEST))[IDX * 4    ] := GET_U8_BE(VAL, 0);
        (Puint8(DEST))[IDX * 4 + 1] := GET_U8_BE(VAL, 1);
        (Puint8(DEST))[IDX * 4 + 2] := GET_U8_BE(VAL, 2);
        (Puint8(DEST))[IDX * 4 + 3] := GET_U8_BE(VAL, 3);
end;

function MAKE_U32(V0, V1, V2, V3: uint8):uint32;
begin
    RESULT := (uint32(uint8(V0))  shl  24) or
              (uint32(uint8(V1))  shl  16) or
              (uint32(uint8(V2))  shl   8) or
              (uint32(uint8(V3))      )
end;

procedure ARIA_SUBST_DIFF_EVEN(var T0,T1,T2,T3: Uint32);
begin
        ARIA_SBOX_LAYER2_WITH_PRE_DIFF(T0, T1, T2, T3);
        ARIA_DIFF_WORD(T0, T1, T2, T3);
        ARIA_DIFF_BYTE(T2, T3, T0, T1);
        ARIA_DIFF_WORD(T0, T1, T2, T3);
end;

procedure ARIA_ADD_ROUND_KEY(RK: PARIA_u128;var  T0,T1,T2,T3: Uint32);
begin
        T0  := (T0) xor ((RK).u[0]);
        T1  := (T1) xor ((RK).u[1]);
        T2  := (T2) xor ((RK).u[2]);
        T3  := (T3) xor ((RK).u[3]);
end;

procedure ossl_aria_encrypt(const _in : PByte; _out : PByte;const key : PARIA_KEY);
var
  reg0, reg1, reg2, reg3 : uint32;
  Nr : integer;
  rk : PARIA_u128;
  function get_Nr: Int;
  begin
     Nr := Nr-2;
     Result := Nr;
  end;
begin
    if (_in = nil)  or  (_out = nil)  or  (key = nil) then begin
        exit;
    end;
    rk := @key.rd_key;
    Nr := key.rounds;
    if (Nr <> 12)  and  (Nr <> 14)  and  (Nr <> 16) then begin
        exit;
    end;
    reg0 := GET_U32_BE(_in, 0);
    reg1 := GET_U32_BE(_in, 1);
    reg2 := GET_U32_BE(_in, 2);
    reg3 := GET_U32_BE(_in, 3);
    ARIA_ADD_ROUND_KEY(rk, reg0, reg1, reg2, reg3);
    Inc(rk);
    ARIA_SUBST_DIFF_ODD(reg0, reg1, reg2, reg3);
    ARIA_ADD_ROUND_KEY(rk, reg0, reg1, reg2, reg3);
    Inc(rk);
    while get_Nr > 0 do
    begin
        ARIA_SUBST_DIFF_EVEN(reg0, reg1, reg2, reg3);
        ARIA_ADD_ROUND_KEY(rk, reg0, reg1, reg2, reg3);
        Inc(rk);
        ARIA_SUBST_DIFF_ODD(reg0, reg1, reg2, reg3);
        ARIA_ADD_ROUND_KEY(rk, reg0, reg1, reg2, reg3);
        Inc(rk);
    end;
    reg0 := rk.u[0]  xor  MAKE_U32(
         uint8(X1[GET_U8_BE(reg0, 0)]     ),
         uint8(X2[GET_U8_BE(reg0, 1)]  shr  8),
         uint8(S1[GET_U8_BE(reg0, 2)]     ),
         uint8(S2[GET_U8_BE(reg0, 3)]     ));
    reg1 := rk.u[1]  xor  MAKE_U32(
         uint8(X1[GET_U8_BE(reg1, 0)]     ),
         uint8(X2[GET_U8_BE(reg1, 1)]  shr  8),
         uint8(S1[GET_U8_BE(reg1, 2)]     ),
         uint8(S2[GET_U8_BE(reg1, 3)]     ));
    reg2 := rk.u[2]  xor  MAKE_U32(
         uint8(X1[GET_U8_BE(reg2, 0)]     ),
         uint8(X2[GET_U8_BE(reg2, 1)]  shr  8),
         uint8(S1[GET_U8_BE(reg2, 2)]     ),
         uint8(S2[GET_U8_BE(reg2, 3)]     ));
    reg3 := rk.u[3]  xor  MAKE_U32(
         uint8(X1[GET_U8_BE(reg3, 0)]     ),
         uint8(X2[GET_U8_BE(reg3, 1)]  shr  8),
         uint8(S1[GET_U8_BE(reg3, 2)]     ),
         uint8(S2[GET_U8_BE(reg3, 3)]     ));
    PUT_U32_BE(_out, 0, reg0);
    PUT_U32_BE(_out, 1, reg1);
    PUT_U32_BE(_out, 2, reg2);
    PUT_U32_BE(_out, 3, reg3);
end;


procedure _ARIA_GSRK(RK: PARIA_u128;  X, Y: PUint32; Q, R: Uint32);
begin
{$POINTERMATH ON}
        RK.u[0] :=
            ((X)[0])  xor
            (((Y)[((Q)    ) mod 4])  shr  (R))  xor
            (((Y)[((Q) + 3) mod 4])  shl  (32 - (R)));
        (RK).u[1] :=
            ((X)[1])  xor
            (((Y)[((Q) + 1) mod 4])  shr  (R))  xor
            (((Y)[((Q)    ) mod 4])  shl  (32 - (R)));
        (RK).u[2] :=
            ((X)[2])  xor
            (((Y)[((Q) + 2) mod 4])  shr  (R))  xor
            (((Y)[((Q) + 1) mod 4])  shl  (32 - (R)));
        (RK).u[3] :=
            ((X)[3])  xor
            (((Y)[((Q) + 3) mod 4])  shr  (R))  xor
            (((Y)[((Q) + 2) mod 4])  shl  (32 - (R)));
{$POINTERMATH OFF}
end;


procedure ARIA_GSRK(RK: PARIA_u128;  X, Y: PUint32; N: Uint32);
begin
   _ARIA_GSRK(RK, X, Y, 4 - ((N) div 32), (N) mod 32)
end;

procedure ARIA_SBOX_LAYER2_WITH_PRE_DIFF(var T0, T1, T2, T3 : uint32);
begin
        T0 :=
            X1[GET_U8_BE(T0, 0)]  xor
            X2[GET_U8_BE(T0, 1)]  xor
            S1[GET_U8_BE(T0, 2)]  xor
            S2[GET_U8_BE(T0, 3)];
        T1 :=
            X1[GET_U8_BE(T1, 0)]  xor
            X2[GET_U8_BE(T1, 1)]  xor
            S1[GET_U8_BE(T1, 2)]  xor
            S2[GET_U8_BE(T1, 3)];
        T2 :=
            X1[GET_U8_BE(T2, 0)]  xor
            X2[GET_U8_BE(T2, 1)]  xor
            S1[GET_U8_BE(T2, 2)]  xor
            S2[GET_U8_BE(T2, 3)];
        T3 :=
            X1[GET_U8_BE(T3, 0)]  xor
            X2[GET_U8_BE(T3, 1)]  xor
            S1[GET_U8_BE(T3, 2)]  xor
            S2[GET_U8_BE(T3, 3)];
end;


procedure ARIA_DIFF_BYTE(var T0, T1, T2, T3 : uint32);
begin
        T1 := (((T1)  shl  8) and $ff00ff00)  xor  (((T1)  shr  8) and $00ff00ff);
        T2 := rotr32(T2, 16);
        T3 := bswap32(T3);
end;

procedure ARIA_DIFF_WORD(var T0, T1, T2, T3 : uint32);
begin
        T1  := (T1) xor ((T2));
        T2  := (T2) xor ((T3));
        T0  := (T0) xor ((T1));
        T3  := (T3) xor ((T1));
        T2  := (T2) xor ((T0));
        T1  := (T1) xor ((T2));
end;

procedure ARIA_SUBST_DIFF_ODD(var T0, T1, T2, T3 : uint32);
begin
        ARIA_SBOX_LAYER1_WITH_PRE_DIFF(T0, T1, T2, T3);
        ARIA_DIFF_WORD(T0, T1, T2, T3);
        ARIA_DIFF_BYTE(T0, T1, T2, T3);
        ARIA_DIFF_WORD(T0, T1, T2, T3);
end;

function rotl32(v: uint32; r: byte): UInt32;
begin
   Result := ((uint32(v) shl (r)) or (uint32(v) shr (32 - r)))
end;

function rotr32(v: uint32; r: byte): UInt32;
begin
   Result := ((uint32(v) shr (r)) or (uint32(v) shl (32 - r)))
end;

function bswap32(v: uint32): UInt32;
begin
   Result := (((v) shl 24) xor ((v) shr 24) xor
    (((v) and $0000ff00) shl 8) xor (((v) and $00ff0000) shr 8))
end;


function GET_U8_BE(X: uint32; Y: byte): uint8;
begin
   Result := (uint8((X) shr ((3 - Y) * 8)))
end;

procedure ARIA_SBOX_LAYER1_WITH_PRE_DIFF(var T0, T1, T2, T3 : uint32);
begin
        T0 :=
            S1[GET_U8_BE(T0, 0)] xor
            S2[GET_U8_BE(T0, 1)] xor
            X1[GET_U8_BE(T0, 2)] xor
            X2[GET_U8_BE(T0, 3)];
        T1 :=
            S1[GET_U8_BE(T1, 0)] xor
            S2[GET_U8_BE(T1, 1)] xor
            X1[GET_U8_BE(T1, 2)] xor
            X2[GET_U8_BE(T1, 3)];
        T2 :=
            S1[GET_U8_BE(T2, 0)] xor
            S2[GET_U8_BE(T2, 1)] xor
            X1[GET_U8_BE(T2, 2)] xor
            X2[GET_U8_BE(T2, 3)];
        T3 :=
            S1[GET_U8_BE(T3, 0)] xor
            S2[GET_U8_BE(T3, 1)] xor
            X1[GET_U8_BE(T3, 2)] xor
            X2[GET_U8_BE(T3, 3)];
end;

function GET_U32_BE(X: PByte; Y: Byte): uint32;
begin
    Result := (uint32(Puint8(X)[Y * 4    ] shl 24)) xor
              (uint32(Puint8(X)[Y * 4 + 1] shl 16)) xor
              (uint32(Puint8(X)[Y * 4 + 2] shl  8)) xor
              (uint32(Puint8(X)[Y * 4 + 3]      ))
end;

function ossl_aria_set_encrypt_key(const userKey : PByte; bits : integer; key : PARIA_KEY):integer;
var
  reg0, reg1, reg2, reg3 : uint32;
  w0, w1, w2, w3 : array[0..3] of uint32;
  ck : Puint32;
  rk : PARIA_u128;
  Nr : integer;
begin
{$POINTERMATH ON}
    Nr := (bits + 256) div 32;
    if (userKey = nil)  or  (key = nil) then
    begin
        Exit(-1);
    end;
    if (bits <> 128)  and  (bits <> 192)  and  (bits <> 256) then
    begin
        Exit(-2);
    end;
    rk := @key.rd_key;
    key.rounds := Nr;
    ck := @Key_RC[(bits - 128) div 64][0];
    w0[0] := GET_U32_BE(userKey, 0);
    w0[1] := GET_U32_BE(userKey, 1);
    w0[2] := GET_U32_BE(userKey, 2);
    w0[3] := GET_U32_BE(userKey, 3);
    reg0 := w0[0]  xor  ck[0];
    reg1 := w0[1]  xor  ck[1];
    reg2 := w0[2]  xor  ck[2];
    reg3 := w0[3]  xor  ck[3];
    ARIA_SUBST_DIFF_ODD(reg0, reg1, reg2, reg3);
    if bits > 128 then
    begin
        w1[0] := GET_U32_BE(userKey, 4);
        w1[1] := GET_U32_BE(userKey, 5);
        if bits > 192 then
        begin
            w1[2] := GET_U32_BE(userKey, 6);
            w1[3] := GET_U32_BE(userKey, 7);
        end
        else begin
            w1[2] := 0;w1[3] := 0;
        end;
    end
    else
    begin
        w1[0] := 0; w1[1] := 0; w1[2] := 0; w1[3] := 0;
    end;
    w1[0]  := w1[0] xor reg0;
    w1[1]  := w1[1] xor reg1;
    w1[2]  := w1[2] xor reg2;
    w1[3]  := w1[3] xor reg3;
    reg0 := w1[0];
    reg1 := w1[1];
    reg2 := w1[2];
    reg3 := w1[3];
    reg0  := reg0 xor (ck[4]);
    reg1  := reg1 xor (ck[5]);
    reg2  := reg2 xor (ck[6]);
    reg3  := reg3 xor (ck[7]);
    ARIA_SUBST_DIFF_EVEN(reg0, reg1, reg2, reg3);
    reg0  := reg0 xor (w0[0]);
    reg1  := reg1 xor (w0[1]);
    reg2  := reg2 xor (w0[2]);
    reg3  := reg3 xor (w0[3]);
    w2[0] := reg0;
    w2[1] := reg1;
    w2[2] := reg2;
    w2[3] := reg3;
    reg0  := reg0 xor (ck[8]);
    reg1  := reg1 xor (ck[9]);
    reg2  := reg2 xor (ck[10]);
    reg3  := reg3 xor (ck[11]);
    ARIA_SUBST_DIFF_ODD(reg0, reg1, reg2, reg3);
    w3[0] := reg0  xor  w1[0];
    w3[1] := reg1  xor  w1[1];
    w3[2] := reg2  xor  w1[2];
    w3[3] := reg3  xor  w1[3];
    ARIA_GSRK(rk, @w0, @w1, 19);
    Inc(rk);
    ARIA_GSRK(rk, @w1, @w2, 19);
    Inc(rk);
    ARIA_GSRK(rk, @w2, @w3, 19);
    Inc(rk);
    ARIA_GSRK(rk, @w3, @w0, 19);
    Inc(rk);
    ARIA_GSRK(rk, @w0, @w1, 31);
    Inc(rk);
    ARIA_GSRK(rk, @w1, @w2, 31);
    Inc(rk);
    ARIA_GSRK(rk, @w2, @w3, 31);
    Inc(rk);
    ARIA_GSRK(rk, @w3, @w0, 31);
    Inc(rk);
    ARIA_GSRK(rk, @w0, @w1, 67);
    Inc(rk);
    ARIA_GSRK(rk, @w1, @w2, 67);
    Inc(rk);
    ARIA_GSRK(rk, @w2, @w3, 67);
    Inc(rk);
    ARIA_GSRK(rk, @w3, @w0, 67);
    Inc(rk);
    ARIA_GSRK(rk, @w0, @w1, 97);
    if bits > 128 then
    begin
        Inc(rk);
        ARIA_GSRK(rk, @w1, @w2, 97);
        Inc(rk);
        ARIA_GSRK(rk, @w2, @w3, 97);
    end;
    if bits > 192 then
    begin
        Inc(rk);
        ARIA_GSRK(rk, @w3, @w0, 97);
        Inc(rk);
        ARIA_GSRK(rk, @w0, @w1, 109);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

end.
