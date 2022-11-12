unit openssl3.crypto.des.set_key;

interface
uses OpenSSL.Api;

 procedure DES_set_odd_parity( key : PDES_cblock);

 procedure DES_set_key_unchecked(key : Pconst_DES_cblock; schedule : PDES_key_schedule);


const

  DES_KEY_SZ = (sizeof(TDES_cblock));
  ITERATIONS = 16;
  des_skb: array[0..7, 0..63] of DES_LONG = (
    (
     (* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 *)
     Long($00000000), Long($00000010), Long($20000000), Long($20000010),
     Long($00010000), Long($00010010), Long($20010000), Long($20010010),
     Long($00000800), Long($00000810), Long($20000800), Long($20000810),
     Long($00010800), Long($00010810), Long($20010800), Long($20010810),
     Long($00000020), Long($00000030), Long($20000020), Long($20000030),
     Long($00010020), Long($00010030), Long($20010020), Long($20010030),
     Long($00000820), Long($00000830), Long($20000820), Long($20000830),
     Long($00010820), Long($00010830), Long($20010820), Long($20010830),
     Long($00080000), Long($00080010), Long($20080000), Long($20080010),
     Long($00090000), Long($00090010), Long($20090000), Long($20090010),
     Long($00080800), Long($00080810), Long($20080800), Long($20080810),
     Long($00090800), Long($00090810), Long($20090800), Long($20090810),
     Long($00080020), Long($00080030), Long($20080020), Long($20080030),
     Long($00090020), Long($00090030), Long($20090020), Long($20090030),
     Long($00080820), Long($00080830), Long($20080820), Long($20080830),
     Long($00090820), Long($00090830), Long($20090820), Long($20090830)
     ),
    (
     (* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 *)
     Long($00000000), Long($02000000), Long($00002000), Long($02002000),
     Long($00200000), Long($02200000), Long($00202000), Long($02202000),
     Long($00000004), Long($02000004), Long($00002004), Long($02002004),
     Long($00200004), Long($02200004), Long($00202004), Long($02202004),
     Long($00000400), Long($02000400), Long($00002400), Long($02002400),
     Long($00200400), Long($02200400), Long($00202400), Long($02202400),
     Long($00000404), Long($02000404), Long($00002404), Long($02002404),
     Long($00200404), Long($02200404), Long($00202404), Long($02202404),
     Long($10000000), Long($12000000), Long($10002000), Long($12002000),
     Long($10200000), Long($12200000), Long($10202000), Long($12202000),
     Long($10000004), Long($12000004), Long($10002004), Long($12002004),
     Long($10200004), Long($12200004), Long($10202004), Long($12202004),
     Long($10000400), Long($12000400), Long($10002400), Long($12002400),
     Long($10200400), Long($12200400), Long($10202400), Long($12202400),
     Long($10000404), Long($12000404), Long($10002404), Long($12002404),
     Long($10200404), Long($12200404), Long($10202404), Long($12202404)
     ),
    (
     (* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 *)
     Long($00000000), Long($00000001), Long($00040000), Long($00040001),
     Long($01000000), Long($01000001), Long($01040000), Long($01040001),
     Long($00000002), Long($00000003), Long($00040002), Long($00040003),
     Long($01000002), Long($01000003), Long($01040002), Long($01040003),
     Long($00000200), Long($00000201), Long($00040200), Long($00040201),
     Long($01000200), Long($01000201), Long($01040200), Long($01040201),
     Long($00000202), Long($00000203), Long($00040202), Long($00040203),
     Long($01000202), Long($01000203), Long($01040202), Long($01040203),
     Long($08000000), Long($08000001), Long($08040000), Long($08040001),
     Long($09000000), Long($09000001), Long($09040000), Long($09040001),
     Long($08000002), Long($08000003), Long($08040002), Long($08040003),
     Long($09000002), Long($09000003), Long($09040002), Long($09040003),
     Long($08000200), Long($08000201), Long($08040200), Long($08040201),
     Long($09000200), Long($09000201), Long($09040200), Long($09040201),
     Long($08000202), Long($08000203), Long($08040202), Long($08040203),
     Long($09000202), Long($09000203), Long($09040202), Long($09040203)
     ),
    (
     (* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 *)
     Long($00000000), Long($00100000), Long($00000100), Long($00100100),
     Long($00000008), Long($00100008), Long($00000108), Long($00100108),
     Long($00001000), Long($00101000), Long($00001100), Long($00101100),
     Long($00001008), Long($00101008), Long($00001108), Long($00101108),
     Long($04000000), Long($04100000), Long($04000100), Long($04100100),
     Long($04000008), Long($04100008), Long($04000108), Long($04100108),
     Long($04001000), Long($04101000), Long($04001100), Long($04101100),
     Long($04001008), Long($04101008), Long($04001108), Long($04101108),
     Long($00020000), Long($00120000), Long($00020100), Long($00120100),
     Long($00020008), Long($00120008), Long($00020108), Long($00120108),
     Long($00021000), Long($00121000), Long($00021100), Long($00121100),
     Long($00021008), Long($00121008), Long($00021108), Long($00121108),
     Long($04020000), Long($04120000), Long($04020100), Long($04120100),
     Long($04020008), Long($04120008), Long($04020108), Long($04120108),
     Long($04021000), Long($04121000), Long($04021100), Long($04121100),
     Long($04021008), Long($04121008), Long($04021108), Long($04121108)
     ),
    (
     (* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 *)
     Long($00000000), Long($10000000), Long($00010000), Long($10010000),
     Long($00000004), Long($10000004), Long($00010004), Long($10010004),
     Long($20000000), Long($30000000), Long($20010000), Long($30010000),
     Long($20000004), Long($30000004), Long($20010004), Long($30010004),
     Long($00100000), Long($10100000), Long($00110000), Long($10110000),
     Long($00100004), Long($10100004), Long($00110004), Long($10110004),
     Long($20100000), Long($30100000), Long($20110000), Long($30110000),
     Long($20100004), Long($30100004), Long($20110004), Long($30110004),
     Long($00001000), Long($10001000), Long($00011000), Long($10011000),
     Long($00001004), Long($10001004), Long($00011004), Long($10011004),
     Long($20001000), Long($30001000), Long($20011000), Long($30011000),
     Long($20001004), Long($30001004), Long($20011004), Long($30011004),
     Long($00101000), Long($10101000), Long($00111000), Long($10111000),
     Long($00101004), Long($10101004), Long($00111004), Long($10111004),
     Long($20101000), Long($30101000), Long($20111000), Long($30111000),
     Long($20101004), Long($30101004), Long($20111004), Long($30111004)
     ),
    (
     (* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 *)
     Long($00000000), Long($08000000), Long($00000008), Long($08000008),
     Long($00000400), Long($08000400), Long($00000408), Long($08000408),
     Long($00020000), Long($08020000), Long($00020008), Long($08020008),
     Long($00020400), Long($08020400), Long($00020408), Long($08020408),
     Long($00000001), Long($08000001), Long($00000009), Long($08000009),
     Long($00000401), Long($08000401), Long($00000409), Long($08000409),
     Long($00020001), Long($08020001), Long($00020009), Long($08020009),
     Long($00020401), Long($08020401), Long($00020409), Long($08020409),
     Long($02000000), Long($0A000000), Long($02000008), Long($0A000008),
     Long($02000400), Long($0A000400), Long($02000408), Long($0A000408),
     Long($02020000), Long($0A020000), Long($02020008), Long($0A020008),
     Long($02020400), Long($0A020400), Long($02020408), Long($0A020408),
     Long($02000001), Long($0A000001), Long($02000009), Long($0A000009),
     Long($02000401), Long($0A000401), Long($02000409), Long($0A000409),
     Long($02020001), Long($0A020001), Long($02020009), Long($0A020009),
     Long($02020401), Long($0A020401), Long($02020409), Long($0A020409)
     ),
    (
     (* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 *)
     Long($00000000), Long($00000100), Long($00080000), Long($00080100),
     Long($01000000), Long($01000100), Long($01080000), Long($01080100),
     Long($00000010), Long($00000110), Long($00080010), Long($00080110),
     Long($01000010), Long($01000110), Long($01080010), Long($01080110),
     Long($00200000), Long($00200100), Long($00280000), Long($00280100),
     Long($01200000), Long($01200100), Long($01280000), Long($01280100),
     Long($00200010), Long($00200110), Long($00280010), Long($00280110),
     Long($01200010), Long($01200110), Long($01280010), Long($01280110),
     Long($00000200), Long($00000300), Long($00080200), Long($00080300),
     Long($01000200), Long($01000300), Long($01080200), Long($01080300),
     Long($00000210), Long($00000310), Long($00080210), Long($00080310),
     Long($01000210), Long($01000310), Long($01080210), Long($01080310),
     Long($00200200), Long($00200300), Long($00280200), Long($00280300),
     Long($01200200), Long($01200300), Long($01280200), Long($01280300),
     Long($00200210), Long($00200310), Long($00280210), Long($00280310),
     Long($01200210), Long($01200310), Long($01280210), Long($01280310)
     ),
    (
     (* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 *)
     Long($00000000), Long($04000000), Long($00040000), Long($04040000),
     Long($00000002), Long($04000002), Long($00040002), Long($04040002),
     Long($00002000), Long($04002000), Long($00042000), Long($04042000),
     Long($00002002), Long($04002002), Long($00042002), Long($04042002),
     Long($00000020), Long($04000020), Long($00040020), Long($04040020),
     Long($00000022), Long($04000022), Long($00040022), Long($04040022),
     Long($00002020), Long($04002020), Long($00042020), Long($04042020),
     Long($00002022), Long($04002022), Long($00042022), Long($04042022),
     Long($00000800), Long($04000800), Long($00040800), Long($04040800),
     Long($00000802), Long($04000802), Long($00040802), Long($04040802),
     Long($00002800), Long($04002800), Long($00042800), Long($04042800),
     Long($00002802), Long($04002802), Long($00042802), Long($04042802),
     Long($00000820), Long($04000820), Long($00040820), Long($04040820),
     Long($00000822), Long($04000822), Long($00040822), Long($04040822),
     Long($00002820), Long($04002820), Long($00042820), Long($04042820),
     Long($00002822), Long($04002822), Long($00042822), Long($04042822)
     )
);
  odd_parity: array[0..255] of BYte = (
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110,
    110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127,
    127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143,
    143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158,
    158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174,
    174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191,
    191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206,
    206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223,
    223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239,
    239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254,
    254
);
implementation
uses openssl3.crypto.des.des_local;

const // 1d arrays
  shifts2 : array[0..15] of integer = (
    0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0 );


procedure DES_set_key_unchecked(key : Pconst_DES_cblock; schedule : PDES_key_schedule);
var
  c, d, t, s, t2 : DES_LONG;
  _in : PByte;
  k : PDES_LONG;
  i : integer;
  ks_p: Pdes_st;
begin

{$IFDEF OPENBSD_DEV_CRYPTO}
    memcpy(schedule.key, key, sizeof(schedule.key));
    schedule.session := nil;
{$ENDIF}
    ks_p := @schedule.ks;
    k := @ks_p.deslong[0];
    _in := @( key^)[0];
    c2l(_in, c);
    c2l(_in, d);
    {
     * do PC1 in 47 simple operations. Thanks to John Fletcher
     * for the inspiration.
     }
    PERM_OP(d, c, t, 4, Long($0f0f0f0f));
    HPERM_OP(c, t, -2, Long($cccc0000));
    HPERM_OP(d, t, -2, Long($cccc0000));
    PERM_OP(d, c, t, 1, Long($55555555));
    PERM_OP(c, d, t, 8, Long($00ff00ff));
    PERM_OP(d, c, t, 1, Long($55555555));
    d := (((d and Long($000000ff)) shl Long(16)) or (d and Long($0000ff00)) or
         ((d and Long($00ff0000))  shr  Long(16)) or ((c and Long($f0000000))  shr  Long(4)));
    c := c and Long($0fffffff);
    for i := 0 to ITERATIONS-1 do
    begin
        if shifts2[i] > 0 then
        begin
            c := ((c  shr  Long(2)) or (c shl Long(26)));
            d := ((d  shr  Long(2)) or (d shl Long(26)));
        end
        else
        begin
            c := ((c  shr  Long(1)) or (c shl Long(27)));
            d := ((d  shr  Long(1)) or (d shl Long(27)));
        end;
        c := c and Long($0fffffff);
        d := d and Long($0fffffff);
        {
         * could be a few less shifts but I am to lazy at this point in time
         * to investigate
         }
        s := des_skb[0][(c) and $3f] or
            des_skb[1][((c  shr  Long(6)) and $03) or ((c  shr  Long(7)) and $3c)] or
            des_skb[2][((c  shr  Long(13)) and $0f) or ((c  shr  Long(14)) and $30)] or
            des_skb[3][((c  shr  Long(20)) and $01) or ((c  shr  Long(21)) and $06) or
                       ((c  shr  Long(22)) and $38)];
        t := des_skb[4][(d) and $3f] or
            des_skb[5][((d  shr  Long(7)) and $03) or ((d  shr  Long(8)) and $3c)] or
            des_skb[6][(d  shr  Long(15)) and $3f] or
            des_skb[7][((d  shr  Long(21)) and $0f) or ((d  shr  Long(22)) and $30)];
        { table contained 0213 4657 }
        t2 := ((t shl Long(16)) or (s and Long($0000ffff))) and Long($ffffffff);
        k^ := ROTATE(t2, 30) and Long($ffffffff);
        Inc(k);
        t2 := ((s  shr  Long(16)) or (t and Long($ffff0000)));
        k^ := ROTATE(t2, 26) and Long($ffffffff);
        Inc(k);
    end;
end;



procedure DES_set_odd_parity( key : PDES_cblock);
var
  i : uint32;
begin
    for i := 0 to DES_KEY_SZ-1 do
        key^[i] := odd_parity[( key^)[i]];
end;


end.
