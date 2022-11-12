unit openssl3.crypto.des.des_enc;

interface
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}OpenSSL.Api;

 procedure DES_ede3_cbc_encrypt(const input : PByte; output : PByte; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; enc : integer);
procedure DES_encrypt3(data : PDES_LONG; ks1, ks2, ks3 : PDES_key_schedule);
procedure DES_encrypt2( data : PDES_LONG; ks : PDES_key_schedule; enc : integer);
procedure DES_decrypt3( data : PDES_LONG; ks1, ks2, ks3 : PDES_key_schedule);

procedure DES_encrypt1( data : PDES_LONG; ks : PDES_key_schedule; enc : integer);

implementation

uses openssl3.crypto.des.des_local;




procedure DES_encrypt1( data : PDES_LONG; ks : PDES_key_schedule; enc : integer);
var
  l, r, t, u : DES_LONG;
  s : PDES_LONG;
begin
{$POINTERMATH ON}
    r := data[0];
    l := data[1];
    IP(r, l);
    {
     * Things have been modified so that the initial rotate is done outside
     * the loop.  This required the DES_SPtrans values in sp.h to be rotated
     * 1 bit to the right. One perl script later and things have a 5% speed
     * up on a sparc2. Thanks to Richard Outerbridge for pointing this out.
     }
    { clear the top bits on machines with 8byte longs }
    { shift left by 2 }
    r := ROTATE(r, 29) and $ffffffff;
    l := ROTATE(l, 29) and $ffffffff;
    s := @(Pdes_st(@ks.ks).deslong);
    {
     * I don't know if it is worth the effort of loop unrolling the inner
     * loop
     }
    if enc > 0 then
    begin
   u := r xor s[0 ];
   t := r xor s[0+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[2 ];
   t := l xor s[2+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[4 ];
   t := r xor s[4+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[6 ];
   t := l xor s[6+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[8 ];
   t := r xor s[8+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[10 ];
   t := l xor s[10+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[12 ];
   t := r xor s[12+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[14 ];
   t := l xor s[14+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[16 ];
   t := r xor s[16+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[18 ];
   t := l xor s[18+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[20 ];
   t := r xor s[20+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[22 ];
   t := l xor s[22+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[24 ];
   t := r xor s[24+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[26 ];
   t := l xor s[26+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[28 ];
   t := r xor s[28+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[30 ];
   t := l xor s[30+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end
 else
 begin
   u := r xor s[30 ];
   t := r xor s[30+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[28 ];
   t := l xor s[28+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[26 ];
   t := r xor s[26+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[24 ];
   t := l xor s[24+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[22 ];
   t := r xor s[22+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[20 ];
   t := l xor s[20+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[18 ];
   t := r xor s[18+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[16 ];
   t := l xor s[16+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[14 ];
   t := r xor s[14+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[12 ];
   t := l xor s[12+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[10 ];
   t := r xor s[10+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[8 ];
   t := l xor s[8+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[6 ];
   t := r xor s[6+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[4 ];
   t := l xor s[4+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := r xor s[2 ];
   t := r xor s[2+1];
   t := (_lrotr(t,4));
   l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   u := l xor s[0 ];
   t := l xor s[0+1];
   t := (_lrotr(t,4));
   r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
   end;
    { rotate and clear the top bits on machines with 8byte longs }
    l := ROTATE(l, 3) and $ffffffff;
    r := ROTATE(r, 3) and $ffffffff;
    FP(r, l);
    data[0] := l;
    data[1] := r;
    l := 0; r := 0; t := 0; u := 0;
{$POINTERMATH OFF}
end;

procedure DES_decrypt3( data : PDES_LONG; ks1, ks2, ks3 : PDES_key_schedule);
var
  l, r : DES_LONG;
begin
{$POINTERMATH ON}
    l := data[0];
    r := data[1];
    IP(l, r);
    data[0] := l;
    data[1] := r;
    DES_encrypt2(PDES_LONG(data), ks3, DES_DECRYPT);
    DES_encrypt2(PDES_LONG(data), ks2, DES_ENCRYPT);
    DES_encrypt2(PDES_LONG(data), ks1, DES_DECRYPT);
    l := data[0];
    r := data[1];
    FP(r, l);
    data[0] := l;
    data[1] := r;
{$POINTERMATH OFF}
end;



procedure DES_encrypt2( data : PDES_LONG; ks : PDES_key_schedule; enc : integer);
var
  l, r, t, u : DES_LONG;
  s : PDES_LONG;
begin
{$POINTERMATH ON}
    r := data[0];
    l := data[1];
    {
     * Things have been modified so that the initial rotate is done outside
     * the loop.  This required the DES_SPtrans values in sp.h to be rotated
     * 1 bit to the right. One perl script later and things have a 5% speed
     * up on a sparc2. Thanks to Richard Outerbridge for pointing this out.
     }
    { clear the top bits on machines with 8byte longs }
    r := ROTATE(r, 29) and $ffffffff;
    l := ROTATE(l, 29) and $ffffffff;
    s := @Pdes_st(@ks.ks).deslong;
    {
     * I don't know if it is worth the effort of loop unrolling the inner
     * loop
     }
     if enc > 0 then
     begin
        begin
         u := r xor s[0 ];
         t := r xor s[0+1];
         t := (_lrotr(t,4));
         l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
         end;
        ;
        begin  u := l xor s[2 ];
 t := l xor s[2+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[4 ];
 t := r xor s[4+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[6 ];
 t := l xor s[6+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[8 ];
 t := r xor s[8+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[10 ];
 t := l xor s[10+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[12 ];
 t := r xor s[12+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[14 ];
 t := l xor s[14+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[16 ];
 t := r xor s[16+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[18 ];
 t := l xor s[18+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[20 ];
 t := r xor s[20+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[22 ];
 t := l xor s[22+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[24 ];
 t := r xor s[24+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[26 ];
 t := l xor s[26+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[28 ];
 t := r xor s[28+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[30 ];
 t := l xor s[30+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
    end
    else
    begin
        begin  u := r xor s[30 ];
 t := r xor s[30+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[28 ];
 t := l xor s[28+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[26 ];
 t := r xor s[26+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[24 ];
 t := l xor s[24+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[22 ];
 t := r xor s[22+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[20 ];
 t := l xor s[20+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[18 ];
 t := r xor s[18+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[16 ];
 t := l xor s[16+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[14 ];
 t := r xor s[14+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[12 ];
 t := l xor s[12+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[10 ];
 t := r xor s[10+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[8 ];
 t := l xor s[8+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[6 ];
 t := r xor s[6+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[4 ];
 t := l xor s[4+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := r xor s[2 ];
 t := r xor s[2+1];
 t := (_lrotr(t,4));
 l := l xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
        begin  u := l xor s[0 ];
 t := l xor s[0+1];
 t := (_lrotr(t,4));
 r := r xor (DES_SPtrans[0][(u shr  2) and $3f]xor DES_SPtrans[2][(u shr 10) and $3f]xor DES_SPtrans[4][(u shr 18) and $3f]xor DES_SPtrans[6][(u shr 26) and $3f]xor DES_SPtrans[1][(t shr  2) and $3f]xor DES_SPtrans[3][(t shr 10) and $3f]xor DES_SPtrans[5][(t shr 18) and $3f]xor DES_SPtrans[7][(t shr 26) and $3f]);
 end;
;
    end;
    { rotate and clear the top bits on machines with 8byte longs }
    data[0] := ROTATE(l, 3) and $ffffffff;
    data[1] := ROTATE(r, 3) and $ffffffff;
    l := 0; r := 0; t := 0; u := 0;
{$POINTERMATH OFF}
end;

procedure DES_encrypt3(data : PDES_LONG; ks1, ks2, ks3 : PDES_key_schedule);
var
  l, r : DES_LONG;
begin
{$POINTERMATH ON}
    l := data[0];
    r := data[1];
    IP(l, r);
    data[0] := l;
    data[1] := r;
    DES_encrypt2(PDES_LONG(data), ks1, DES_ENCRYPT);
    DES_encrypt2(PDES_LONG(data), ks2, DES_DECRYPT);
    DES_encrypt2(PDES_LONG(data), ks3, DES_ENCRYPT);
    l := data[0];
    r := data[1];
    FP(r, l);
    data[0] := l;
    data[1] := r;
{$POINTERMATH OFF}
end;

procedure DES_ede3_cbc_encrypt(const input : PByte; output : PByte; length : long; ks1, ks2, ks3 : PDES_key_schedule; ivec : PDES_cblock; enc : integer);
var
  tin0, tin1, tout0, tout1, xor0, xor1, t0, t1 : DES_LONG;
  _in, _out : PByte;
  l : long;
  tin : array[0..1] of DES_LONG;
  iv : PByte;
begin
    l := length;
    _in := input;
    _out := output;
    iv := @( ivec^)[0];
    if enc > 0 then
    begin
        c2l(iv, tout0);
        c2l(iv, tout1);
        l := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            DES_encrypt3(PDES_LONG(@tin), ks1, ks2, ks3);
            tout0 := tin[0];
            tout1 := tin[1];
            l2c(tout0, _out);
            l2c(tout1, _out);
            l := l - 8;
        end;
        if l <> -8 then
        begin
            c2ln(_in, tin0, tin1, l + 8);
            tin0  := tin0 xor tout0;
            tin1  := tin1 xor tout1;
            tin[0] := tin0;
            tin[1] := tin1;
            DES_encrypt3(PDES_LONG (@tin), ks1, ks2, ks3);
            tout0 := tin[0];
            tout1 := tin[1];
            l2c(tout0, _out);
            l2c(tout1, _out);
        end;
        iv := @(ivec^)[0];
        l2c(tout0, iv);
        l2c(tout1, iv);
    end
    else
    begin
        //register DES_LONG t0, t1;
        c2l(iv, xor0);
        c2l(iv, xor1);
        l := l - 8;
        while l >= 0 do
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            t0 := tin0;
            t1 := tin1;
            tin[0] := tin0;
            tin[1] := tin1;
            DES_decrypt3(PDES_LONG(@tin), ks1, ks2, ks3);
            tout0 := tin[0];
            tout1 := tin[1];
            tout0  := tout0 xor xor0;
            tout1  := tout1 xor xor1;
            l2c(tout0, _out);
            l2c(tout1, _out);
            xor0 := t0;
            xor1 := t1;
            l := l - 8;
        end;
        if l <> -8 then
        begin
            c2l(_in, tin0);
            c2l(_in, tin1);
            t0 := tin0;
            t1 := tin1;
            tin[0] := tin0;
            tin[1] := tin1;
            DES_decrypt3(PDES_LONG(@tin), ks1, ks2, ks3);
            tout0 := tin[0];
            tout1 := tin[1];
            tout0  := tout0 xor xor0;
            tout1  := tout1 xor xor1;
            l2cn(tout0, tout1, _out, l + 8);
            xor0 := t0;
            xor1 := t1;
        end;
        iv := @(ivec^)[0];
        l2c(xor0, iv);
        l2c(xor1, iv);
    end;
    tin0 := 0; tin1 := 0; tout0 := 0; tout1 := 0; xor0 := 0; xor1 := 0;
    tin[0] := 0; tin[1] := 0;
end;

end.
