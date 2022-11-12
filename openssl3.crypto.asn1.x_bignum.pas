unit openssl3.crypto.asn1.x_bignum;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;


  function _bn_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
  function _bn_secure_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
  procedure _bn_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  function bn_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
  function bn_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
  function bn_secure_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
  function _bn_print(_out : PBIO;const pval : PPASN1_VALUE; const it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;

  function BIGNUM_it:PASN1_ITEM;
  function CBIGNUM_it:PASN1_ITEM;

const
   BN_SENSITIVE = 1;
var
   bignum_pf: TASN1_PRIMITIVE_FUNCS = (
    app_data: nil;
    flags:  0;
    prim_new: _bn_new;
    prim_free: _bn_free;
    prim_clear: nil;
    prim_c2i: bn_c2i;
    prim_i2c: bn_i2c;
    prim_print: _bn_print
);
   cbignum_pf: TASN1_PRIMITIVE_FUNCS = (
    app_data: nil;
    flags:  0;
    prim_new: _bn_secure_new;
    prim_free: _bn_free;
    prim_clear: nil;
    prim_c2i: bn_secure_c2i;
    prim_i2c: bn_i2c;
    prim_print: _bn_print
);

implementation
uses openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_print,
      openssl3.crypto.bio.bio_lib;






function CBIGNUM_it:PASN1_ITEM;
const
     local_it: TASN1_ITEM  = (
        itype: $0;
        utype: 2;
        templates:  Pointer(0) ;
        tcount:  0;
        funcs: @cbignum_pf;
        size: 1;
        sname: 'CBIGNUM'
     );
begin
  result := @local_it;
end;

function _bn_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
begin
    pval^ := PASN1_VALUE( BN_new);
    if pval^ <> nil then
       Exit(1)
    else
        Result := 0;
end;


function _bn_secure_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
begin
    pval^ := PASN1_VALUE( BN_secure_new);
    if pval^ <> nil then
       Exit(1)
    else
        Result := 0;
end;


procedure _bn_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    if pval^ = nil then Exit;
    if (it.size and BN_SENSITIVE) > 0 then
       BN_clear_free(PBIGNUM(pval^))
    else
        BN_free(PBIGNUM(pval^));
    pval^ := nil;
end;


function bn_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
var
  bn : PBIGNUM;

  pad : integer;
begin
    if pval^ = nil then
       Exit(-1);
    bn := PBIGNUM(pval^);
    { If MSB set in an octet we need a padding byte }
    if (BN_num_bits(bn) and $7) > 0  then
        pad := 0
    else
        pad := 1;
    if cont <> nil then
    begin
        if pad > 0 then
            PostInc(cont)^ :=  0;
        BN_bn2bin(bn, cont);
    end;
    Result := pad + BN_num_bytes(bn);
end;


function bn_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
var
  bn : PBIGNUM;
begin
    if (pval^ = nil)  and  (0>= _bn_new(pval, it)) then
        Exit(0);
    bn := PBIGNUM(pval^);
    if nil = BN_bin2bn(cont, len, bn ) then
    begin
        _bn_free(pval, it);
        Exit(0);
    end;
    Result := 1;
end;


function bn_secure_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
var
  ret : integer;

  bn : PBIGNUM;
begin
    if (pval^ = nil)  and  (0>= _bn_secure_new(pval, it)) then
        Exit(0);
    ret := bn_c2i(pval, cont, len, utype, free_cont, it);
    if 0>= ret then Exit(0);
    { Set constant-time flag for all secure BIGNUMS }
    bn := PBIGNUM(pval^);
    BN_set_flags(bn, BN_FLG_CONSTTIME);
    Result := ret;
end;


function _bn_print(_out : PBIO;const pval : PPASN1_VALUE; const it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;
begin
    if 0>= BN_print(_out, PPBIGNUM( pval)^ )   then
        Exit(0);
    if BIO_puts(_out, #10) <= 0  then
        Exit(0);
    Result := 1;
end;



function BIGNUM_it:PASN1_ITEM;
const
   local_it: TASN1_ITEM  = (
        itype: $0;
        utype:  2;
        templates:  Pointer(0) ;
        tcount:  0;
        funcs:  @bignum_pf;
        size:  0;
        sname:  'BIGNUM'
 );

begin
  Result := @local_it;
end;


end.
