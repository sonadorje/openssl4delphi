unit openssl3.crypto.ec.curve448.scalar;

interface
uses OpenSSL.Api;

const
    C448_SCALAR_BYTES = 56;
    C448_SCALAR_LIMBS = ((446-1) div C448_WORD_BITS+1);
    C448_SCALAR_BITS = 446;
    WBITS = C448_WORD_BITS ;
    MONTGOMERY_FACTOR: c448_word_t = c448_word_t( $3bd440fae918bc5);//ULL


procedure ossl_curve448_scalar_decode_long(s : curve448_scalar_t;const ser : PByte; ser_len : size_t);
procedure curve448_scalar_copy(_out : curve448_scalar_t;const a : curve448_scalar_t);
 procedure scalar_decode_short(s : curve448_scalar_t;const ser : PByte; nbytes : size_t);
procedure ossl_curve448_scalar_mul(&out : curve448_scalar_t;const a, b : curve448_scalar_t);
procedure sc_montmul(&out : curve448_scalar_t;const a, b : curve448_scalar_t);
procedure sc_subx(&_out : curve448_scalar_t;const accum : Pc448_word_t{C448_SCALAR_LIMBS}; sub, p : curve448_scalar_t; extra : c448_word_t);
procedure ossl_curve448_scalar_destroy( scalar : curve448_scalar_t);
procedure ossl_curve448_scalar_add(_out : curve448_scalar_t;const a, b : curve448_scalar_t);
function ossl_curve448_scalar_decode(s : curve448_scalar_t;const ser{C448_SCALAR_BYTES} : PByte):c448_error_t;
procedure ossl_curve448_scalar_halve(_out : curve448_scalar_t;const a : curve448_scalar_t);
 procedure ossl_curve448_scalar_encode(ser : PByte{C448_SCALAR_BYTES};const s : curve448_scalar_t);
 procedure ossl_curve448_scalar_sub(_out : curve448_scalar_t;const a, b : curve448_scalar_t);

var
  sc_p, sc_r2,
  ossl_curve448_scalar_zero,
  ossl_curve448_scalar_one: curve448_scalar_t;

implementation
uses openssl3.crypto.ec.curve448, openssl3.crypto.ec.curve448.arch_32.f_impl,
     openssl3.crypto.mem;





procedure ossl_curve448_scalar_sub(_out : curve448_scalar_t;const a, b : curve448_scalar_t);
begin
    sc_subx(_out, @a[0].limb, b, sc_p, 0);
end;



procedure ossl_curve448_scalar_encode(ser : PByte;const s : curve448_scalar_t);
var
  i, j, k : uint32;
begin
    k := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        for j := 0 to sizeof(c448_word_t)-1 do
        begin
            ser[k] := s[0].limb[i]  shr  (8 * j);
            Inc(k);
        end;
    end;
end;


procedure ossl_curve448_scalar_halve(_out : curve448_scalar_t;const a : curve448_scalar_t);
var
  mask : c448_word_t;

  chain : c448_dword_t;

  i : uint32;
begin
    mask := 0 - (a[0].limb[0] and 1);
    chain := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        chain := (chain + a[0].limb[i]) + (sc_p[0].limb[i] and mask);
        _out[0].limb[i] := c448_word_t( chain);
        chain := chain shr C448_WORD_BITS;
    end;
    for i := 0 to C448_SCALAR_LIMBS - 1-1 do
        _out[0].limb[i] := _out[0].limb[i]  shr  1 or _out[0].limb[i + 1]  shl  (WBITS - 1);
    _out[0].limb[i] := _out[0].limb[i]  shr  1 or c448_word_t( (chain  shl  (WBITS - 1)));
end;



procedure ossl_curve448_scalar_add(_out : curve448_scalar_t;const a, b : curve448_scalar_t);
var
  chain : c448_dword_t;

  i : uint32;
begin
    chain := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        chain := (chain + a[0].limb[i]) + b[0].limb[i];
        _out[0].limb[i] := c448_word_t( chain);
        chain := chain shr WBITS;
    end;
    sc_subx(_out, @_out[0].limb, sc_p, sc_p, c448_word_t( chain));
end;

function ossl_curve448_scalar_decode(s : curve448_scalar_t;const ser{C448_SCALAR_BYTES} : PByte):c448_error_t;
var
  i : uint32;

  accum : c448_dsword_t;
begin
    accum := 0;
    scalar_decode_short(s, ser, C448_SCALAR_BYTES);
    for i := 0 to C448_SCALAR_LIMBS-1 do
        accum := (accum + s[0].limb[i] - sc_p[0].limb[i])  shr  WBITS;
    { Here accum = 0 or -1 }
    ossl_curve448_scalar_mul(s, s, ossl_curve448_scalar_one); { ham-handed reduce }
    Result := c448_succeed_if(not word_is_zero(uint32( accum)));
end;


procedure ossl_curve448_scalar_destroy( scalar : curve448_scalar_t);
var
  p :Pointer;
begin
    p := Addr(scalar);
    OPENSSL_cleanse(p, sizeof(curve448_scalar_t));
end;



procedure sc_subx(&_out : curve448_scalar_t;const accum : Pc448_word_t; sub, p : curve448_scalar_t; extra : c448_word_t);
var
  chain : c448_dsword_t;

  i : uint32;

  borrow : c448_word_t;
begin
{$POINTERMATH ON}
    chain := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        chain := (chain + accum[i]) - sub[0].limb[i];
        _out[0].limb[i] := c448_word_t( chain);
        chain := chain shr WBITS;
    end;
    borrow := c448_word_t( chain) + extra;     { = 0 or -1 }
    chain := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        chain := (chain + _out[0].limb[i]) + (p[0].limb[i] and borrow);
        _out[0].limb[i] := c448_word_t( chain);
        chain := chain shr WBITS;
    end;
{$POINTERMATH OFF}
end;




procedure sc_montmul(&out : curve448_scalar_t;const a, b : curve448_scalar_t);
var
  i,
  j        : uint32;
  accum    : array[0..(C448_SCALAR_LIMBS + 1)-1] of c448_word_t;

  hi_carry,
  mand     : c448_word_t;
  mier     : Pc448_word_t;
  chain    : c448_dword_t;
begin
{$POINTERMATH ON}
    FillChar(accum, C448_SCALAR_LIMBS + 1, 0 );

    hi_carry := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        mand := a[0].limb[i];
        mier := @b[0].limb;
        chain := 0;
        for j := 0 to C448_SCALAR_LIMBS-1 do
        begin
            chain  := chain + ((c448_dword_t(mand)) * mier[j] + accum[j]);
            accum[j] := c448_word_t(chain);
            chain := chain shr WBITS;
        end;
        accum[j] := c448_word_t(chain);
        mand := accum[0] * MONTGOMERY_FACTOR;
        chain := 0;
        mier := @sc_p[0].limb;
        for j := 0 to C448_SCALAR_LIMBS-1 do
        begin
            chain  := chain + (c448_dword_t (mand *mier[j]) + accum[j]);
            if j>0 then
               accum[j - 1] := c448_word_t(chain);
            chain := chain  shr WBITS;
        end;
        chain  := chain + (accum[j]);
        chain  := chain + hi_carry;
        accum[j - 1] := c448_word_t(chain);
        hi_carry := chain  shr  WBITS;
    end;
    sc_subx(&out, @accum, sc_p, sc_p, hi_carry);
{$POINTERMATH OFF}
end;



procedure ossl_curve448_scalar_mul(&out : curve448_scalar_t;const a, b : curve448_scalar_t);
begin
    sc_montmul(&out, a, b);
    sc_montmul(&out, &out, sc_r2);
end;



procedure scalar_decode_short(s : curve448_scalar_t;const ser : PByte; nbytes : size_t);
var
  i, j, k : size_t;

  _out : c448_word_t;
begin
    k := 0;
    for i := 0 to C448_SCALAR_LIMBS-1 do
    begin
        _out := 0;
        j := 0;
        while ( j < sizeof(c448_word_t) ) and  (k < nbytes)do
        begin
            _out  := _out  or ((c448_word_t(ser[k]))  shl  (8 * j));
            Inc(j);Inc(k);
        end;
        s[0].limb[i] := _out;
    end;
end;




procedure curve448_scalar_copy(_out : curve448_scalar_t;const a : curve448_scalar_t);
begin
    _out[0] := a[0];
end;


procedure ossl_curve448_scalar_decode_long(s : curve448_scalar_t;const ser : PByte; ser_len : size_t);
var
  i : size_t;

  t1, t2 : curve448_scalar_t;
begin
    if ser_len = 0 then begin
        curve448_scalar_copy(s, ossl_curve448_scalar_zero);
        exit;
    end;
    i := ser_len - (ser_len mod C448_SCALAR_BYTES);
    if i = ser_len then
       i  := i - C448_SCALAR_BYTES;
    scalar_decode_short(t1, @ser[i], ser_len - i);
    if ser_len = sizeof(curve448_scalar_t) then
    begin
        assert(i = 0);
        { ham-handed reduce }
        ossl_curve448_scalar_mul(s, t1, ossl_curve448_scalar_one);
        ossl_curve448_scalar_destroy(t1);
        exit;
    end;
    while i>0 do
    begin
        i  := i - C448_SCALAR_BYTES;
        sc_montmul(t1, t1, sc_r2);
        ossl_curve448_scalar_decode(t2, ser + i);
        ossl_curve448_scalar_add(t1, t1, t2);
    end;
    curve448_scalar_copy(s, t1);
    ossl_curve448_scalar_destroy(t1);
    ossl_curve448_scalar_destroy(t2);
end;

initialization
  Fillchar(ossl_curve448_scalar_zero, SizeOf(ossl_curve448_scalar_zero) ,0);
  FillChar(ossl_curve448_scalar_one, SizeOf( ossl_curve448_scalar_one), 1);
  sc_p[0].limb[0] := SC_LIMB1($2378c292ab5844f3);
  sc_p[0].limb[1] := SC_LIMB2($2378c292ab5844f3);

  sc_p[0].limb[2] := SC_LIMB1($216cc2728dc58f55);
  sc_p[0].limb[3] := SC_LIMB2($216cc2728dc58f55);

  sc_p[0].limb[4] := SC_LIMB1($c44edb49aed63690);
  sc_p[0].limb[5] := SC_LIMB2($c44edb49aed63690);
  sc_p[0].limb[6] := SC_LIMB1($ffffffff7cca23e9);
  sc_p[0].limb[7] := SC_LIMB2($ffffffff7cca23e9);
  sc_p[0].limb[8] := SC_LIMB1($ffffffffffffffff);
  sc_p[0].limb[9] := SC_LIMB2($ffffffffffffffff);
  sc_p[0].limb[10] := SC_LIMB1($ffffffffffffffff);
  sc_p[0].limb[11] := SC_LIMB2($ffffffffffffffff);
  sc_p[0].limb[12] := SC_LIMB1($3fffffffffffffff);
  sc_p[0].limb[13] := SC_LIMB2($ffffffffffffffff);
  sc_r2[0].limb[0] := SC_LIMB1($e3539257049b9b60);
  sc_r2[0].limb[1] := SC_LIMB2($e3539257049b9b60);
  sc_r2[0].limb[2] := SC_LIMB1($7af32c4bc1b195d9);
  sc_r2[0].limb[3] := SC_LIMB2($7af32c4bc1b195d9);
  sc_r2[0].limb[4] := SC_LIMB1($0d66de2388ea1859);
  sc_r2[0].limb[5] := SC_LIMB2($0d66de2388ea1859);
  sc_r2[0].limb[6] := SC_LIMB1($ae17cf725ee4d838);
  sc_r2[0].limb[7] := SC_LIMB2($ae17cf725ee4d838);
  sc_r2[0].limb[8] := SC_LIMB1($1a9cc14ba3c47c44);
  sc_r2[0].limb[9] := SC_LIMB2($1a9cc14ba3c47c44);
  sc_r2[0].limb[10] := SC_LIMB1($2052bcb7e4d070af);
  sc_r2[0].limb[11] := SC_LIMB2($2052bcb7e4d070af);
  sc_r2[0].limb[12] := SC_LIMB1($3402a939f823b729);
  sc_r2[0].limb[13] := SC_LIMB2($3402a939f823b729)
end.
