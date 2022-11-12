unit openssl3.crypto.ec.curve448;

interface
uses OpenSSL.Api, Variants;




const
   COFACTOR = 4;
   EDWARDS_D   =    (-39081);
   TWISTED_D = (EDWARDS_D - 1);
   EDDSA_448_PUBLIC_BYTES = 57;
   EDDSA_448_PRIVATE_BYTES = EDDSA_448_PUBLIC_BYTES;
   C448_WNAF_FIXED_TABLE_BITS = 5;
   C448_WNAF_VAR_TABLE_BITS = 3;

function ossl_x448(out_shared_key : PByte;const private_key, peer_public_value : PByte):integer;
procedure gf_invert(y : Tgf;const x : Tgf; assert_nonzero : integer);

function ossl_x448_int(_out : PByte;const base, scalar : PByte):c448_error_t;
 function c448_succeed_if( x : c448_bool_t):c448_error_t;
 function mask_to_bool( m : mask_t):c448_bool_t;
 procedure ossl_curve448_precomputed_scalarmul(_out : curve448_point_t;const table : Pcurve448_precomputed_s; scalar : curve448_scalar_t);
 procedure point_double_internal(p : curve448_point_t;const q : curve448_point_t; before_double : integer);
 procedure constant_time_lookup_niels(ni : Pniels_s;const table : Pniels_t; nelts, idx : integer);
 procedure cond_neg_niels( n : niels_t; neg : mask_t);
  procedure add_niels_to_pt(d : curve448_point_t;const e : niels_t; before_double : integer);
 procedure niels_to_pt(e : curve448_point_t;const n : niels_t);
 procedure ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(enc{EDDSA_448_PUBLIC_BYTES} : Pbyte;const p : curve448_point_t);
 procedure curve448_point_copy(var a : curve448_point_t;const b : curve448_point_t);
 procedure ossl_curve448_point_destroy( point : curve448_point_t);
  function ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(p : curve448_point_t;const enc{57} : Pbyte):c448_error_t;
  function ossl_curve448_point_valid(const p : curve448_point_t):c448_bool_t;
   procedure ossl_curve448_base_double_scalarmul_non_secret(combo : curve448_point_t;const scalar1 : curve448_scalar_t; base2 : curve448_point_t; scalar2 : curve448_scalar_t);
    function numtrailingzeros( i : uint32):uint32;
    procedure prepare_wnaf_table(output : Ppniels;const working : curve448_point_t; tbits : uint32);
   procedure pt_to_pniels(b : Tpniels;const a : curve448_point_t);
   procedure ossl_curve448_point_double(p : curve448_point_t;const q : curve448_point_t);
    procedure add_pniels_to_pt(p : curve448_point_t;const pn : Tpniels; before_double : integer);
   procedure pniels_to_pt(e : curve448_point_t;const d : Tpniels);
   procedure sub_pniels_from_pt(p : curve448_point_t;const pn : Tpniels; before_double : integer);
   procedure sub_niels_from_pt(d : curve448_point_t;const e : niels_t; before_double : integer);
   function ossl_curve448_point_eq(const p, q : curve448_point_t):c448_bool_t;
    procedure ossl_x448_public_from_private(out_public_value : Pbyte;const private_key : Pbyte);
    procedure ossl_x448_derive_public_key(_out : Pbyte;const scalar : Pbyte);
   procedure ossl_curve448_point_mul_by_ratio_and_encode_like_x448(_out : Pbyte;const p : curve448_point_t);


var
  precomputed_scalarmul_adjustment: curve448_scalar_t ;
  ossl_curve448_point_identity: curve448_point_t;

implementation
uses
{$IF ARCH_WORD_BITS = 32}
   openssl3.crypto.ec.curve448.arch_32.f_impl,
{$endif} openssl3.crypto.ec.curve448.curve448_tables,
  openssl3.crypto.mem,
  openssl3.crypto.ec.curve448.f_generic,openssl3.crypto.ec.curve448.field ,
  openssl3.crypto.ec.curve448.scalar, openssl3.internal.constant_time;




procedure ossl_curve448_point_mul_by_ratio_and_encode_like_x448(_out : Pbyte;const p : curve448_point_t);
var
  q : curve448_point_t;
begin
    curve448_point_copy(q, p);
    gf_invert(q[0].t, q[0].x, 0);   { 1/x }
    gf_mul(@q[0].z, q[0].t, q[0].y);   { y/x }
    gf_sqr(@q[0].y, q[0].z);         { (y/x)^2 }
    gf_serialize(_out, q[0].y, 1);
    ossl_curve448_point_destroy(q);
end;


procedure ossl_x448_derive_public_key(_out : Pbyte;const scalar : Pbyte);
var
    scalar2    : array[0..X_PRIVATE_BYTES-1] of byte;
    the_scalar : curve448_scalar_t;
    p          : curve448_point_t;
    i          : uint32;
begin
    { Scalar conditioning }
    memcpy(@scalar2, scalar, sizeof(scalar2));
    scalar2[0] := scalar2[0] and (- uint8( COFACTOR));
    scalar2[X_PRIVATE_BYTES - 1] := scalar2[X_PRIVATE_BYTES - 1] and  not ((0 - 1)  shl  ((X_PRIVATE_BITS + 7) mod 8)) ;
    scalar2[X_PRIVATE_BYTES - 1] := scalar2[X_PRIVATE_BYTES - 1]  or (1  shl  ((X_PRIVATE_BITS + 7) mod 8));
    ossl_curve448_scalar_decode_long(the_scalar, @scalar2, sizeof(scalar2));
    { Compensate for the encoding ratio }
    i := 1;
    while i < X448_ENCODE_RATIO do
    begin
        ossl_curve448_scalar_halve(the_scalar, the_scalar);
        i := i shl  1;
    end;
    ossl_curve448_precomputed_scalarmul(p, ossl_curve448_precomputed_base,
                                        the_scalar);
    ossl_curve448_point_mul_by_ratio_and_encode_like_x448(_out, p);
    ossl_curve448_point_destroy(p);
end;



procedure ossl_x448_public_from_private(out_public_value : Pbyte;const private_key : Pbyte);
begin
    ossl_x448_derive_public_key(out_public_value, private_key);
end;


function ossl_curve448_point_eq(const p, q : curve448_point_t):c448_bool_t;
var
  succ : mask_t;

  a, b : Tgf;
begin
    { equality mod 2-torsion compares x/y }
    gf_mul(@a, p[0].y, q[0].x);
    gf_mul(@b, q[0].y, p[0].x);
    succ := gf_eq(a, b);
    Result := mask_to_bool(succ);
end;

procedure sub_niels_from_pt(d : curve448_point_t;const e : niels_t; before_double : integer);
var
  a, b, c : Tgf;
begin
    gf_sub_nr(b, d[0].y, d[0].x);   { 3+e }
    gf_mul(@a[0], e[0].b, b);
    gf_add_nr(b, d[0].x, d[0].y);   { 2+e }
    gf_mul(@d[0].y, e[0].a, b);
    gf_mul(@d[0].x, e[0].c, d[0].t);
    gf_add_nr(c, a, d[0].y);      { 2+e }
    gf_sub_nr(b, d[0].y, a);      { 3+e }
    gf_add_nr(d[0].y, d[0].z, d[0].x); { 2+e }
    gf_sub_nr(a, d[0].z, d[0].x);   { 3+e }
    gf_mul(@d[0].z, a, d[0].y);
    gf_mul(@d[0].x, d[0].y, b);
    gf_mul(@d[0].y, a, c);
    if 0>= before_double then
       gf_mul(@d[0].t, b, c);
end;


procedure sub_pniels_from_pt(p : curve448_point_t;const pn : Tpniels; before_double : integer);
var
  L0 : Tgf;
begin
    gf_mul(@L0, p[0].z, pn[0].z);
    gf_copy(p[0].z, L0);
    sub_niels_from_pt(p, pn[0].n, before_double);
end;

procedure pniels_to_pt(e : curve448_point_t;const d : Tpniels);
var
  eu : Tgf;
begin
    gf_add(eu, d[0].n[0].b, d[0].n[0].a);
    gf_sub(e[0].y, d[0].n[0].b, d[0].n[0].a);
    gf_mul(@e[0].t, e[0].y, eu);
    gf_mul(@e[0].x, d[0].z, e[0].y);
    gf_mul(@e[0].y, d[0].z, eu);
    gf_sqr(@e[0].z, d[0].z);
end;




procedure add_pniels_to_pt(p : curve448_point_t;const pn : Tpniels; before_double : integer);
var
  L0 : Tgf;
begin
    gf_mul(@L0, p[0].z, pn[0].z);
    gf_copy(p[0].z, L0);
    add_niels_to_pt(p, pn[0].n, before_double);
end;



procedure ossl_curve448_point_double(p : curve448_point_t;const q : curve448_point_t);
begin
    point_double_internal(p, q, 0);
end;





procedure pt_to_pniels(b : Tpniels;const a : curve448_point_t);
begin
    gf_sub(b[0].n[0].a, a[0].y, a[0].x);
    gf_add(b[0].n[0].b, a[0].x, a[0].y);
    gf_mulw(b[0].n[0].c, a[0].t, 2 * TWISTED_D);
    gf_add(b[0].z, a[0].z, a[0].z);
end;


procedure prepare_wnaf_table(output : Ppniels;const working : curve448_point_t; tbits : uint32);
var
  tmp : curve448_point_t;
  i : integer;
  twop : Tpniels;
  p: Pointer;
begin
{$POINTERMATH ON}

    pt_to_pniels( (output+0)^, working);
    //pt_to_pniels( output^[0], working);
    if tbits = 0 then exit;
    ossl_curve448_point_double(tmp, working);
    pt_to_pniels(twop, tmp);
    add_pniels_to_pt(tmp, (output+0)^, 0);
    pt_to_pniels( (output+1)^, tmp);
    for i := 2 to 1  shl  tbits-1 do
    begin
        add_pniels_to_pt(tmp, twop, 0);
        pt_to_pniels( (output+i)^, tmp);
    end;
    ossl_curve448_point_destroy(tmp);
    p := Addr(twop);
    OPENSSL_cleanse(p, sizeof(twop));
{$POINTERMATH ON}
end;


function numtrailingzeros( i : uint32):uint32;
var
  tmp, num : uint32;
begin
    num := 31;
    if i = 0 then Exit(32);
    tmp := i  shl  16;
    if tmp <> 0 then
    begin
        i := tmp;
        num  := num - 16;
    end;
    tmp := i  shl  8;
    if tmp <> 0 then
    begin
        i := tmp;
        num  := num - 8;
    end;
    tmp := i  shl  4;
    if tmp <> 0 then
    begin
        i := tmp;
        num  := num - 4;
    end;
    tmp := i  shl  2;
    if tmp <> 0 then
    begin
        i := tmp;
        num  := num - 2;
    end;
    tmp := i  shl  1;
    if tmp <> 0 then
       Dec(num);
    Result := num;
end;

function recode_wnaf(control : Psmvt_control;const scalar : curve448_scalar_t; table_bits : uint32):integer;
var
  table_size : uint32;
  position   : integer;
  current    : uint64;
  mask,
  w,
  B_OVER_16  : uint32;
  n,
  i,
  pos,
  odd        : uint32;
  delta      : integer;
begin
{$POINTERMATH ON}
    table_size := C448_SCALAR_BITS div (table_bits + 1) + 3;
    position := table_size - 1;
    B_OVER_16  := sizeof(scalar[0].limb[0]) div 2;
    current := scalar[0].limb[0] and $FFFF;
    mask := (1  shl  (table_bits + 1)) - 1;
    { place the end marker }
    control[position].power := -1;
    control[position].addend := 0;
    Dec(position);
    {
     * PERF: Could negate scalar if it's large.  But then would need more cases
     * in the actual code that uses it, all for an expected reduction of like
     * 1/5 op. Probably not worth it.
     }
    for w := 1 to (C448_SCALAR_BITS - 1) div 16 + 3-1 do
    begin
        if w < (C448_SCALAR_BITS - 1 div 16 + 1) then
        begin
            { Refill the 16 high bits of current }
            current := current + uint32( ((scalar[0].limb[w div B_OVER_16]
                        shr  (16 * (w mod B_OVER_16)))  shl  16));
        end;
        while (current and $FFFF)>0 do
        begin
            pos := NUMTRAILINGZEROS(uint32( current));
            odd := uint32( current  shr  pos);
            delta := odd and mask;
            assert(position >= 0);
            if (odd and (1  shl  (table_bits + 1)))>0  then
                delta  := delta - ((1  shl  (table_bits + 1)));
            current  := current - (delta * (1  shl  pos));
            control[position].power := pos + 16 * (w - 1);
            control[position].addend := delta;
            Dec(position);
        end;
        current := current shr 16;
    end;
    assert(current = 0);
    Inc(position);
    n := table_size - position;
    for i := 0 to n-1 do
        control[i] := control[i + position];
    Result := n - 1;
{$POINTERMATH OFF}
end;




procedure ossl_curve448_base_double_scalarmul_non_secret(combo : curve448_point_t;const scalar1 : curve448_scalar_t; base2 : curve448_point_t; scalar2 : curve448_scalar_t);
var
  table_bits_var,
  table_bits_pre,
  ncb_pre,
  ncb_var        : integer;
  precmp_var     : array[0..(1 shl C448_WNAF_VAR_TABLE_BITS)-1] of Tpniels;
  contp, contv, i:int;
  p: Pointer;
  cv,
  cp             : integer;
  control_var: array[0..C448_SCALAR_BITS div (C448_WNAF_VAR_TABLE_BITS + 1) + 3-1] of Tsmvt_control;
  control_pre: array[0..C448_SCALAR_BITS div (C448_WNAF_FIXED_TABLE_BITS + 1) + 3-1] of Tsmvt_control;
begin
{$POINTERMATH ON}
     table_bits_var := C448_WNAF_VAR_TABLE_BITS;
     table_bits_pre := C448_WNAF_FIXED_TABLE_BITS;


    ncb_pre := recode_wnaf(@control_pre, scalar1, table_bits_pre);
    ncb_var := recode_wnaf(@control_var, scalar2, table_bits_var);
    contp := 0; contv := 0;
    prepare_wnaf_table(@precmp_var, base2, table_bits_var);
    i := control_var[0].power;
    if i < 0 then
    begin
        curve448_point_copy(combo, ossl_curve448_point_identity);
        exit;
    end;
    if i > control_pre[0].power then
    begin
        pniels_to_pt(combo, precmp_var[control_var[0].addend  shr  1]);
        PostInc(contv);
    end
    else
    if (i = control_pre[0].power)  and  (i >= 0) then
    begin
        pniels_to_pt(combo, precmp_var[control_var[0].addend  shr  1]);
        add_niels_to_pt(combo,
              (ossl_curve448_wnaf_base + (control_pre[0].addend  shr  1))^, i);
        Inc(contv);
        Inc(contp);
    end
    else
    begin
        i := control_pre[0].power;
        niels_to_pt(combo, (ossl_curve448_wnaf_base + (control_pre[0].addend  shr  1))^ );
        Inc(contp);
    end;
    Dec(i);
    while ( i >= 0) do
    begin
        cv := int(i = control_var[contv].power);
        cp := int(i = control_pre[contp].power);
        point_double_internal(combo, combo, int( (i>0)  and  (0>= (cv  or  cp)) ));
        if cv>0 then
        begin
            assert(control_var[contv].addend>0);
            if control_var[contv].addend > 0 then
               add_pniels_to_pt(combo, precmp_var[control_var[contv].addend  shr  1],
                                 int((i>0)  and  (0>= cp)))
            else
                sub_pniels_from_pt(combo,
                                   precmp_var[(-control_var[contv].addend)
                                               shr  1], int((i>0)  and  (0>= cp)));
            Inc(contv);
        end;
        if cp>0 then
        begin
            assert(control_pre[contp].addend>0);
            if control_pre[contp].addend > 0 then
               add_niels_to_pt(combo,
                       (ossl_curve448_wnaf_base + (control_pre[contp].addend
                                                    shr  1))^, i)
            else
               sub_niels_from_pt(combo,
                      (ossl_curve448_wnaf_base + ((-control_pre[contp].addend)  shr  1))^, i);
            PostInc(contp);
        end;
        Dec(i);
    end;
    { This function is non-secret, but whatever this is cheap. }
    p := @control_var;
    OPENSSL_cleanse(p, sizeof(control_var));
    p := @control_pre;
    OPENSSL_cleanse(p, sizeof(control_pre));
    p := @precmp_var;
    OPENSSL_cleanse(p, sizeof(precmp_var));
    assert(contv = ncb_var);
    ncb_var := NULL;
    assert(contp = ncb_pre);
    ncb_pre := NULL;
{$POINTERMATH OFF}
end;




function ossl_curve448_point_valid(const p : curve448_point_t):c448_bool_t;
var
  _out : mask_t;

  a, b, c : Tgf;
begin
    gf_mul(@a, p[0].x, p[0].y);
    gf_mul(@b, p[0].z, p[0].t);
    _out := gf_eq(a, b);
    gf_sqr(@a, p[0].x);
    gf_sqr(@b, p[0].y);
    gf_sub(a, b, a);
    gf_sqr(@b, p[0].t);
    gf_mulw(c, b, TWISTED_D);
    gf_sqr(@b, p[0].z);
    gf_add(b, b, c);
    _out := _out and gf_eq(a, b);
    _out := _out and (not gf_eq(p[0].z, ZERO));
    Result := mask_to_bool(_out);
end;





function ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(p : curve448_point_t;const enc : Pbyte):c448_error_t;
var
  enc2 : array[0..(EDDSA_448_PUBLIC_BYTES)-1] of byte;
  low, succ, ok : mask_t;
  a, b, c, d : Tgf;
  p1: Pgf_s;
  pb: PByte;
begin
    memcpy(@enc2, enc, sizeof(enc2));
    low := not word_is_zero(enc2[EDDSA_448_PRIVATE_BYTES - 1] and $80);
    enc2[EDDSA_448_PRIVATE_BYTES - 1] := enc2[EDDSA_448_PRIVATE_BYTES - 1] and (not $80);
    succ := gf_deserialize(p[0].y, @enc2, 1, 0);
    succ := succ and word_is_zero(enc2[EDDSA_448_PRIVATE_BYTES - 1]);
    gf_sqr(@p[0].x, p[0].y);
    gf_sub(p[0].z, ONE, p[0].x);    { num = 1-y^2 }
    gf_mulw(p[0].t, p[0].x, EDWARDS_D); { dy^2 }
    gf_sub(p[0].t, ONE, p[0].t);    { denom = 1-dy^2 or 1-d + dy^2 }
    gf_mul(@p[0].x, p[0].z, p[0].t);
    succ := succ and gf_isr(p[0].t, p[0].x); { 1/sqrt(num * denom) }
    gf_mul(@p[0].x, p[0].t, p[0].z);   { sqrt(num / denom) }
    gf_cond_neg(p[0].x, gf_lobit(p[0].x)  xor  low);
    gf_copy(p[0].z, ONE);
    begin
        { 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) }
        gf_sqr(@c, p[0].x);
        gf_sqr(@a, p[0].y);
        gf_add(d, c, a);
        gf_add(p[0].t, p[0].y, p[0].x);
        gf_sqr(@b, p[0].t);
        gf_sub(b, b, d);
        gf_sub(p[0].t, a, c);
        gf_sqr(@p[0].x, p[0].z);
        gf_add(p[0].z, p[0].x, p[0].x);
        gf_sub(a, p[0].z, d);
        gf_mul(@p[0].x, a, b);
        gf_mul(@p[0].z, p[0].t, a);
        gf_mul(@p[0].y, p[0].t, d);
        gf_mul(@p[0].t, b, d);
        p1 := @a;
        OPENSSL_cleanse(Pointer(p1), sizeof(a));
        p1 := @b;
        OPENSSL_cleanse(Pointer(p1), sizeof(b));
        p1 := @c;
        OPENSSL_cleanse(Pointer(p1), sizeof(c));
        p1 := @d;
        OPENSSL_cleanse(Pointer(p1), sizeof(d));
    end;
    pb := @enc2;
    OPENSSL_cleanse(Pointer(pb), sizeof(enc2));
    ok := not succ;
    assert( (ossl_curve448_point_valid(p)>0)  or  (ok>0));
    Result := c448_succeed_if(mask_to_bool(succ));
end;





procedure ossl_curve448_point_destroy( point : curve448_point_t);
var
  p: Pcurve448_point_t;
begin
    p := @point;
    OPENSSL_cleanse(Pointer(p), sizeof(curve448_point_t));
end;



procedure curve448_point_copy(var a : curve448_point_t;const b : curve448_point_t);
begin
    a[0] := b[0];
end;




procedure ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(enc : Pbyte;const p : curve448_point_t);
var
  x, y, z, t : Tgf;
  q : curve448_point_t;
  u : Tgf;
  p1: Pgf_s;
begin
    { The point is now on the twisted curve.  Move it to untwisted. }
    curve448_point_copy(q, p);
    begin
        { 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) }
        gf_sqr(@x, q[0].x);
        gf_sqr(@t, q[0].y);
        gf_add(u, x, t);
        gf_add(z, q[0].y, q[0].x);
        gf_sqr(@y, z);
        gf_sub(y, y, u);
        gf_sub(z, t, x);
        gf_sqr(@x, q[0].z);
        gf_add(t, x, x);
        gf_sub(t, t, z);
        gf_mul(@x, t, y);
        gf_mul(@y, z, u);
        gf_mul(@z, u, t);
        p1 := @u;
        OPENSSL_cleanse(Pointer(p1), sizeof(u));
    end;
    { Affinize }
    gf_invert(z, z, 1);
    gf_mul(@t, x, z);
    gf_mul(@x, y, z);
    { Encode }
    enc[EDDSA_448_PRIVATE_BYTES - 1] := 0;
    gf_serialize(enc, x, 1);
    enc[EDDSA_448_PRIVATE_BYTES - 1]  := enc[EDDSA_448_PRIVATE_BYTES - 1]  or ($80 and gf_lobit(t));
    p1 := @x ;
    OPENSSL_cleanse(Pointer(p1), sizeof(x));
    p1 := @y;
    OPENSSL_cleanse(Pointer(p1), sizeof(y));
    p1 := @z;
    OPENSSL_cleanse(Pointer(p1), sizeof(z));
    p1 := @t;
    OPENSSL_cleanse(Pointer(p1), sizeof(t));
    ossl_curve448_point_destroy(q);
end;





procedure niels_to_pt(e : curve448_point_t;const n : niels_t);
begin
    gf_add(e[0].y, n[0].b, n[0].a);
    gf_sub(e[0].x, n[0].b, n[0].a);
    gf_mul(@e[0].t, e[0].y, e[0].x);
    gf_copy(e[0].z, ONE);
end;



procedure add_niels_to_pt(d : curve448_point_t;const e : niels_t; before_double : integer);
var
  a, b, c : Tgf;
begin
    gf_sub_nr(b, d[0].y, d[0].x);   { 3+e }
    gf_mul(@a, e[0].a, b);
    gf_add_nr(b, d[0].x, d[0].y);   { 2+e }
    gf_mul(@d[0].y, e[0].b, b);
    gf_mul(@d[0].x, e[0].c, d[0].t);
    gf_add_nr(c, a, d[0].y);      { 2+e }
    gf_sub_nr(b, d[0].y, a);      { 3+e }
    gf_sub_nr(d[0].y, d[0].z, d[0].x); { 3+e }
    gf_add_nr(a, d[0].x, d[0].z);   { 2+e }
    gf_mul(@d[0].z, a, d[0].y);
    gf_mul(@d[0].x, d[0].y, b);
    gf_mul(@d[0].y, a, c);
    if 0>= before_double then
       gf_mul(@d[0].t, b, c);
end;






procedure cond_neg_niels( n : niels_t; neg : mask_t);
begin
    gf_cond_swap(n[0].a, @n[0].b, neg);
    gf_cond_neg(n[0].c, neg);
end;




procedure constant_time_lookup_niels(ni : Pniels_s;const table : Pniels_t; nelts, idx : integer);
begin
    constant_time_lookup(ni, table, sizeof(niels_st), nelts, idx);
end;



procedure point_double_internal(p : curve448_point_t;const q : curve448_point_t; before_double : integer);
var
  a, b, c, d : Tgf;
begin
    gf_sqr(@c, q[0].x);
    gf_sqr(@a, q[0].y);
    gf_add_nr(d, c, a);         { 2+e }
    gf_add_nr(p[0].t, q[0].y, q[0].x); { 2+e }
    gf_sqr(@b, p[0].t);
    gf_subx_nr(b, b, d, 3);     { 4+e }
    gf_sub_nr(p[0].t, a, c);      { 3+e }
    gf_sqr(@p[0].x, q[0].z);
    gf_add_nr(p[0].z, p[0].x, p[0].x); { 2+e }
    gf_subx_nr(a, p[0].z, p[0].t, 4); { 6+e }
    if GF_HEADROOM = 5 then
       gf_weak_reduce(a);      { or 1+e }
    gf_mul(@p[0].x, a, b);
    gf_mul(@p[0].z, p[0].t, a);
    gf_mul(@p[0].y, p[0].t, d);
    if 0>= before_double then
       gf_mul(@p[0].t, b, d);
end;





procedure ossl_curve448_precomputed_scalarmul(_out : curve448_point_t;const table : Pcurve448_precomputed_s; scalar : curve448_scalar_t);
var
  i,  j,   k,
  n,t,s        : uint32;
  p1: Pniels_t;
  ni       : niels_t;
  scalar1x : curve448_scalar_t;
  p2: Pcurve448_scalar_t;
  tab      : integer;
  invert   : mask_t;
  bit      : uint32;
begin
    n := COMBS_N; t := COMBS_T; s := COMBS_S;
    ossl_curve448_scalar_add(scalar1x, scalar, precomputed_scalarmul_adjustment);
    ossl_curve448_scalar_halve(scalar1x, scalar1x);
    i := s;
    while ( i > 0) do
    begin
        if i <> s then point_double_internal(_out, _out, 0);
        for j := 0 to n-1 do
        begin
            tab := 0;
            for k := 0 to t-1 do
            begin
                bit := (i - 1) + s * (k + j * t);
                if bit < C448_SCALAR_BITS then
                    tab := tab or
                        (scalar1x[0].limb[bit div WBITS]  shr  (bit mod WBITS) and 1)  shl  k;
            end;
            invert := (tab  shr  (t - 1)) - 1;
            tab  := tab xor invert;
            tab := tab and (1  shl  (t - 1)) - 1;
            constant_time_lookup_niels(@ni, @table.table[j  shl  (t - 1)],
                                       1  shl  (t - 1), tab);
            cond_neg_niels(ni, invert);
            if (i <> s)   or  (j <> 0) then
                add_niels_to_pt(_out, ni, Int( (j = n - 1)  and  (i <> 1) ))
            else
                niels_to_pt(_out, ni);
        end;
        Dec(i);
    end;
    p1 := @ni;
    OPENSSL_cleanse(Pointer(p1), sizeof(ni));
    p2 := @scalar1x;
    OPENSSL_cleanse(Pointer(p2), sizeof(scalar1x));
end;


function mask_to_bool( m : mask_t):c448_bool_t;
begin
    Result := c448_sword_t(sword_t(m));
end;


function c448_succeed_if( x : c448_bool_t):c448_error_t;
begin
    Result := c448_error_t( x);
end;





procedure gf_invert(y : Tgf;const x : Tgf; assert_nonzero : integer);
var
  ret : mask_t;

  t1, t2 : Tgf;
begin
    gf_sqr(@t1, x);              { o^2 }
    ret := gf_isr(t2, t1);       { +-1/sqrt(o^2) = +-1/o }
    //(void)ret;
    if assert_nonzero>0 then
       assert(ret>0);
    gf_sqr(@t1, t2);
    gf_mul(@t2, t1, x);          { not direct to y in case of alias. }
    gf_copy(y, t2);
end;

function ossl_x448_int(_out : PByte;const base, scalar : PByte):c448_error_t;
var
  x1, x2, z2, x3, z3, t1, t2 : Tgf;
  t : integer;
  swap, nz : mask_t;
  sb : int8;
  k_t : mask_t;
begin
    swap := 0;
    gf_deserialize(x1, base, 1, 0);
    gf_copy(x2, ONE);
    gf_copy(z2, ZERO);
    gf_copy(x3, x1);
    gf_copy(z3, ONE);
    for t := X_PRIVATE_BITS - 1  downto 0 do
    begin
        sb := scalar[t div 8];
        { Scalar conditioning }
        if t div 8 = 0 then
           sb := sb and ( - uint8( COFACTOR))
        else
        if (t = X_PRIVATE_BITS - 1) then
            sb := -1;
        k_t := (sb  shr  (t mod 8)) and 1;
        k_t := 0 - k_t;             { set to all 0s or all 1s }
        swap  := swap xor k_t;
        gf_cond_swap(x2, @x3, swap);
        gf_cond_swap(z2, @z3, swap);
        swap := k_t;
        {
         * The '_nr' below skips coefficient reduction. In the following
         * comments, '2+e' is saying that the coefficients are at most 2+epsilon
         * times the reduction limit.
         }
        gf_add_nr(t1, x2, z2);  { A = x2 + z2 }
 { 2+e }
        gf_sub_nr(t2, x2, z2);  { B = x2 - z2 }
 { 3+e }
        gf_sub_nr(z2, x3, z3);  { D = x3 - z3 }
 { 3+e }
        gf_mul(@x2, t1, z2);     { DA }
        gf_add_nr(z2, z3, x3);  { C = x3 + z3 }
 { 2+e }
        gf_mul(@x3, t2, z2);     { CB }
        gf_sub_nr(z3, x2, x3);  { DA-CB }
 { 3+e }
        gf_sqr(@z2, z3);         { (DA-CB)^2 }
        gf_mul(@z3, x1, z2);     { z3 = x1(DA-CB)^2 }
        gf_add_nr(z2, x2, x3);  { (DA+CB) }
 { 2+e }
        gf_sqr(@x3, z2);         { x3 = (DA+CB)^2 }
        gf_sqr(@z2, t1);         { AA = A^2 }
        gf_sqr(@t1, t2);         { BB = B^2 }
        gf_mul(@x2, z2, t1);     { x2 = AA*BB }
        gf_sub_nr(t2, z2, t1);  { E = AA-BB }
 { 3+e }
        gf_mulw(t1, t2, -EDWARDS_D); { E*-d = a24*E }
        gf_add_nr(t1, t1, z2);  { AA + a24*E }
 { 2+e }
        gf_mul(@z2, t2, t1);     { z2 = E(AA+a24*E) }
    end;
    { Finish }
    gf_cond_swap(x2, @x3, swap);
    gf_cond_swap(z2, @z3, swap);
    gf_invert(z2, z2, 0);
    gf_mul(@x1, x2, z2);
    gf_serialize(_out, x1, 1);
    nz := not gf_eq(x1, ZERO);
    OPENSSL_cleanse(@x1, sizeof(x1));
    OPENSSL_cleanse(@x2, sizeof(x2));
    OPENSSL_cleanse(@z2, sizeof(z2));
    OPENSSL_cleanse(@x3, sizeof(x3));
    OPENSSL_cleanse(@z3, sizeof(z3));
    OPENSSL_cleanse(@t1, sizeof(t1));
    OPENSSL_cleanse(@t2, sizeof(t2));
    Result := c448_succeed_if(mask_to_bool(nz));
end;



function ossl_x448(out_shared_key : PByte;const private_key, peer_public_value : PByte):integer;
begin
    Result := int(ossl_x448_int(out_shared_key, peer_public_value, private_key) = C448_SUCCESS);
end;

initialization
  precomputed_scalarmul_adjustment[0].limb[0] := SC_LIMB1($c873d6d54a7bb0cf);
  precomputed_scalarmul_adjustment[0].limb[1] := SC_LIMB2($c873d6d54a7bb0cf);

  precomputed_scalarmul_adjustment[0].limb[2] :=SC_LIMB1($e933d8d723a70aad);
  precomputed_scalarmul_adjustment[0].limb[3] :=SC_LIMB2($e933d8d723a70aad);
  precomputed_scalarmul_adjustment[0].limb[4] :=SC_LIMB1($bb124b65129c96fd);
  precomputed_scalarmul_adjustment[0].limb[5] :=SC_LIMB2($bb124b65129c96fd);
  precomputed_scalarmul_adjustment[0].limb[6] :=SC_LIMB1($00000008335dc163);
  precomputed_scalarmul_adjustment[0].limb[7] :=SC_LIMB2($00000008335dc163);

  FillChar(ossl_curve448_point_identity[0].x[0], SizeOf(Tgf), 0);
  FillChar(ossl_curve448_point_identity[0].y[0], SizeOf(Tgf), 1);
  FillChar(ossl_curve448_point_identity[0].z[0], SizeOf(Tgf), 1);
  FillChar(ossl_curve448_point_identity[0].t[0], SizeOf(Tgf), 0);

end.
