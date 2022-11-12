unit openssl3.crypto.siphash.siphash;

interface
 uses OpenSSL.Api;

 function SipHash_ctx_size:size_t;
  function SipHash_hash_size( ctx : PSIPHASH):size_t;
  function siphash_adjust_hash_size( hash_size : size_t):size_t;
  function SipHash_set_hash_size( ctx : PSIPHASH; hash_size : size_t):integer;
  function _SipHash_Init(ctx : PSIPHASH;const k : PByte; crounds, drounds : integer):integer;
  procedure _SipHash_Update(ctx : PSIPHASH; &in : PByte; inlen : size_t);
  function _SipHash_Final( ctx : PSIPHASH; &out : PByte; outlen : size_t):integer;

implementation

function U8TO64_LE(p: PByte):uint64;
begin
{$POINTERMATH ON}
  Result :=  ((uint64(p[0])) or (uint64(p[1])  shl  8) or
               (uint64(p[2])  shl  16) or (uint64(p[3])  shl  24) or
               (uint64(p[4])  shl  32) or (uint64(p[5])  shl  40) or
               (uint64(p[6])  shl  48) or (uint64(p[7])  shl  56))
{$POINTERMATH OFF}
end;

function SipHash_ctx_size:size_t;
begin
    Result := sizeof(TSIPHASH);
end;


function SipHash_hash_size( ctx : PSIPHASH):size_t;
begin
    Result := ctx.hash_size;
end;


function siphash_adjust_hash_size( hash_size : size_t):size_t;
begin
    if hash_size = 0 then
       hash_size := SIPHASH_MAX_DIGEST_SIZE;
    Result := hash_size;
end;


function SipHash_set_hash_size( ctx : PSIPHASH; hash_size : size_t):integer;
begin
    hash_size := siphash_adjust_hash_size(hash_size);
    if (hash_size <> SIPHASH_MIN_DIGEST_SIZE)
         and  (hash_size <> SIPHASH_MAX_DIGEST_SIZE) then
         Exit(0);
    {
     * It's possible that the key was set first.  If the hash size changes,
     * we need to adjust v1 (see SipHash_Init().
     }
    { Start by adjusting the stored size, to make things easier }
    ctx.hash_size := siphash_adjust_hash_size(ctx.hash_size);
    { Now, adjust ctx.v1 if the old and the new size differ }
    if size_t( ctx.hash_size) <> hash_size then
    begin
        ctx.v1  := ctx.v1 xor $ee;
        ctx.hash_size := hash_size;
    end;
    Result := 1;
end;


function _SipHash_Init(ctx : PSIPHASH;const k : PByte; crounds, drounds : integer):integer;
var
  k0, k1 : uint64;
begin
    k0 := U8TO64_LE(k);
    k1 := U8TO64_LE(k + 8);
    { If the hash size wasn't set, i.e. is zero }
    ctx.hash_size := siphash_adjust_hash_size(ctx.hash_size);
    if drounds = 0 then drounds := SIPHASH_D_ROUNDS;
    if crounds = 0 then crounds := SIPHASH_C_ROUNDS;
    ctx.crounds := crounds;
    ctx.drounds := drounds;
    ctx.len := 0;
    ctx.total_inlen := 0;
    ctx.v0 := Int64($736f6d6570736575)  xor  k0;
    ctx.v1 := UInt64($646f72616e646f6d)  xor  k1;
    ctx.v2 := Int64($6c7967656e657261)  xor  k0;
    ctx.v3 := Int64($7465646279746573)  xor  k1;
    if ctx.hash_size = SIPHASH_MAX_DIGEST_SIZE then
       ctx.v1  := ctx.v1 xor $ee;
    Result := 1;
end;

function ROTL(x: UInt64; b: Byte):uint64;
begin
   Result := uint64(((x)  shl  (b)) or ((x)  shr  (64 - (b))))
end;

procedure _SipHash_Update(ctx : PSIPHASH; &in : PByte; inlen : size_t);
var
  m         : uint64;
  left      : integer;
  i         : uint32;
  v0,
  v1,
  v2,
  v3        : uint64;
  available : size_t;
  _end: PByte;
  procedure SIPROUND;
  begin
      v0  := v0 + v1;
      v1 := ROTL(v1, 13);
      v1  := v1 xor v0;
      v0 := ROTL(v0, 32);
      v2  := v2 + v3;
      v3 := ROTL(v3, 16);
      v3  := v3 xor v2;
      v0  := v0 + v3;
      v3 := ROTL(v3, 21);
      v3  := v3 xor v0;
      v2  := v2 + v1;
      v1 := ROTL(v1, 17);
      v1  := v1 xor v2;
      v2 := ROTL(v2, 32);
  end;
begin
    v0 := ctx.v0;
    v1 := ctx.v1;
    v2 := ctx.v2;
    v3 := ctx.v3;
    ctx.total_inlen  := ctx.total_inlen + inlen;
    if ctx.len >0 then
    begin
        { deal with leavings }
        available := SIPHASH_BLOCK_SIZE - ctx.len;
        { not enough to fill leavings }
        if inlen < available then
        begin
            memcpy(@ctx.leavings[ctx.len], &in, inlen);
            ctx.len  := ctx.len + inlen;
            exit;
        end;
        { copy data into leavings and reduce input }
        memcpy(@ctx.leavings[ctx.len], &in, available);
        inlen  := inlen - available;
        &in := &in + available;
        { process leavings }
        m := U8TO64_LE(@ctx.leavings);
        v3  := v3 xor m;
        for i := 0 to ctx.crounds-1 do
            SIPROUND;
        v0  := v0 xor m;
    end;
    left := inlen and (SIPHASH_BLOCK_SIZE-1); { gets put into leavings }
    _end := &in + inlen - left;
    while &in <> _end do
    begin
        m := U8TO64_LE(&in);
        v3  := v3 xor m;
        for i := 0 to ctx.crounds-1 do
            SIPROUND;
        v0  := v0 xor m;
        &in := &in + 8;
    end;
    { save leavings and other ctx }
    if left>0 then
       memcpy(@ctx.leavings, _end, left);
    ctx.len := left;
    ctx.v0 := v0;
    ctx.v1 := v1;
    ctx.v2 := v2;
    ctx.v3 := v3;
end;

procedure U32TO8_LE(p: PByte; v:Uint32);
begin
    p[0] := Byte(v);
    p[1] := Byte(v  shr  8);
    p[2] := Byte(v  shr  16);
    p[3] := Byte(v  shr  24);
end;

procedure U64TO8_LE(p: PByte; v:Uint64);
begin
    U32TO8_LE(p, uint32(v));
    U32TO8_LE(p + 4, uint32(v  shr  32));
end;


function _SipHash_Final( ctx : PSIPHASH; &out : PByte; outlen : size_t):integer;
var
  i : uint32;

  b, v0, v1, v2, v3 : uint64;
  procedure SIPROUND;
  begin
      v0  := v0 + v1;
      v1 := ROTL(v1, 13);
      v1  := v1 xor v0;
      v0 := ROTL(v0, 32);
      v2  := v2 + v3;
      v3 := ROTL(v3, 16);
      v3  := v3 xor v2;
      v0  := v0 + v3;
      v3 := ROTL(v3, 21);
      v3  := v3 xor v0;
      v2  := v2 + v1;
      v1 := ROTL(v1, 17);
      v1  := v1 xor v2;
      v2 := ROTL(v2, 32);
  end;
begin
    { finalize hash }
    b := ctx.total_inlen  shl  56;
    v0 := ctx.v0;
    v1 := ctx.v1;
    v2 := ctx.v2;
    v3 := ctx.v3;
    if outlen <> size_t( ctx.hash_size) then Exit(0);
    case ctx.len of
    7:
        b  := b  or ((uint64( ctx.leavings[6])  shl  48));
        { fall thru }
    6:
        b  := b  or ((uint64( ctx.leavings[5])  shl  40));
        { fall thru }
    5:
        b  := b  or ((uint64( ctx.leavings[4])  shl  32));
        { fall thru }
    4:
        b  := b  or ((uint64( ctx.leavings[3])  shl  24));
        { fall thru }
    3:
        b  := b  or ((uint64( ctx.leavings[2])  shl  16));
        { fall thru }
    2:
        b  := b  or ((uint64( ctx.leavings[1])  shl   8));
        { fall thru }
    1:
        b  := b  or (uint64( ctx.leavings[0]));
    0:
        begin
          //
        end;
    end;
    v3  := v3 xor b;
    for i := 0 to ctx.crounds-1 do
        SIPROUND;
    v0  := v0 xor b;
    if ctx.hash_size = SIPHASH_MAX_DIGEST_SIZE then
       v2  := v2 xor $ee
    else
        v2  := v2 xor $ff;
    for i := 0 to ctx.drounds-1 do
        SIPROUND;
    b := v0  xor  v1  xor  v2   xor  v3;
    U64TO8_LE(&out, b);
    if ctx.hash_size = SIPHASH_MIN_DIGEST_SIZE then Exit(1);
    v1  := v1 xor $dd;
    for i := 0 to ctx.drounds-1 do
        SIPROUND;
    b := v0  xor  v1  xor  v2   xor  v3;
    U64TO8_LE(&out + 8, b);
    Result := 1;
end;



end.
