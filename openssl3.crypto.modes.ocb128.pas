unit openssl3.crypto.modes.ocb128;

interface
uses OpenSSL.Api;

procedure CRYPTO_ocb128_cleanup( ctx : POCB128_CONTEXT);
function CRYPTO_ocb128_init( ctx : POCB128_CONTEXT; keyenc, keydec : Pointer; encrypt, decrypt : block128_f; stream : ocb128_f):integer;
procedure ocb_double( _in, _out : POCB_BLOCK);
procedure ocb_block_lshift(const _in : PByte; shift : size_t; _out : PByte);
function CRYPTO_ocb128_finish(ctx : POCB128_CONTEXT;const tag : PByte; len : size_t):integer;
function ocb_finish( ctx : POCB128_CONTEXT; tag : PByte; len : size_t; write : integer):integer;
function CRYPTO_ocb128_tag( ctx : POCB128_CONTEXT; tag : PByte; len : size_t):integer;
function CRYPTO_ocb128_aad(ctx : POCB128_CONTEXT;{const} aad : PByte; len : size_t):integer;
function ocb_lookup_l( ctx : POCB128_CONTEXT; idx : size_t):POCB_BLOCK;
function ocb_ntz( n : uint64):uint32;
function CRYPTO_ocb128_setiv(ctx : POCB128_CONTEXT;const iv : PByte; len, taglen : size_t):integer;
procedure ocb_block_xor(const in1, in2 : PByte; len : size_t; _out : PByte);
function CRYPTO_ocb128_encrypt(ctx : POCB128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
function CRYPTO_ocb128_decrypt(ctx : POCB128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;

 function CRYPTO_ocb128_copy_ctx( dest, src : POCB128_CONTEXT; keyenc, keydec : Pointer):integer;

implementation


uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.cpuid;



function CRYPTO_ocb128_copy_ctx( dest, src : POCB128_CONTEXT; keyenc, keydec : Pointer):integer;
begin
    memcpy(dest, src, sizeof(TOCB128_CONTEXT));
    if keyenc <> nil then dest.keyenc := keyenc;
    if keydec <> nil then dest.keydec := keydec;
    if src.l <> nil then
    begin
        dest.l := OPENSSL_malloc(src.max_l_index * 16);
        if (dest.l = nil) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(dest.l, src.l, (src.l_index + 1) * 16);
    end;
    Result := 1;
end;


function CRYPTO_ocb128_decrypt(ctx : POCB128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
var
  i,
  all_num_blocks : uint64;
  num_blocks,
  last_len,
  max_idx, top        : size_t;
  tmp            : TOCB_BLOCK;
  lookup         : POCB_BLOCK;
  pad            : TOCB_BLOCK;
  function get_top: int;
  begin
     top := top shr 1;
     Result := top;
  end;
begin
    {
     * Calculate the number of blocks of data to be decrypted provided now, and
     * so far
     }
    num_blocks := len div 16;
    all_num_blocks := num_blocks + ctx.sess.blocks_processed;
    if (num_blocks > 0)  and  (all_num_blocks = size_t(all_num_blocks))
         and  (Assigned(ctx.stream)) then
    begin
        max_idx := 0; top := size_t(all_num_blocks);
         // See how many L_{i} //entries we need to process data at hand
         // and pre-compute missing entries in the table [if any]...

        while get_top > 0  do
            Inc(max_idx);
        if ocb_lookup_l(ctx, max_idx) = nil  then
            Exit(0);
        ctx.stream(_in, _out, num_blocks, ctx.keydec,
                    size_t(ctx.sess.blocks_processed) + 1, @ctx.sess.offset.c,
                    {(const Byte  ( *)[16])}PPByte(@ctx.l), @ctx.sess.checksum.c);
    end
    else
    begin
        { Loop through all full blocks to be decrypted }
        //for i := ctx.sess.blocks_processed + 1 to all_num_blocks do
        i := ctx.sess.blocks_processed + 1;
        while i<= all_num_blocks do
        begin
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            lookup := ocb_lookup_l(ctx, ocb_ntz(i));
            if lookup = nil then Exit(0);
            ocb_block16_xor(@ctx.sess.offset, lookup, @ctx.sess.offset);
            memcpy(@tmp.c, _in, 16);
            _in  := _in + 16;
            { P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) }
            ocb_block16_xor(@ctx.sess.offset, @tmp, @tmp);
            ctx.decrypt(@tmp.c, @tmp.c, ctx.keydec);
            ocb_block16_xor(@ctx.sess.offset, @tmp, @tmp);
            // Checksum_i = Checksum_{i-1} xor P_i
            ocb_block16_xor(@tmp, @ctx.sess.checksum, @ctx.sess.checksum);
            memcpy(_out, @tmp.c, 16);
            _out  := _out + 16;
            Inc(i);
        end;
    end;
    {
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     }
    last_len := len mod 16;
    if last_len > 0 then
    begin
        { Offset_* = Offset_m xor L_* }
        ocb_block16_xor(@ctx.sess.offset, @ctx.l_star, @ctx.sess.offset);
        { Pad = ENCIPHER(K, Offset_*) }
        ctx.encrypt(@ctx.sess.offset.c, @pad.c, ctx.keyenc);
        { P_* = C_* xor Pad[1..bitlen(C_*)] }
        ocb_block_xor(_in, @pad.c, last_len, _out);
        { Checksum_* = Checksum_m xor (P_*  or  1  or  zeros(127-bitlen(P_*))) }
        memset(@pad.c, 0, 16);           { borrow pad }
        memcpy(@pad.c, _out, last_len);
        pad.c[last_len] := $80;
        ocb_block16_xor(@pad, @ctx.sess.checksum, @ctx.sess.checksum);
    end;
    ctx.sess.blocks_processed := all_num_blocks;
    Result := 1;
end;



function CRYPTO_ocb128_encrypt(ctx : POCB128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
var
  i,
  all_num_blocks : uint64;
  num_blocks,
  last_len,
  max_idx, top        : size_t;
  lookup         : POCB_BLOCK;
  tmp,
  pad            : TOCB_BLOCK;
  function get_top: int;
  begin
     top := top shr 1;
     Result := top;
  end;
begin
    {
     * Calculate the number of blocks of data to be encrypted provided now, and
     * so far
     }
    num_blocks := len div 16;
    all_num_blocks := num_blocks + ctx.sess.blocks_processed;
    if (num_blocks > 0)  and  (all_num_blocks = size_t(all_num_blocks))
         and  (Assigned(ctx.stream)) then
    begin
        max_idx := 0; top := size_t(all_num_blocks);

         // See how many L_{i} //entries we need to process data at hand
         // and pre-compute missing entries in the table [if any]...

        while get_top > 0 do
            Inc(max_idx);
        if ocb_lookup_l(ctx, max_idx ) = nil then
            Exit(0);
        ctx.stream(_in, _out, num_blocks, ctx.keyenc,
                    size_t(ctx.sess.blocks_processed + 1), @ctx.sess.offset.c,
                    PPByte(@ctx.l), @ctx.sess.checksum.c);
    end
    else
    begin
        { Loop through all full blocks to be encrypted }
        //for i := ctx.sess.blocks_processed + 1 to all_num_blocks do
        i := ctx.sess.blocks_processed + 1;
        while i <= all_num_blocks do
        begin
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            lookup := ocb_lookup_l(ctx, ocb_ntz(i));
            if lookup = nil then Exit(0);
            ocb_block16_xor(@ctx.sess.offset, lookup, @ctx.sess.offset);
            memcpy(@tmp.c, _in, 16);
            _in  := _in + 16;
            // Checksum_i = Checksum_{i-1} xor P_i
            ocb_block16_xor(@tmp, @ctx.sess.checksum, @ctx.sess.checksum);
            { C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) }
            ocb_block16_xor(@ctx.sess.offset, @tmp, @tmp);
            ctx.encrypt(@tmp.c, @tmp.c, ctx.keyenc);
            ocb_block16_xor(@ctx.sess.offset, @tmp, @tmp);
            memcpy(_out, @tmp.c, 16);
            _out  := _out + 16;
            Inc(i);
        end;
    end;
    {
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     }
    last_len := len mod 16;
    if last_len > 0 then
    begin
        { Offset_* = Offset_m xor L_* }
        ocb_block16_xor(@ctx.sess.offset, @ctx.l_star, @ctx.sess.offset);
        { Pad = ENCIPHER(K, Offset_*) }
        ctx.encrypt(@ctx.sess.offset.c, @pad.c, ctx.keyenc);
        { C_* = P_* xor Pad[1..bitlen(P_*)] }
        ocb_block_xor(_in, @pad.c, last_len, _out);
        { Checksum_* = Checksum_m xor (P_*  or  1  or  zeros(127-bitlen(P_*))) }
        memset(@pad.c, 0, 16);           { borrow pad }
        memcpy(@pad.c, _in, last_len);
        pad.c[last_len] := $80;
        ocb_block16_xor(@pad, @ctx.sess.checksum, @ctx.sess.checksum);
    end;
    ctx.sess.blocks_processed := all_num_blocks;
    Result := 1;
end;




procedure ocb_block_xor(const in1, in2 : PByte; len : size_t; _out : PByte);
var
  i : size_t;
begin
    for i := 0 to len-1 do begin
        _out[i] := in1[i]  xor  in2[i];
    end;
end;



function CRYPTO_ocb128_setiv(ctx : POCB128_CONTEXT;const iv : PByte; len, taglen : size_t):integer;
var
  ktop, tmp, nonce : array[0..15] of Byte;
  mask : Byte;
  stretch : array[0..23] of Byte;
  bottom, shift : size_t;
  p: Pbyte;
begin

    {
     * Spec says IV is 120 bits or fewer - it allows non byte aligned lengths.
     * We don't support this at this stage
     }
    if (len > 15)  or  (len < 1)  or  (taglen > 16)  or  (taglen < 1) then  begin
        Exit(-1);
    end;
    { Reset nonce-dependent variables }
    memset(@ctx.sess, 0, sizeof(ctx.sess));
    { Nonce = num2str(TAGLEN mod 128,7)  or  zeros(120-bitlen(N))  or  1  or  N }
    nonce[0] := ((taglen * 8) mod 128) shl 1;
    memset(PByte(@nonce) + 1, 0, 15);
    memcpy(PByte(@nonce) + 16 - len, iv, len);
    nonce[15 - len]  := nonce[15 - len]  or 1;
    { Ktop = ENCIPHER(K, Nonce[1..122]  or  zeros(6)) }
    memcpy(@tmp, @nonce, 16);
    tmp[15] := tmp[15] and $c0;
    ctx.encrypt(@tmp, @ktop, ctx.keyenc);
    { Stretch = Ktop  or  (Ktop[1..64] xor Ktop[9..72]) }
    memcpy(@stretch, @ktop, 16);
    ocb_block_xor(@ktop, PByte(@ktop) + 1, 8, PByte(@stretch) + 16);
    { bottom = str2num(Nonce[123..128]) }
    bottom := nonce[15] and $3f;
    { Offset_0 = Stretch[1+bottom..128+bottom] }
    shift := bottom mod 8;
    ocb_block_lshift(PByte(@stretch) + (bottom div 8), shift, @ctx.sess.offset.c);
    mask := $ff;
    mask := mask shl (8 - shift);
    p := PByte(@stretch) + (bottom div 8) + 16;
    ctx.sess.offset.c[15] := ctx.sess.offset.c[15] or
        (p^ and mask)  shr  (8 - shift);
    Result := 1;
end;



function ocb_ntz( n : uint64):uint32;
var
  cnt : uint32;
begin
    cnt := 0;
    {
     * We do a right-to-left simple sequential search. This is surprisingly
     * efficient as the distribution of trailing zeros is not uniform,
     * e.g. the number of possible inputs with no trailing zeros is equal to
     * number with 2 or more, etc. Checking the last two bits covers 75% of
     * all numbers. Checking the last three covers 87.5%
     }
    while 0>=(n and 1) do
    begin
        n := n shr 1;
        Inc(cnt);
    end;
    Result := cnt;
end;



function ocb_lookup_l( ctx : POCB128_CONTEXT; idx : size_t): POCB_BLOCK;
var
  l_index : size_t;
  tmp_ptr : Pointer;
begin
{$POINTERMATH ON}
    l_index := ctx.l_index;
    if idx <= l_index then begin
        Exit(ctx.l + idx);
    end;
    { We don't have it - so calculate it }
    if idx >= ctx.max_l_index then begin
        {
         * Each additional entry allows to process almost double as
         * much data, so that in linear world the table will need to
         * be expanded with smaller and smaller increments. Originally
         * it was doubling in size, which was a waste. Growing it
         * linearly is not formally optimal, but is simpler to implement.
         * We grow table by minimally required 4*n that would accommodate
         * the index.
         }
        ctx.max_l_index  := ctx.max_l_index + ((idx - ctx.max_l_index + 4) and not 3);
        {tmp_ptr := }OPENSSL_realloc(Pointer(ctx.l), ctx.max_l_index * sizeof(TOCB_BLOCK));
        if ctx.l  = nil then { prevent ctx.l from being clobbered }
            Exit(nil);
        //ctx.l := tmp_ptr;
    end;
    while l_index < idx do  begin
        ocb_double(ctx.l + l_index, ctx.l + l_index + 1);
        PostInc(l_index);
    end;
    ctx.l_index := l_index;
    Result := ctx.l + idx;
{$POINTERMATH OFF}
end;



function CRYPTO_ocb128_aad(ctx : POCB128_CONTEXT;{const} aad : PByte; len : size_t):integer;
var
  i,
  all_num_blocks : uint64;
  num_blocks,
  last_len       : size_t;
    tmp            : TOCB_BLOCK;
    lookup         : POCB_BLOCK;
begin
    { Calculate the number of blocks of AAD provided now, and so far }
    num_blocks := len div 16;
    all_num_blocks := num_blocks + ctx.sess.blocks_hashed;
    { Loop through all full blocks of AAD }
    //for i := ctx.sess.blocks_hashed + 1 to all_num_blocks do
    i := ctx.sess.blocks_processed + 1;
    while i<= all_num_blocks do
    begin
        // Offset_i = Offset_{i-1} xor L_{ntz(i)}
        lookup := ocb_lookup_l(ctx, ocb_ntz(i));
        if lookup = nil then Exit(0);
        ocb_block16_xor(@ctx.sess.offset_aad, lookup, @ctx.sess.offset_aad);
        memcpy(@tmp.c, aad, 16);
        aad  := aad + 16;
        // Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)
        ocb_block16_xor(@ctx.sess.offset_aad, @tmp, @tmp);
        ctx.encrypt(@tmp.c, @tmp.c, ctx.keyenc);
        ocb_block16_xor(@tmp, @ctx.sess.sum, @ctx.sess.sum);
        Inc(i);
    end;
    {
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     }
    last_len := len mod 16;
    if last_len > 0 then
    begin
        { Offset_* = Offset_m xor L_* }
        ocb_block16_xor(@ctx.sess.offset_aad, @ctx.l_star,
                        @ctx.sess.offset_aad);
        { CipherInput = (A_*  or  1  or  zeros(127-bitlen(A_*))) xor Offset_* }
        memset(@tmp.c, 0, 16);
        memcpy(@tmp.c, aad, last_len);
        tmp.c[last_len] := $80;
        ocb_block16_xor(@ctx.sess.offset_aad, @tmp, @tmp);
        { Sum = Sum_m xor ENCIPHER(K, CipherInput) }
        ctx.encrypt(@tmp.c, @tmp.c, ctx.keyenc);
        ocb_block16_xor(@tmp, @ctx.sess.sum, @ctx.sess.sum);
    end;
    ctx.sess.blocks_hashed := all_num_blocks;
    Result := 1;
end;



function CRYPTO_ocb128_tag( ctx : POCB128_CONTEXT; tag : PByte; len : size_t):integer;
begin
    Result := ocb_finish(ctx, tag, len, 1);
end;



function ocb_finish( ctx : POCB128_CONTEXT; tag : PByte; len : size_t; write : integer):integer;
var
  tmp : TOCB_BLOCK;
begin
    if (len > 16)  or  (len < 1) then begin
        Exit(-1);
    end;
    {
     * Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
     }
    ocb_block16_xor(@ctx.sess.checksum, @ctx.sess.offset, @tmp);
    ocb_block16_xor(@ctx.l_dollar, @tmp, @tmp);
    ctx.encrypt(@tmp.c, @tmp.c, ctx.keyenc);
    if write > 0 then begin
        memcpy(tag, @tmp, len);
        Exit(1);
    end
    else
    begin
        Exit(CRYPTO_memcmp(@tmp, tag, len));
    end;
end;


function CRYPTO_ocb128_finish(ctx : POCB128_CONTEXT;const tag : PByte; len : size_t):integer;
begin
    Result := ocb_finish(ctx, PByte(tag), len, 0);
end;



procedure ocb_block_lshift(const _in : PByte; shift : size_t; _out : PByte);
var
  i : integer;

  carry, carry_next : Byte;
begin
    carry := 0;
    for i := 15 downto 0 do
    begin
        carry_next := _in[i]  shr  (8 - shift);
        _out[i] := (_in[i] shl shift) or carry;
        carry := carry_next;
    end;
end;



procedure ocb_double(_in, _out : POCB_BLOCK);
var
  mask : Byte;
begin
    {
     * Calculate the mask based on the most significant bit. There are more
     * efficient ways to do this - but this way is constant time
     }
    mask := _in.c[0] and $80;
    mask := mask shr 7;
    mask := (0 - mask) and $87;
    ocb_block_lshift(@_in.c, 1, @_out.c);
    _out.c[15]  := _out.c[15] xor mask;
end;


function CRYPTO_ocb128_init( ctx : POCB128_CONTEXT; keyenc, keydec : Pointer; encrypt, decrypt : block128_f; stream : ocb128_f):integer;
begin
{$POINTERMATH ON}
    memset(ctx, 0, sizeof( ctx^));
    ctx.l_index := 0;
    ctx.max_l_index := 5;
    ctx.l := OPENSSL_malloc(ctx.max_l_index * 16 );
    if ctx.l =  nil then  begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    {
     * We set both the encryption and decryption key schedules - decryption
     * needs both. Don't really need decryption schedule if only doing
     * encryption - but it simplifies things to take it anyway
     }
    ctx.encrypt := encrypt;
    ctx.decrypt := decrypt;
    ctx.stream := stream;
    ctx.keyenc := keyenc;
    ctx.keydec := keydec;
    { L_* = ENCIPHER(K, zeros(128)) }
    ctx.encrypt(@ctx.l_star.c, @ctx.l_star.c, ctx.keyenc);
    { L_$ = double(L_*) }
    ocb_double(@ctx.l_star, @ctx.l_dollar);
    { L_0 = double(L_$) }
    ocb_double(@ctx.l_dollar, ctx.l);
    // L_{i} = double(L_{i-1})
    ocb_double(ctx.l, ctx.l+1);
    ocb_double(ctx.l+1, ctx.l+2);
    ocb_double(ctx.l+2, ctx.l+3);
    ocb_double(ctx.l+3, ctx.l+4);
    ctx.l_index := 4;   { enough to process up to 496 bytes }
    Result := 1;
{$POINTERMATH OFF}
end;

procedure CRYPTO_ocb128_cleanup( ctx : POCB128_CONTEXT);
begin
    if ctx <> nil then
    begin
        OPENSSL_clear_free(Pointer(ctx.l), ctx.max_l_index * 16);
        OPENSSL_cleanse(Pointer(ctx), sizeof( ctx^));
    end;
end;

end.
