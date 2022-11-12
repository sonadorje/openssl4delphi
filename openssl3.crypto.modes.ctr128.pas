unit openssl3.crypto.modes.ctr128;

interface
uses OpenSSL.Api;

procedure CRYPTO_ctr128_encrypt_ctr32({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec, ecount_buf : PByte; num : Puint32; func : ctr128_f);
procedure ctr96_inc( counter : PByte);
procedure CRYPTO_ctr128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec, ecount_buf : PByte; num : Puint32; block : block128_f);
procedure ctr128_inc_aligned( counter : PByte);
procedure ctr128_inc( counter : PByte);

implementation


procedure ctr128_inc( counter : PByte);
var
  n,c : uint32;
begin
    n := 16; c := 1;
    repeat
        Dec(n);
        c  := c + (counter[n]);
        counter[n] := uint8(c);
        c  := c shr 8;
    until not (n>0);
end;



procedure ctr128_inc_aligned( counter : PByte);
var
  data: Psize_t;
  c, d, n :size_t;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    
    if (ossl_is_endian.one = 1)  or  (size_t(counter) mod sizeof(size_t) <> 0)  then
    begin
        ctr128_inc(counter);
        Exit;
    end;
    data := Psize_t(counter);
    c := 1;
    n := 16 div sizeof(size_t);
    repeat
        PreDec(n);
        data[n]  := data[n] + c;
        d := data[n];
        { did addition carry? }
        c := ((d - c) and not d)  shr  (sizeof(size_t) * 8 - 1);
    until not (n>0);
{$POINTERMATH OFF}
end;



procedure CRYPTO_ctr128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec, ecount_buf : PByte; num : Puint32; block : block128_f);
var
  n : uint32;
  l : size_t;
begin
    l := 0;
    n := num^;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if 16 mod sizeof(size_t) = 0 then
    begin  { always true actually }
        while Boolean(0) do
        begin
            while (n > 0)  and  (len > 0) do
            begin
                PostInc(_out)^ := PostInc(_in)^  xor  ecount_buf[n];
                PreDec(len);
                n := (n + 1) mod 16;
            end;
{$if defined(STRICT_ALIGNMENT)}
            if size_t(_in) or size_t(out or size_t(ecount_buf then % sizeofsize_t( <> 0 then
                break;
{$endif}
            while len >= 16 do
            begin
                block (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                n := 0;
                while n < 16 do
                begin
                    Psize_t_aX(_out + n)^ := Psize_t_aX(_in + n)^
                         xor  Psize_t_aX(ecount_buf + n)^;
                    n := n + sizeof(size_t);
                end;
                len  := len - 16;
                _out  := _out + 16;
                _in  := _in + 16;
                n := 0;
            end;
            if len > 0 then
            begin
                block (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                while PostDec(len) > 0 do
                begin
                    _out[n] := _in[n]  xor  ecount_buf[n];
                    Inc(n);
                end;
            end;
            num^ := n;
            exit;
        end;

    end;
    { the rest would be commonly eliminated by x86* compiler }
{$ENDIF}
    while l < len do
    begin
        if n = 0 then begin
           block (ivec, ecount_buf, key);
            ctr128_inc(ivec);
        end;
        _out[l] := _in[l]  xor  ecount_buf[n];
        PreInc(l);
        n := (n + 1) mod 16;
    end;
    num^ := n;
end;





procedure ctr96_inc( counter : PByte);
var
  n,c : uint32;
begin
    n := 12; c := 1;
    repeat
        Dec(n);
        c  := c + (counter[n]);
        counter[n] := uint8(c);
        c  := c shr  8;
    until not (n>0);
end;



procedure CRYPTO_ctr128_encrypt_ctr32({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec, ecount_buf : PByte; num : Puint32; func : ctr128_f);
var
  n, ctr32 : uint32;

  blocks : size_t;
begin
   n := num^;
    while (n > 0)  and  (len > 0) do
    begin
        PostInc(_out)^ := PostInc(_in)^  xor  ecount_buf[n];
        PreDec(len);
        n := (n + 1) mod 16;
    end;
    ctr32 := GETU32(ivec + 12);
    while len >= 16 do
    begin
        blocks := len div 16;
        {
         * 1shl28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         }
        if (sizeof(size_t) > sizeof(uint32))  and  (blocks > (1 shl 28)) then
            blocks := (1 shl 28);
        {
         * As ( *func) operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         }
        ctr32  := ctr32 + uint32(blocks);
        if ctr32 < blocks then begin
            blocks  := blocks - ctr32;
            ctr32 := 0;
        end;
        func(_in, _out, blocks, key, ivec);
        { ( *ctr) does not update ivec, caller does: }
        PUTU32(ivec + 12, ctr32);
        { ... overflow was detected, propagate carry. }
        if ctr32 = 0 then ctr96_inc(ivec);
        blocks  := blocks  * 16;
        len  := len - blocks;
        _out  := _out + blocks;
        _in  := _in + blocks;
    end;
    if len > 0 then
    begin
        memset(ecount_buf, 0, 16);
        func (ecount_buf, ecount_buf, 1, key, ivec);
        Inc(ctr32);
        PUTU32(ivec + 12, ctr32);
        if ctr32 = 0 then ctr96_inc(ivec);
        while PostDec(len) > 0 do
        begin
            _out[n] := _in[n]  xor  ecount_buf[n];
            Inc(n);
        end;
    end;
    num^ := n;
end;


end.
