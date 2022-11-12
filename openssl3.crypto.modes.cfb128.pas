unit openssl3.crypto.modes.cfb128;

interface
uses OpenSSL.Api;

procedure CRYPTO_cfb128_1_encrypt(const _in : PByte; &out : PByte; bits : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);

procedure cfbr_encrypt_block(const _in : PByte; &out : PByte; nbits : integer;const key : Pointer; ivec : PByte; enc : integer; block : block128_f);
procedure CRYPTO_cfb128_8_encrypt(const _in : PByte; _out : PByte; length : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);

 procedure CRYPTO_cfb128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);

implementation


procedure CRYPTO_cfb128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);
var
  n : uint32;
  l : size_t;
  c : Byte;
  t : size_t;
  //c, c : Byte;
begin
    l := 0;
    if num^ < 0 then begin
        { There is no good way to signal an error return from here }
        num^ := -1;
        Exit;
    end;
    n := num^;
    if enc > 0 then
    begin
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
        if 16 mod sizeof(size_t) = 0 then
        begin  { always true actually }
            while Boolean(0) do
            begin
                while (n > 0)  and  (len > 0) do
                begin
                    ivec[n]  := ivec[n] xor PostInc(_in)^;
                    PostInc(_out)^ := ivec[n];
                    PreDec(len);
                    n := (n + 1) mod 16;
                end;
{$if defined(STRICT_ALIGNMENT)}
                if (size_t(_in) or size_t(_out) or size_t(ivec) ) mod
                    sizeof(size_t) <> 0  then
                    break;
{$endif}
                while len >= 16 do
                begin
                    block(ivec, ivec, key);
                    while n < 16 do
                    begin
                        Psize_t_aX(ivec + n)^ := Psize_t_aX(ivec + n)^ xor Psize_t_aX(_in + n)^;
                        Psize_t_aX(_out + n)^ := Psize_t_aX(ivec + n)^;
                        n:= n + sizeof(size_t);
                    end;
                    len  := len - 16;
                    _out  := _out + 16;
                    _in  := _in + 16;
                    n := 0;
                end;
                if len > 0 then
                begin
                    block (ivec, ivec, key);
                    while PostDec(len) > 0 do
                    begin
                        ivec[n]  := ivec[n] xor (_in[n]);
                        _out[n] := ivec[n];
                        Inc(n);
                    end;
                end;
                num^ := n;
                Exit;
            end;

        end;
        { the rest would be commonly eliminated by x86* compiler }
{$ENDIF}
        while l < len do
        begin
            if n = 0 then begin
                block (ivec, ivec, key);
            end;
            ivec[n]  := ivec[n] xor (_in[l]);
            _out[l] := ivec[n];
            Inc(l);
            n := (n + 1) mod 16;
        end;
        num^ := n;
    end
    else
    begin
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
        if 16 mod sizeof(size_t) = 0 then
        begin  { always true actually }
            while Boolean(0) do
            begin
                while (n > 0)  and  (len > 0) do
                begin
                    c := PostInc(_in)^;
                    PostInc(_out)^ := ivec[n]  xor  (c);
                    ivec[n] := c;
                    Dec(len);
                    n := (n + 1) mod 16;
                end;
{$if defined(STRICT_ALIGNMENT)}
                if (size_t(in or size_t(out or size_t(ivec then %
                    sizeofsize_t( <> 0)
                    break;
{$endif}
                while len >= 16 do
                begin
                    block (ivec, ivec, key);
                    while n < 16 do
                    begin
                        t := Psize_t_aX (_in + n)^;
                        Psize_t_aX (_out + n)^ := Psize_t_aX(ivec + n)^  xor  t;
                        Psize_t_aX(ivec + n)^ := t;
                        n := n + sizeof(size_t);
                    end;
                    len  := len - 16;
                    _out  := _out + 16;
                    _in  := _in + 16;
                    n := 0;
                end;
                if len > 0 then
                begin
                    block(ivec, ivec, key);
                    while PostDec(len) > 0 do
                    begin
                        c := _in[n];
                        _out[n] := ivec[n]  xor  (c);
                        ivec[n] := c;
                        Inc(n);
                    end;
                end;
                num^ := n;
                Exit;
            end;

        end;
        { the rest would be commonly eliminated by x86* compiler }
{$ENDIF}
        while l < len do
        begin
            if n = 0 then begin
                block (ivec, ivec, key);
            end;
            c := _in[l];
            _out[l] := ivec[n]  xor  (c);
            ivec[n] := c;
            PreInc(l);
            n := (n + 1) mod 16;
        end;
        num^ := n;
    end;
end;


procedure CRYPTO_cfb128_8_encrypt(const _in : PByte; _out : PByte; length : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);
var
  n : size_t;
begin
    for n := 0 to length-1 do
        cfbr_encrypt_block(@_in[n], @_out[n], 8, key, ivec, enc, block);
end;



procedure cfbr_encrypt_block(const _in : PByte; &out : PByte; nbits : integer;const key : Pointer; ivec : PByte; enc : integer; block : block128_f);
var
  n, rem, num : integer;

  ovec : array[0..(16 * 2 + 1)-1] of Byte;
begin

    if (nbits <= 0)  or  (nbits > 128) then exit;
    { fill in the first half of the new IV with the current IV }
    memcpy(@ovec, ivec, 16);
    { construct the new IV }
    block (ivec, ivec, key);
    num := (nbits + 7) div 8;
    if enc>0 then { encrypt the input }
        for n := 0 to num-1 do
        begin
            ovec[16 + n] := _in[n]  xor  ivec[n] ;
            out[n] := ovec[16 + n];
        end
    else                        { decrypt the input }
        for n := 0 to num-1 do
        begin
            ovec[16 + n] := _in[n]  xor  ivec[n];
            out[n] := ovec[16 + n] ;
        end;
    { shift ovec left... }
    rem := nbits mod 8;
    num := nbits div 8;
    if rem = 0 then
       memcpy(@ivec, PByte(@ovec) + num, 16)
    else
        for n := 0 to 16-1 do
            ivec[n] := ovec[n + num]  shl  rem or ovec[n + num + 1]  shr  (8 - rem);
    { it is not necessary to cleanse ovec, since the IV is not secret }
end;


procedure CRYPTO_cfb128_1_encrypt(const _in : PByte; &out : PByte; bits : size_t;const key : Pointer; ivec : PByte; num : PInteger; enc : integer; block : block128_f);
var
  n : size_t;

  c, d : array[0..0] of Byte;
begin

    for n := 0 to bits-1 do
    begin
        c[0] := get_result(_in[n div 8] and (1  shl  (7 - n mod 8)) >0, $80 , 0);
        cfbr_encrypt_block(@c, @d, 1, key, ivec, enc, block);
        out[n div 8] := (out[n div 8] and not (1  shl  uint32(7 - n mod 8))) or
            ((d[0] and $80)  shr  uint32 (n mod 8));
    end;
end;


end.
