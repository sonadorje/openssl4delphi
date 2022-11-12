unit openssl3.crypto.modes.cbc128;

interface
uses OpenSSL.Api;

{$if not defined(STRICT_ALIGNMENT) and not defined(PEDANTIC)}
  const STRICT_ALIGNMENT = 0;
{$endif}



 procedure CRYPTO_cbc128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; block_func : block128_f);
procedure CRYPTO_cbc128_decrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; block_func : block128_f);

implementation


procedure CRYPTO_cbc128_decrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; block_func : block128_f);
type
  tmp_st = record
     case Integer of
      0:  ( t: array[0..(16 div sizeof(size_t)-1)] of  size_t);
      1:  ( c: array[0..16-1] of Byte)
  end;
var
  n : size_t;
  iv : PByte;
  out_t, iv_t : Psize_t_aX;
  c1 : Byte;
  c2 : size_t;
  ivec_t, in_t : Psize_t_aX;
  c3 : Byte;
  tmp: tmp_st;
begin
{$POINTERMATH ON}
    if len = 0 then exit;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if _in <> _out then begin
        iv := ivec;
        if (STRICT_ALIGNMENT > 0) and
           ( (size_t(_in) or size_t(_out) or size_t(ivec)) mod sizeof(size_t) <> 0) then
        begin
            while len >= 16 do
            begin
                block_func(_in, _out, key);
                for n := 0 to 16-1 do
                    _out[n]  := _out[n] xor (iv[n]);
                iv := _in;
                len  := len - 16;
                _in  := _in + 16;
                _out  := _out + 16;
            end;
        end
        else
        if (16 mod sizeof(size_t) = 0) then
        begin  { always true }
            while len >= 16 do
            begin
                out_t := Psize_t_aX (_out);
                iv_t := Psize_t_aX(iv);
                block_func (_in, _out, key);
                for n := 0 to 16 div sizeof(size_t) -1 do
                    out_t[n]  := out_t[n] xor (iv_t[n]);
                iv := _in;
                len  := len - 16;
                _in  := _in + 16;
                _out  := _out + 16;
            end;
        end;
        if ivec <> iv then memcpy(ivec, iv, 16);
    end
    else
    begin
        if (STRICT_ALIGNMENT > 0)  and
           ( (size_t(_in) or size_t(_out) or size_t(ivec) )mod sizeof(size_t) <> 0) then
        begin
            while len >= 16 do
            begin
                block_func(_in, @tmp.c, key);
                for n := 0 to 16-1 do
                begin
                    c1 := _in[n];
                    _out[n] := tmp.c[n]  xor  ivec[n];
                    ivec[n] := c1;
                end;
                len  := len - 16;
                _in  := _in + 16;
                _out  := _out + 16;
            end;
        end
        else
        if (16 mod sizeof(size_t) = 0) then
        begin  { always true }
            while len >= 16 do
            begin
                out_t := Psize_t_aX(_out);
                ivec_t := Psize_t_aX(ivec);
                in_t := Psize_t_aX(_in);
                block_func(_in, @tmp.c, key);
                for n := 0 to 16 div sizeof(size_t)-1 do
                begin
                    c2 := in_t[n];
                    out_t[n] := tmp.t[n]  xor  ivec_t[n];
                    ivec_t[n] := c2;
                end;
                len  := len - 16;
                _in  := _in + 16;
                _out  := _out + 16;
            end;  //-->while len >= 16
        end;
    end;
{$ENDIF}
    while len > 0 do
    begin
        block_func(_in, @tmp.c, key);
        n := 0;
        while (n < 16)  and  (n < len) do
        begin
            c3 := _in[n];
            _out[n] := tmp.c[n]  xor  ivec[n];
            ivec[n] := c3;
            Inc(n);
        end;
        if len <= 16 then
        begin
            while n < 16 do
            begin
                ivec[n] := _in[n];
                inc(n);
            end;
            break;
        end;
        len  := len - 16;
        _in  := _in + 16;
        _out  := _out + 16;
    end;//-->while len > 0
{$POINTERMATH OFF}
end;



procedure CRYPTO_cbc128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; block_func : block128_f);
var
  n : size_t;
  iv : PByte;
begin
     iv := ivec;
    if len = 0 then Exit;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if (STRICT_ALIGNMENT > 0) and
       ( ( size_t(_in) or size_t(_out) or size_t(ivec) ) mod sizeof(size_t) <> 0) then
    begin
        while len >= 16 do
        begin
            for n := 0 to 16-1 do
                _out[n] := _in[n]  xor  iv[n];
            block_func(_out, _out, key);
            iv := _out;
            len  := len - 16;
            _in  := _in + 16;
            _out  := _out + 16;
        end;
    end
    else
    begin
        while len >= 16 do
        begin
            n := 0;
            while n < 16 do
            begin
                Psize_t_aX(_out + n)^ := Psize_t_aX(_in + n)^  xor  Psize_t_aX(iv + n)^;
                 n := n + sizeof(size_t)
            end;
            block_func(_out, _out, key);
            iv := _out;
            len  := len - 16;
            _in  := _in + 16;
            _out  := _out + 16;
        end;
    end;
{$ENDIF}
    while len > 0 do
    begin
        n := 0;
        while (n < 16)  and  (n < len) do
        begin
            _out[n] := _in[n]  xor  iv[n];
            Inc(n);
        end;
        while n < 16 do
        begin
            _out[n] := iv[n];
            Inc(n);
        end;
        block_func (_out, _out, key);
        iv := _out;
        if len <= 16 then break;
        len  := len - 16;
        _in  := _in + 16;
        _out  := _out + 16;
    end;
    if ivec <> iv then
       memcpy(ivec, iv, 16);
end;


end.
