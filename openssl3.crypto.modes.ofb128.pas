unit openssl3.crypto.modes.ofb128;

interface
uses OpenSSL.Api;

 procedure CRYPTO_ofb128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; num : PInteger; block : block128_f);

implementation


procedure CRYPTO_ofb128_encrypt({const} _in : PByte; _out : PByte; len : size_t;const key : Pointer; ivec : PByte; num : PInteger; block : block128_f);
var
  n : uint32;

  l : size_t;
begin
    l := 0;
    if num^ < 0 then begin
        { There is no good way to signal an error return from here }
        num^ := -1;
        exit;
    end;
    n := num^;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if 16 mod sizeof(size_t) = 0 then
    begin  { always true actually }
        while Boolean(0) do
        begin
            while (n > 0) and  (len > 0) do
            begin
                PostInc(_out)^ := PostInc(_in)^  xor  ivec[n];
                PreDec(len);
                n := (n + 1) mod 16;
            end;
{$if defined(STRICT_ALIGNMENT)}
            if (size_t(_in) or size_t(_out) or size_t(ivec)) mod sizeof(size_t) <> 0  then
                break;
{$endif}
            while len >= 16 do
            begin
                block(ivec, ivec, key);
                while n < 16 do
                begin
                    Psize_t_aX(_out + n)^ := Psize_t_aX(_in + n)^
                         xor  Psize_t_aX(ivec + n)^;
                    n := n + sizeof(size_t)
                end;
                len  := len - 16;
                _out := _out + 16;
                _in  := _in + 16;
                n := 0;
            end;
            if len > 0 then
            begin
                block(ivec, ivec, key);
                while PostDec(len)>0 do
                begin
                    _out[n] := _in[n]  xor  ivec[n];
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
            block (ivec, ivec, key);
        end;
        _out[l] := _in[l]  xor  ivec[n];
        PreInc(l);
        n := (n + 1) mod 16;
    end;
    num^ := n;
end;


end.
