unit openssl3.crypto.evp.encode;

interface
uses OpenSSL.Api, SysUtils;

const
    B64_EOLN                = $F0;
    B64_CR                  = $F1;
    B64_EOF                 = $F2;
    B64_WS                  = $E0;
    B64_ERROR               = $FF;

    srpdata_bin2ascii: PAnsiChar =
    '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./';
    data_bin2ascii: PAnsiChar =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    srpdata_ascii2bin: array[0..128-1] of Byte = (
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $E0, $F0, $FF, $FF, $F1, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $E0, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $F2, $3E, $3F,
    $00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $FF, $FF, $FF, $00, $FF, $FF,
    $FF, $0A, $0B, $0C, $0D, $0E, $0F, $10,
    $11, $12, $13, $14, $15, $16, $17, $18,
    $19, $1A, $1B, $1C, $1D, $1E, $1F, $20,
    $21, $22, $23, $FF, $FF, $FF, $FF, $FF,
    $FF, $24, $25, $26, $27, $28, $29, $2A,
    $2B, $2C, $2D, $2E, $2F, $30, $31, $32,
    $33, $34, $35, $36, $37, $38, $39, $3A,
    $3B, $3C, $3D, $FF, $FF, $FF, $FF, $FF
);
    data_ascii2bin: array[0..128-1] of Byte = (
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $E0, $F0, $FF, $FF, $F1, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $E0, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $3E, $FF, $F2, $FF, $3F,
    $34, $35, $36, $37, $38, $39, $3A, $3B,
    $3C, $3D, $FF, $FF, $FF, $00, $FF, $FF,
    $FF, $00, $01, $02, $03, $04, $05, $06,
    $07, $08, $09, $0A, $0B, $0C, $0D, $0E,
    $0F, $10, $11, $12, $13, $14, $15, $16,
    $17, $18, $19, $FF, $FF, $FF, $FF, $FF,
    $FF, $1A, $1B, $1C, $1D, $1E, $1F, $20,
    $21, $22, $23, $24, $25, $26, $27, $28,
    $29, $2A, $2B, $2C, $2D, $2E, $2F, $30,
    $31, $32, $33, $FF, $FF, $FF, $FF, $FF
);

 function EVP_ENCODE_CTX_new:PEVP_ENCODE_CTX;
 procedure EVP_EncodeInit( ctx : PEVP_ENCODE_CTX);
 function EVP_EncodeUpdate(ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger;_in : PByte; inl : integer):integer;
 function evp_encodeblock_int(ctx : PEVP_ENCODE_CTX; t : PByte; f : PByte; dlen : integer):integer;
  procedure EVP_EncodeFinal( ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger);
 procedure EVP_ENCODE_CTX_free( ctx : PEVP_ENCODE_CTX);
  procedure EVP_DecodeInit( ctx : PEVP_ENCODE_CTX);
 function EVP_DecodeUpdate(ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger;{const} _in : PByte; inl : integer):integer;
 function evp_decodeblock_int(ctx : PEVP_ENCODE_CTX; t : PByte; f : PByte; n : integer):integer;
 function conv_ascii2bin(a : Byte;const table : PByte):Byte;
 function EVP_DecodeFinal( ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger):integer;
 function EVP_DecodeBlock(t : PByte;const f : PByte; n : integer):integer;

function EVP_EncodeBlock(t : PByte;const f : PByte; dlen : integer):integer;
function EVP_ENCODE_CTX_num( ctx : PEVP_ENCODE_CTX):integer;

implementation

uses openssl3.crypto.mem, openssl3.crypto.evp;




function EVP_ENCODE_CTX_num( ctx : PEVP_ENCODE_CTX):integer;
begin
    Result := ctx.num;
end;




function EVP_EncodeBlock(t : PByte;const f : PByte; dlen : integer):integer;
begin
    Result := evp_encodeblock_int(nil, t, f, dlen);
end;



function EVP_DecodeBlock(t : PByte;const f : PByte; n : integer):integer;
begin
    Result := evp_decodeblock_int(nil, t, f, n);
end;


function EVP_DecodeFinal( ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger):integer;
var
  i : integer;
begin
    outl^ := 0;
    if ctx.num <> 0 then
    begin
        i := evp_decodeblock_int(ctx, _out, @ctx.enc_data, ctx.num);
        if i < 0 then
           Exit(-1);
        ctx.num := 0;
        outl^ := i;
        Exit(1);
    end
    else
        Result := 1;
end;

function B64_NOT_BASE64(a: int): Boolean;
begin
   Result := (a or $13) = $F3;
end;

function B64_BASE64(a: int): Boolean;
begin
  Result := (not B64_NOT_BASE64(a));
end;


{$ifndef CHARSET_EBCDIC}
function conv_ascii2bin(a : Byte;const table : PByte):Byte;
begin
    if (a and $80) > 0 then
       Exit(B64_ERROR);
    Result := table[a];
end;
{$ELSE}

function conv_ascii2bin(a : Byte;const table : PByte):Byte;
var
  table : array[0..(a)-1] of return;
begin
    a := os_toascii[a];
    if a and $80 then Exit(B64_ERROR);
    Result := table[a];
end;
{$ENDIF}


function evp_decodeblock_int(ctx : PEVP_ENCODE_CTX; t : PByte; f : PByte; n : integer):integer;
var
  i, a, b, c, d, ret : integer;
  table: PByte;
  l : Cardinal;
begin
    ret := 0;
    if (ctx <> nil)  and  ( (ctx.flags and EVP_ENCODE_CTX_USE_SRP_ALPHABET) <> 0)  then
        table := @srpdata_ascii2bin
    else
        table := @data_ascii2bin;
    { trim whitespace from the start of the line. }
    while (n > 0)  and  (conv_ascii2bin(f^, table) = B64_WS) do
    begin
        Inc(f);
        Dec(n);
    end;
    {
     * strip off stuff at the end of the line ascii2bin values B64_WS,
     * B64_EOLN, B64_EOLN and B64_EOF
     }
    while (n > 3)  and  (B64_NOT_BASE64(conv_ascii2bin(f[n - 1], table))) do
        Dec(n);
    if n mod 4 <> 0 then
       Exit(-1);
    i := 0;
    while i < n do
    begin
        a := conv_ascii2bin( PostInc(f)^, table);
        b := conv_ascii2bin( PostInc(f)^, table);
        c := conv_ascii2bin( PostInc(f)^, table);
        d := conv_ascii2bin( PostInc(f)^, table);
        if ( (a and $80) > 0) or ( (b and $80) > 0 )  or
           ( (c and $80) > 0) or ( (d and $80) > 0 ) then
            Exit(-1);
        l := (ulong(a)  shl  18) or
             (ulong(b)  shl  12) or
             (ulong(c)  shl  6 ) or (ulong(d));
        PostInc(t)^ := Byte(l  shr  16) and $ff;
        PostInc(t)^ := Byte(l  shr  8) and $ff;
        PostInc(t)^ := Byte(l) and $ff;
        ret  := ret + 3;
        i := i + 4;
    end;
    Result := ret;
end;


function EVP_DecodeUpdate(ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger;{const} _in : PByte; inl : integer):integer;
var
  seof,   eof,
  rv,   ret,
  i,   v,
  tmp,   n,
  decoded_len : integer;
  d,
  table       : PByte;
  label _end, _tail;
begin
    seof := 0;
    eof := 0;
    rv := -1;
    ret := 0;
    n := ctx.num;
    d := @ctx.enc_data;
    if (n > 0)  and  (d[n - 1] = ord('=')) then
    begin
        Inc(eof);
        if (n > 1)  and  (d[n - 2] = Ord('=')) then
           Inc(eof);
    end;
     { Legacy behaviour: an empty input chunk signals end of input. }
    if inl = 0 then
    begin
        rv := 0;
        goto _end ;
    end;
    if (ctx.flags and EVP_ENCODE_CTX_USE_SRP_ALPHABET) <> 0 then
        table := @srpdata_ascii2bin
    else
        table := @data_ascii2bin;
    for i := 0 to inl-1 do
    begin
        tmp := PostInc(_in)^;
      
        v := conv_ascii2bin(tmp, table);
        if v = B64_ERROR then
        begin
            rv := -1;
            goto _end ;
        end;
        if tmp = Ord('=') then
        begin
            Inc(eof);
        end
        else
        if (eof > 0)  and  (B64_BASE64(v)) then
        begin
            { More data after padding. }
            rv := -1;
            goto _end ;
        end;
        if eof > 2 then
        begin
            rv := -1;
            goto _end ;
        end;
        if v = B64_EOF then
        begin
            seof := 1;
            goto _tail ;
        end;
        { Only save valid base64 characters. }
        if B64_BASE64(v) then
        begin
            if n >= 64 then
            begin
                {
                 * We increment n once per loop, and empty the buffer as soon as
                 * we reach 64 characters, so this can only happen if someone's
                 * manually messed with the ctx. Refuse to write any more data.
                 }
                rv := -1;
                goto _end ;
            end;
            assert(n < int (sizeof(ctx.enc_data)));
            d[PostInc(n)] := tmp;
        end;
        if n = 64 then
        begin
            decoded_len := evp_decodeblock_int(ctx, _out, d, n);
            n := 0;
            if (decoded_len < 0)  or  (eof > decoded_len) then
            begin
                rv := -1;
                goto _end ;
            end;
            ret  := ret + (decoded_len - eof);
            _out  := _out + (decoded_len - eof);
        end;
    end; //-->for i := 0 to inl-1
    {
     * Legacy behaviour: if the current line is a full base64-block (i.e., has
     * 0 mod 4 base64 characters), it is processed immediately. We keep this
     * behaviour as applications may not be calling EVP_DecodeFinal properly.
     }
_tail:
    if n > 0 then
    begin
        if (n and 3) = 0 then
        begin
            decoded_len := evp_decodeblock_int(ctx, _out, d, n);
            n := 0;
            if (decoded_len < 0)  or  (eof > decoded_len) then
            begin
                rv := -1;
                goto _end ;
            end;
            ret  := ret + ((decoded_len - eof));
        end
        else if (seof>0) then
        begin
            { EOF in the middle of a base64 block. }
            rv := -1;
            goto _end ;
        end;
    end;
    rv := int( (seof>0)  or  (get_result( (n = 0)  and (eof>0) , 0 , 1) > 0));
_end:
    { Legacy behaviour. This should probably rather be zeroed on error. }
    outl^ := ret;
    ctx.num := n;
    Result := rv;
end;

procedure EVP_DecodeInit( ctx : PEVP_ENCODE_CTX);
begin
    { Only ctx.num and ctx.flags are used during decoding. }
    ctx.num := 0;
    ctx.length := 0;
    ctx.line_num := 0;
    ctx.flags := 0;
end;


procedure EVP_ENCODE_CTX_free( ctx : PEVP_ENCODE_CTX);
begin
    OPENSSL_free(Pointer(ctx));
end;



procedure EVP_EncodeFinal( ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger);
var
  ret : uint32;
begin
    ret := 0;
    if ctx.num <> 0 then
    begin
        ret := evp_encodeblock_int(ctx, _out, @ctx.enc_data, ctx.num);
        if (ctx.flags and EVP_ENCODE_CTX_NO_NEWLINES) = 0 then
        begin
            _out[ret] := Ord(#10);
            Inc(ret);
        end;
        _out[ret] := Ord(#0);
        ctx.num := 0;
    end;
    outl^ := ret;
end;

{$ifndef CHARSET_EBCDIC}
function conv_bin2ascii(a: ulong; table: Pbyte): Byte;
begin
   Result := table[(a) and $3f];
end;
{$else}
(*
 * We assume that PEM encoded files are EBCDIC files (i.e., printable text
 * files). Convert them here while decoding. When encoding, output is EBCDIC
 * (text) format again. (No need for conversion in the conv_bin2ascii macro,
 * as the underlying textstring data_bin2ascii[] is already EBCDIC)
 *)
conv_bin2ascii(a, table)       ((table)[(a)&0x3f])
{$endif}


function evp_encodeblock_int(ctx : PEVP_ENCODE_CTX; t : PByte; f : PByte; dlen : integer):integer;
var
  i, ret : integer;
  l : Cardinal;
  table : PByte;
  data: TBytes;
begin
    ret := 0;
    if (ctx <> nil)  and ( (ctx.flags and EVP_ENCODE_CTX_USE_SRP_ALPHABET) <> 0) then
    begin
        data  := StrToBytes(srpdata_bin2ascii);
        table := PByte(data);
    end
    else
    begin
        data := StrToBytes(data_bin2ascii);
        table := PByte(data);
    end;
    i := dlen;
    while i > 0 do
    begin
        if i >= 3 then
        begin
            l := (ulong(f[0])  shl  16) or
                 (ulong(f[1])  shl  8 ) or f[2];
            PostInc(t)^ := conv_bin2ascii(l  shr  18, table);
            PostInc(t)^ := conv_bin2ascii(l  shr  12, table);
            PostInc(t)^ := conv_bin2ascii(l  shr  6, table);
            PostInc(t)^ := conv_bin2ascii(l, table);
        end
        else
        begin
            l := ulong(f[0])  shl  16;
            if i = 2 then
               l  := l  or (ulong(f[1])  shl  8);
            PostInc(t)^ := conv_bin2ascii(l  shr  18, table);
            PostInc(t)^ := conv_bin2ascii(l  shr  12, table);
            PostInc(t)^ := get_result(i = 1 , Ord('=') , conv_bin2ascii(l  shr  6, table));
            PostInc(t)^ := Ord('=');
        end;
        ret  := ret + 4;
        f  := f + 3;
        i := i - 3;
    end;
    t^ := Ord(#0);
    SetLength(data, 0);
    Result := ret;
end;

function EVP_EncodeUpdate(ctx : PEVP_ENCODE_CTX; _out : PByte; outl : PInteger;_in : PByte; inl : integer):integer;
var
  i, j : integer;

  total : size_t;
begin
    total := 0;
    outl^ := 0;
    if inl <= 0 then
       Exit(0);
    assert(ctx.length <= int (sizeof(ctx.enc_data)));
    if ctx.length - ctx.num > inl then
    begin
        memcpy(@(ctx.enc_data[ctx.num]), _in, inl);
        ctx.num  := ctx.num + inl;
        Exit(1);
    end;
    if ctx.num <> 0 then
    begin
        i := ctx.length - ctx.num;
        memcpy(@(ctx.enc_data[ctx.num]), _in, i);
        _in  := _in + i;
        inl  := inl - i;
        j := evp_encodeblock_int(ctx, _out, @ctx.enc_data, ctx.length);
        ctx.num := 0;
        _out  := _out + j;
        total := j;
        if (ctx.flags and EVP_ENCODE_CTX_NO_NEWLINES) = 0 then
        begin
            PostInc(_out)^ := Ord(#10);
            Inc(total);
        end;
        _out^ := Ord(#0);
    end;
    while (inl >= ctx.length)  and  (total <= INT_MAX) do
    begin
        j := evp_encodeblock_int(ctx, _out, _in, ctx.length);
        _in  := _in + ctx.length;
        inl  := inl - ctx.length;
        _out  := _out + j;
        total  := total + j;
        if (ctx.flags and EVP_ENCODE_CTX_NO_NEWLINES) = 0 then
        begin
            PostInc(_out)^ := Ord(#10);
            Inc(total);
        end;
        _out^ := Ord(#0);
    end;
    if total > INT_MAX then
    begin
        { Too much output data! }
        outl^ := 0;
        Exit(0);
    end;
    if inl <> 0 then
       memcpy(@(ctx.enc_data[0]), _in, inl);
    ctx.num := inl;
    outl^ := total;
    Result := 1;
end;




procedure EVP_EncodeInit( ctx : PEVP_ENCODE_CTX);
begin
    ctx.length := 48;
    ctx.num := 0;
    ctx.line_num := 0;
    ctx.flags := 0;
end;

function EVP_ENCODE_CTX_new:PEVP_ENCODE_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(TEVP_ENCODE_CTX));
end;

end.
