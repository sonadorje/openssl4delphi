unit openssl3.crypto.modes.wrap128;

interface
uses OpenSSL.Api, SysUtils;

const
  CRYPTO128_WRAP_MAX = ULONG(1) shl 31;
  default_aiv: array[0..3] of Byte= ($A6, $59, $59, $A6);
  default_iv: array[0..7] of Byte= ($A6, $A6, $A6, $A6, $A6, $A6, $A6, $A6);

 function CRYPTO_128_wrap_pad(key : Pointer;{const} icv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
 function CRYPTO_128_unwrap_pad(key : Pointer;{const} icv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
 function CRYPTO_128_wrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
 function crypto_128_unwrap_raw(key : Pointer; iv, _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;

function CRYPTO_128_unwrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;

implementation
uses openssl3.crypto.mem, {$IFDEF MSWINDOWS}libc.win,{$ENDIF}openssl3.crypto.cpuid;





function CRYPTO_128_unwrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  ret : size_t;
  got_iv : array[0..7] of Byte;
begin
    ret := crypto_128_unwrap_raw(key, @got_iv, _out, _in, inlen, block);
    if ret = 0 then Exit(0);
    if nil=iv then iv := @default_iv;
    if CRYPTO_memcmp(@got_iv, iv, 8)>0 then  begin
        OPENSSL_cleanse(Pointer(_out), ret);
        Exit(0);
    end;
    Result := ret;
end;

function crypto_128_unwrap_raw(key : Pointer; iv, _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  i, j, t : size_t;
  A : PByte;
  B : array[0..15] of Byte;
  R : PByte;
begin

    inlen  := inlen - 8;
    if (inlen and $7 > 0)  or  (inlen < 16)  or  (inlen > CRYPTO128_WRAP_MAX) then
        Exit(0);
    A := @B;
    t := 6 * (inlen  shr  3);
    memcpy(A, _in, 8);
    memmove(_out, _in + 8, inlen);
    for j := 0 to 5 do
    begin
        R := _out + inlen - 8;
        i := 0;
        while i < inlen do
        begin
            A[7]  := A[7] xor (Byte(t and $ff));
            if t > $ff then begin
                A[6]  := A[6] xor (Byte((t  shr  8) and $ff));
                A[5]  := A[5] xor (Byte((t  shr  16) and $ff));
                A[4]  := A[4] xor (Byte((t  shr  24) and $ff));
            end;
            memcpy(PByte(@B) + 8, R, 8);
            block(@B, @B, key);
            memcpy(R, PByte(@B) + 8, 8);
            i := i+ 8;
            Dec(t);
            R := R - 8;
        end;
    end;
    memcpy(iv, A, 8);
    Result := inlen;
end;


function CRYPTO_128_wrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  A : PByte;
  B : array[0..15] of Byte;
  R : PByte;
  i, j, t : size_t;
begin
    if (inlen and $7 > 0) or  (inlen < 16)  or  (inlen > CRYPTO128_WRAP_MAX) then
        Exit(0);
    A := @B;
    t := 1;
    memmove(_out + 8, _in, inlen);
    if nil=iv then
       iv := @default_iv;
    memcpy(A, iv, 8);
    for j := 0 to 5 do
    begin
        R := _out + 8;
        i := 0;
        while i < inlen do
        begin
            memcpy(PByte(@B) + 8, R, 8);
            block(@B, @B, key);
            A[7]  := A[7] xor Byte(t and $ff);
            if t > $ff then begin
                A[6]  := A[6] xor (Byte((t  shr  8) and $ff));
                A[5]  := A[5] xor (Byte((t  shr  16) and $ff));
                A[4]  := A[4] xor (Byte((t  shr  24) and $ff));
            end;
            memcpy(R, PByte(@B) + 8, 8);
            i := i+8;
            Inc(t);
            R := R + 8;
        end;
    end;
    memcpy(_out, A, 8);
    Result := inlen + 8;
end;


function CRYPTO_128_wrap_pad(key : Pointer;{const} icv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  blocks_padded,
  padded_len,
  padding_len   : size_t;
  aiv           : array[0..7] of Byte;
  ret           : integer;
begin
    { n: number of 64-bit blocks in the padded key data
     *
     * If length of plain text is not a multiple of 8, pad the plain text octet
     * string on the right with octets of zeros, where final length is the
     * smallest multiple of 8 that is greater than length of plain text.
     * If length of plain text is a multiple of 8, then there is no padding. }
    blocks_padded := (inlen + 7) div 8;
    padded_len := blocks_padded * 8;
    padding_len := padded_len - inlen;
    { RFC 5649 section 3: Alternative Initial Value }
    { Section 1: use 32-bit fixed field for plaintext octet length }
    if (inlen = 0)  or  (inlen >= CRYPTO128_WRAP_MAX) then
       Exit(0);
    { Section 3: Alternative Initial Value }
    if nil =icv then
       memcpy(@aiv, @default_aiv, 4)
    else
        memcpy(@aiv, icv, 4);    { Standard doesn't mention this. }
    aiv[4] := (inlen  shr  24) and $FF;
    aiv[5] := (inlen  shr  16) and $FF;
    aiv[6] := (inlen  shr  8) and $FF;
    aiv[7] := inlen and $FF;
    if padded_len = 8 then
    begin
        {
         * Section 4.1 - special case in step 2: If the padded plaintext
         * contains exactly eight octets, then prepend the AIV and encrypt
         * the resulting 128-bit block using AES in ECB mode.
         }
        memmove(_out + 8, _in, inlen);
        memcpy(_out, @aiv, 8);
        memset(_out + 8 + inlen, 0, padding_len);
        block(_out, _out, key);
        ret := 16;               { AIV + padded input }
    end
    else
    begin
        memmove(_out, _in, inlen);
        memset(_out + inlen, 0, padding_len); { Section 4.1 step 1 }
        ret := CRYPTO_128_wrap(key, @aiv, _out, _out, padded_len, block);
    end;
    Result := ret;
end;


function CRYPTO_128_unwrap_pad(key : Pointer;{const} icv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  n,
  padded_len,
  padding_len,
  ptext_len   : size_t;
  aiv,
  zeros       : array[0..7] of Byte;
  ret         : size_t;
  buff        : array[0..15] of Byte;
  pb: PByte;
begin
    { n: number of 64-bit blocks in the padded key data }
    n := inlen div 8 - 1;
    { RFC 5649 section 3: Alternative Initial Value }
   FillChar(zeros, 8, 0);

    { Section 4.2: Ciphertext length has to be (n+1) 64-bit blocks. }
    if (inlen and $7 <> 0)  or  (inlen < 16)  or  (inlen >= CRYPTO128_WRAP_MAX) then
        Exit(0);
    if inlen = 16 then
    begin
        {
         * Section 4.2 - special case in step 1: When n=1, the ciphertext
         * contains exactly two 64-bit blocks and they are decrypted as a
         * single AES block using AES in ECB mode: AIV or P[1] = DEC(K, C[0] or
         * C[1])
         }
        block(_in, @buff, key);
        memcpy(@aiv, @buff, 8);
        { Remove AIV }
        memcpy(_out, PByte(@buff) + 8, 8);
        padded_len := 8;
        pb := @buff;
        OPENSSL_cleanse(Pointer(pb), inlen);
    end
    else
    begin
        padded_len := inlen - 8;
        ret := crypto_128_unwrap_raw(key, @aiv, _out, _in, inlen, block);
        if padded_len <> ret then
        begin
            OPENSSL_cleanse(Pointer(_out), inlen);
            Exit(0);
        end;
    end;
    {
     * Section 3: AIV checks: Check that MSB(32,A) = A65959A6. Optionally a
     * user-supplied value can be used (even if standard doesn't mention
     * this).
     }
    if ( (nil=icv)  and  (CRYPTO_memcmp(@aiv, @default_aiv, 4) > 0) )  or
       ( (icv <> nil)  and  (CRYPTO_memcmp(@aiv, icv, 4) > 0)) then
    begin
        OPENSSL_cleanse(Pointer(_out), inlen);
        Exit(0);
    end;
    {
     * Check that 8*(n-1) < LSB(32,AIV) <= 8*n. If so, let ptext_len =
     * LSB(32,AIV).
     }
    ptext_len := (uint32(aiv[4] shl 24))
                or (uint32(aiv[5] shl 16))
                or (uint32(aiv[6] shl  8))
                or  uint32(aiv[7]);
    if (8 * (n - 1) >= ptext_len)  or ( ptext_len > 8 * n)  then
    begin
        OPENSSL_cleanse(Pointer(_out), inlen);
        Exit(0);
    end;
    {
     * Check that the rightmost padding_len octets of the output data are
     * zero.
     }
    padding_len := padded_len - ptext_len;
    if CRYPTO_memcmp(_out + ptext_len, @zeros, padding_len) <> 0  then
    begin
        OPENSSL_cleanse(Pointer(_out), inlen);
        Exit(0);
    end;
    { Section 4.2 step 3: Remove padding }
    Result := ptext_len;
end;


end.
