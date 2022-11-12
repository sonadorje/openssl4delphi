unit openssl3.crypto.params_from_text;

interface
uses OpenSSL.Api;

function prepare_from_text(const paramdefs : POSSL_PARAM; key : PUTF8Char; value : PUTF8Char; value_n : size_t;const paramdef : PPOSSL_PARAM; ishex : Pinteger; buf_n : psize_t; tmpbn : PPBIGNUM; found : Pinteger):integer;
function OSSL_PARAM_allocate_from_text(_to : POSSL_PARAM;const paramdefs : POSSL_PARAM; key, value : PUTF8Char; value_n : size_t;found : Pinteger):Int;
function construct_from_text(_to : POSSL_PARAM;const paramdef : POSSL_PARAM; value : PUTF8Char; value_n : size_t; ishex : integer; buf : Pointer; buf_n : size_t; tmpbn : PBIGNUM):integer;

implementation
uses OpenSSL3.common, openssl3.crypto.params, openssl3.crypto.bn.bn_conv,
     OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.o_str, openssl3.crypto.bn.bn_word;


function construct_from_text(_to : POSSL_PARAM;const paramdef : POSSL_PARAM; value : PUTF8Char; value_n : size_t; ishex : integer; buf : Pointer; buf_n : size_t; tmpbn : PBIGNUM):integer;
var
  cp : Pbyte;

  i, l : size_t;
begin
    if buf = nil then Exit(0);
    if buf_n > 0 then
    begin
        case paramdef.data_type of
        OSSL_PARAM_INTEGER,
        OSSL_PARAM_UNSIGNED_INTEGER:
        begin
            BN_bn2nativepad(tmpbn, buf, buf_n);
            {
             * 2's complement negation, part two.
             *
             * Because we did the first part on the BIGNUM itself, we can just
             * invert all the bytes here and be done with it.
             }
            if (paramdef.data_type = OSSL_PARAM_INTEGER)
                 and  (BN_is_negative(tmpbn)>0  )then
            begin
                i := buf_n;
                cp := buf;
                while PostDec(i) > 0 do
                begin
                    cp^  := cp^ xor $FF;
                    Inc(cp);
                end;
            end;
        end;
        OSSL_PARAM_UTF8_STRING:
        begin
{$IFDEF CHARSET_EBCDIC}
            ebcdic2ascii(buf, value, buf_n);
{$ELSE}
            strncpy(buf, value, buf_n);
{$ENDIF}
            { Don't count the terminating NUL byte as data }
            Dec(buf_n);
        end;
        OSSL_PARAM_OCTET_STRING:
            if ishex>0 then
            begin
                l := 0;
                if  0>= OPENSSL_hexstr2buf_ex(buf, buf_n, @l, value, ':')  then
                    Exit(0);
            end
            else
            begin
                memcpy(buf, value, buf_n);
            end;

        end;
    end;
    _to^ := paramdef^;
    _to.data := buf;
    _to.data_size := buf_n;
    _to.return_size := OSSL_PARAM_UNMODIFIED;
    Result := 1;
end;



function OSSL_PARAM_allocate_from_text(_to : POSSL_PARAM;const paramdefs : POSSL_PARAM; key, value : PUTF8Char; value_n : size_t;found : Pinteger):Int;
var
    paramdef : POSSL_PARAM;
    ishex    : integer;
    buf      : Pointer;
    buf_n    : size_t;
    tmpbn    : PBIGNUM;
    ok       : integer;

    label err;

begin
    paramdef := nil;
    ishex := 0;
    buf := nil;
    buf_n := 0;
    tmpbn := nil;
    ok := 0;
    if (_to = nil)  or  (paramdefs = nil) then Exit(0);
    if  0>= prepare_from_text(paramdefs, key, value, value_n,
                           @paramdef, @ishex, @buf_n, @tmpbn, found) then
       goto err;
    buf := OPENSSL_zalloc(get_result( buf_n > 0 , buf_n , 1));
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    end;
    ok := construct_from_text(_to, paramdef, value, value_n, ishex,
                             buf, buf_n, tmpbn);
    BN_free(tmpbn);
    if  0>= ok then
       OPENSSL_free(buf);
    Exit(ok);
 err:
    BN_free(tmpbn);
    Result := 0;
end;

function prepare_from_text(const paramdefs : POSSL_PARAM; key : PUTF8Char; value : PUTF8Char; value_n : size_t;const paramdef : PPOSSL_PARAM; ishex : Pinteger; buf_n : psize_t; tmpbn : PPBIGNUM; found : Pinteger):integer;
var
    p        : POSSL_PARAM;
    buf_bits : size_t;
    r        : integer;
begin
    {
     * ishex is used to translate legacy style string controls in hex format
     * to octet string parameters.
     }
    ishex^ := CHECK_AND_SKIP_PREFIX(key, 'hex');
    paramdef^ := OSSL_PARAM_locate_const(paramdefs, key);
    p := paramdef^;
    if found <> nil then
       found^ := Int(p <> nil);
    if p = nil then
       Exit(0);

    case p.data_type of
        OSSL_PARAM_INTEGER,
        OSSL_PARAM_UNSIGNED_INTEGER:
        begin
            if ishex^ > 0 then
               r := BN_hex2bn(tmpbn, value)
            else
                r := BN_asc2bn(tmpbn, value);
            if (r = 0)  or  (tmpbn^ = nil) then
                Exit(0);
            if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER)   and
               (BN_is_negative( tmpbn^)>0)  then
            begin
                ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_INVALID_NEGATIVE_VALUE);
                Exit(0);
            end;
            {
             * 2's complement negate, part 1
             *
             * BN_bn2nativepad puts the absolute value of the number in the
             * buffer, i.e. if it's negative, we need to deal with it.  We do
             * it by subtracting 1 here and inverting the bytes in
             * construct_from_text() below.
             * To subtract 1 from an absolute value of a negative number we
             * actually have to add 1: -3 - 1 = -4, |-3| = 3 + 1 = 4.
             }
            if (p.data_type = OSSL_PARAM_INTEGER)  and
               ( BN_is_negative( tmpbn^)>0)  and
               (0>= BN_add_word( tmpbn^, 1)) then
            begin
                Exit(0);
            end;
            buf_bits := size_t(BN_num_bits( tmpbn^));
            {
             * Compensate for cases where the most significant bit in
             * the resulting OSSL_PARAM buffer will be set after the
             * BN_bn2nativepad() call, as the implied sign may not be
             * correct after the second part of the 2's complement
             * negation has been performed.
             * We fix these cases by extending the buffer by one byte
             * (8 bits), which will give some padding.  The second part
             * of the 2's complement negation will do the rest.
             }
            if (p.data_type = OSSL_PARAM_INTEGER)  and
               (buf_bits mod 8 = 0 ) then
               buf_bits  := buf_bits + 8;
            buf_n^ := (buf_bits + 7) div 8;
            {
             * A zero data size means 'arbitrary size', so only do the
             * range checking if a size is specified.
             }
            if p.data_size > 0 then
            begin
                if buf_bits > p.data_size * 8 then
                begin
                    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
                    { Since this is a different error, we don't break }
                    Exit(0);
                end;
                { Change actual size to become the desired size. }
                buf_n^ := p.data_size;
            end;
        end;
        OSSL_PARAM_UTF8_STRING:
        begin
            if ishex^>0 then
            begin
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
                Exit(0);
            end;
            buf_n^ := Length(value) + 1;
        end;
        OSSL_PARAM_OCTET_STRING:
        begin
            if ishex^>0 then
            begin
                buf_n^ := Length(value)  shr  1;
            end
            else
            begin
                buf_n^ := value_n;
            end;
        end;
    end;
    Result := 1;
end;

end.
