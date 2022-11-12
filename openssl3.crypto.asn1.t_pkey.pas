unit openssl3.crypto.asn1.t_pkey;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
   ASN1_BUF_PRINT_WIDTH  =   15;
   ASN1_PRINT_MAX_INDENT = 128;

function ASN1_buf_print(bp : PBIO;const buf : PByte; buflen : size_t; indent : integer):integer;
function ASN1_bn_print(bp : PBIO;const number : PUTF8Char; num : PBIGNUM; ign : PByte; indent : integer):integer;

implementation
uses openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_intern,
     openssl3.crypto.mem;

function ASN1_buf_print(bp : PBIO;const buf : PByte; buflen : size_t; indent : integer):integer;
var
  i : size_t;
begin
    for i := 0 to buflen-1 do
    begin
        if (i mod ASN1_BUF_PRINT_WIDTH)  = 0 then
        begin
            if (i > 0)  and  (BIO_puts(bp, #10) <= 0) then
                Exit(0);
            if 0>= BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT) then
                Exit(0);
        end;
        {
         * Use colon separators for each octet for compatibility as
         * this function is used to print out key components.
         }
        if BIO_printf(bp, '%02x%s', [buf[i],
                      get_result (i = buflen - 1 , '' , ':')]) <= 0 then
                Exit(0);
    end;
    if BIO_write(bp, PUTF8Char(#10), 1 ) <= 0 then
        Exit(0);
    Result := 1;
end;


function ASN1_bn_print(bp : PBIO;const number : PUTF8Char; num : PBIGNUM; ign : PByte; indent : integer):integer;
var
  n, rv : integer;

  buf, tmp : PByte;
  neg: PUTF8Char;
  buflen : integer;
  label _err;
begin
{$POINTERMATH ON}
    rv := 0;
    buf := nil; tmp :=nil;
    if num = nil then Exit(1);
    if BN_is_negative(num) > 0 then
       neg :=  '-'
    else
       neg :=   '';

    if 0>= BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT) then
        Exit(0);
    if BN_is_zero(num) then
    begin
        if BIO_printf(bp, '%s 0'#10, [number]) <= 0 then
            Exit(0);
        Exit(1);
    end;
    if BN_num_bytes(num) <= BN_BYTES  then
    begin
        if BIO_printf(bp, '%s %s%lu (%s0x%lx)'#10, [number, neg,
                       ulong (bn_get_words(num)[0]), neg,
                       ulong (bn_get_words(num)[0])]) <= 0 then
            Exit(0);
        Exit(1);
    end;
    buflen := BN_num_bytes(num) + 1;
    tmp := OPENSSL_malloc(buflen);
    buf := tmp;
    if buf = nil then goto _err ;
    buf[0] := 0;
    if BIO_printf(bp, '%s%s\n', [number,
                  get_result (neg[0] = '-' , ' (Negative)',  '')]) <= 0 then
        goto _err ;
    n := BN_bn2bin(num, buf + 1);
    if (buf[1] and $80) > 0 then
       Inc(n)
    else
       Inc(tmp);
    if ASN1_buf_print(bp, tmp, n, indent + 4) = 0  then
        goto _err ;
    rv := 1;
_err:
    OPENSSL_clear_free(Pointer(buf), buflen);
    Result := rv;
{$POINTERMATH OFF}
end;



end.
