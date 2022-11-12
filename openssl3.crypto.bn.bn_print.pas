unit openssl3.crypto.bn.bn_print;

interface
uses OpenSSL.Api;

function BN_print_fp(fp : PFILE;const a : PBIGNUM):integer;
function BN_print(bp : PBIO;const a : PBIGNUM):integer;
function BN_options:PUTF8Char;

const
   Hex: PUTF8Char = '0123456789ABCDEF';

var
  init: int  = 0;
  data: array[0..16-1] of UTF8char ;

implementation
uses openssl3.crypto.bio.bio_lib, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bio.bss_file, openssl3.crypto.bio.bio_print;





function BN_print_fp(fp : PFILE;const a : PBIGNUM):integer;
var
  b : PBIO;
  ret : integer;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then
        Exit(0);
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret := BN_print(b, a);
    BIO_free(b);
    Result := ret;
end;


function BN_print(bp : PBIO;const a : PBIGNUM):integer;
var
  i, j, v, z, ret : integer;
  label _end;
begin
{$POINTERMATH ON}
    z := 0;
    ret := 0;
    if (a.neg > 0)  and  (BIO_write(bp, PUTF8Char('-'), 1) <> 1) then
        goto _end ;
    if (BN_is_zero(a))  and  (BIO_write(bp, PUTF8Char('0'), 1) <> 1) then
        goto _end ;
    for i := a.top - 1 downto 0 do
    begin
        j := BN_BITS2 - 4;
        while j >= 0 do
        begin
            { strip leading zeros }
            v := int ((a.d[i]  shr  j) and $0f);
            if (z >0)  or  (v <> 0) then
            begin
                if BIO_write(bp, @Hex[v], 1) <> 1 then
                    goto _end ;
                z := 1;
            end;
            j := j-4;
        end;

    end;
    ret := 1;
 _end:
    Result := ret;
{$POINTERMATH OFF}
end;


function BN_options:PUTF8Char;
begin

    if 0>= init then
    begin
        Inc(init);
{$IFDEF BN_LLONG}
        BIO_snprintf(data, sizeof(data), 'bn(%zu,%zu)',
                     sizeof(BN_ULLONG) * 8, sizeof(BN_ULONG) * 8);
{$ELSE} BIO_snprintf(data, sizeof(data), 'bn(%zu,%zu)',
                     [sizeof(BN_ULONG) * 8, sizeof(BN_ULONG) * 8]);
{$ENDIF}
    end;
    Result := data;
end;


end.
