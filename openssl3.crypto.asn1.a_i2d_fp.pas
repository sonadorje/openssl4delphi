unit openssl3.crypto.asn1.a_i2d_fp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function ASN1_i2d_fp(i2d : Ti2d_of_void;_out : PFILE;const x : Pointer):integer;
  function ASN1_i2d_bio(i2d : Ti2d_of_void; _out : PBIO;const x : Pointer):integer;
  function ASN1_item_i2d_fp(const it : PASN1_ITEM;_out : PFILE;const x : Pointer):integer;
  function ASN1_item_i2d_bio(const it : PASN1_ITEM; _out : PBIO;const x : Pointer):integer;
  function ASN1_item_i2d_mem_bio(const it : PASN1_ITEM; val : PASN1_VALUE):PBIO;

implementation

uses OpenSSL3.Err,                  openssl3.crypto.mem,
     openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.bio.bio_lib,   openssl3.crypto.bio.bss_file,
     openssl3.crypto.bio.bss_mem;

function ASN1_i2d_fp(i2d : Ti2d_of_void;_out : PFILE;const x : Pointer):integer;
var
  b : PBIO;

  ret : integer;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_BUF_LIB);
        Exit(0);
    end;
    BIO_set_fp(b, _out, BIO_NOCLOSE);
    ret := ASN1_i2d_bio(i2d, b, x);
    BIO_free(b);
    Result := ret;
end;


function ASN1_i2d_bio(i2d : Ti2d_of_void; _out : PBIO;const x : Pointer):integer;
var
  b : PUTF8Char;
  p : PByte;
  i, j, n, ret : integer;
begin
    j := 0; ret := 1;

    n := i2d(x, nil);
    if n <= 0 then Exit(0);
    b := OPENSSL_malloc(n);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    p := PByte( b);
    i2d(x, @p);
    while true do
    begin
        i := BIO_write(_out, @(b[j]), n);
        if i = n then break;
        if i <= 0 then
        begin
            ret := 0;
            break;
        end;
        j  := j + i;
        n  := n - i;
    end;
    OPENSSL_free(b);
    Result := ret;
end;


function ASN1_item_i2d_fp(const it : PASN1_ITEM;_out : PFILE;const x : Pointer):integer;
var
  b : PBIO;

  ret : integer;
begin
    b := BIO_new(BIO_s_file());
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_BUF_LIB);
        Exit(0);
    end;
    BIO_set_fp(b, _out, BIO_NOCLOSE);
    ret := ASN1_item_i2d_bio(it, b, x);
    BIO_free(b);
    Result := ret;
end;


function ASN1_item_i2d_bio(const it : PASN1_ITEM; _out : PBIO;const x : Pointer):integer;
var
  b : PByte;
  i, j, n, ret : integer;
begin
    b := nil;
    j := 0; ret := 1;
    n := ASN1_item_i2d(x, @b, it);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    while true do
    begin
        i := BIO_write(_out, @(b[j]), n);
        if i = n then break;
        if i <= 0 then begin
            ret := 0;
            break;
        end;
        j  := j + i;
        n  := n - i;
    end;
    OPENSSL_free(b);
    Result := ret;
end;


function ASN1_item_i2d_mem_bio(const it : PASN1_ITEM; val : PASN1_VALUE):PBIO;
var
  res : PBIO;
begin
    if (it = nil)  or  (val = nil) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    res := BIO_new(BIO_s_mem());
    if res = nil then
        Exit(nil);
    if ASN1_item_i2d_bio(it, res, val) <= 0  then
    begin
        BIO_free(res);
        res := nil;
    end;
    Result := res;
end;



end.
