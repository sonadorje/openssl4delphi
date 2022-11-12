unit openssl3.crypto.bio.ossl_core_bio;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_core_bio_new_from_bio( bio : PBIO):POSSL_CORE_BIO;
function ossl_core_bio_free( cb : POSSL_CORE_BIO):integer;
function core_bio_new:POSSL_CORE_BIO;

function ossl_core_bio_new_file(const filename, mode : PUTF8Char):POSSL_CORE_BIO;
function core_bio_new_from_new_bio( bio : PBIO):POSSL_CORE_BIO;
function ossl_core_bio_new_mem_buf(const buf : Pointer; len : integer):POSSL_CORE_BIO;
function ossl_core_bio_read_ex( cb : POSSL_CORE_BIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
function ossl_core_bio_write_ex(cb : POSSL_CORE_BIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
function ossl_core_bio_gets( cb : POSSL_CORE_BIO; buf : PUTF8Char; size : integer):integer;
  function ossl_core_bio_puts(cb : POSSL_CORE_BIO;const buf : PUTF8Char):integer;
  function ossl_core_bio_ctrl( cb : POSSL_CORE_BIO; cmd : integer; larg : long; parg : Pointer):long;
  function ossl_core_bio_vprintf(cb : POSSL_CORE_BIO;const format : PUTF8Char; args : array of const):integer;

function ossl_core_bio_up_ref( cb : POSSL_CORE_BIO):integer;

implementation


uses openssl3.crypto.mem, OpenSSL3.threads_none, openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bss_mem,         openssl3.crypto.bio.bio_print,
     openssl3.include.internal.refcount,  openssl3.crypto.bio.bss_file;



function ossl_core_bio_up_ref( cb : POSSL_CORE_BIO):integer;
var
  ref : integer;
begin
    ref := 0;
    Result := CRYPTO_UP_REF(cb.ref_cnt, ref, cb.ref_lock);
end;




function ossl_core_bio_gets( cb : POSSL_CORE_BIO; buf : PUTF8Char; size : integer):integer;
begin
    Result := BIO_gets(cb.bio, buf, size);
end;


function ossl_core_bio_puts(cb : POSSL_CORE_BIO;const buf : PUTF8Char):integer;
begin
    Result := BIO_puts(cb.bio, buf);
end;


function ossl_core_bio_ctrl( cb : POSSL_CORE_BIO; cmd : integer; larg : long; parg : Pointer):long;
begin
    Result := BIO_ctrl(cb.bio, cmd, larg, parg);
end;


function ossl_core_bio_vprintf(cb : POSSL_CORE_BIO;const format : PUTF8Char; args : array of const):integer;
begin
    Result := BIO_vprintf(cb.bio, format, args);
end;



function ossl_core_bio_write_ex(cb : POSSL_CORE_BIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
begin
    Result := BIO_write_ex(cb.bio, data, dlen, written);
end;



function ossl_core_bio_read_ex( cb : POSSL_CORE_BIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
begin
    Result := BIO_read_ex(cb.bio, data, dlen, readbytes);
end;



function ossl_core_bio_new_mem_buf(const buf : Pointer; len : integer):POSSL_CORE_BIO;
begin
    Result := core_bio_new_from_new_bio(BIO_new_mem_buf(buf, len));
end;


function core_bio_new_from_new_bio( bio : PBIO):POSSL_CORE_BIO;
var
  cb : POSSL_CORE_BIO;
begin
    cb := nil;
    if bio = nil then Exit(nil);
    cb := core_bio_new();
    if  cb = nil then  begin
        BIO_free(bio);
        Exit(nil);
    end;
    cb.bio := bio;
    Result := cb;
end;


function ossl_core_bio_new_file(const filename, mode : PUTF8Char):POSSL_CORE_BIO;
begin
    Result := core_bio_new_from_new_bio(BIO_new_file(filename, mode));
end;

function ossl_core_bio_free( cb : POSSL_CORE_BIO):integer;
var
  ref, res : integer;
begin
    ref := 0; res := 1;
    if cb <> nil then
    begin
        CRYPTO_DOWN_REF(cb.ref_cnt, ref, cb.ref_lock);
        if ref <= 0 then
        begin
            res := BIO_free(cb.bio);
            CRYPTO_THREAD_lock_free(cb.ref_lock);
            OPENSSL_free(cb);
        end;
    end;
    Result := res;
end;

function core_bio_new:POSSL_CORE_BIO;
var
  cb : POSSL_CORE_BIO;
begin
    cb := OPENSSL_malloc(sizeof( cb^));
    cb.ref_lock := CRYPTO_THREAD_lock_new();
    if (cb = nil)  or  (cb.ref_lock = nil) then
    begin
        OPENSSL_free(cb);
        Exit(nil);
    end;
    cb.ref_cnt := 1;
    Result := cb;
end;


function ossl_core_bio_new_from_bio( bio : PBIO):POSSL_CORE_BIO;
var
  cb : POSSL_CORE_BIO;
begin
    cb := core_bio_new();
    if (cb = nil)  or  (0>= BIO_up_ref(bio)) then
    begin
        ossl_core_bio_free(cb);
        Exit(nil);
    end;
    cb.bio := bio;
    Result := cb;
end;


end.
