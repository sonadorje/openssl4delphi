unit openssl3.crypto.bio.bio_prov;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, typinfo;

function ossl_prov_bio_from_dispatch(fns : POSSL_DISPATCH):integer;
function ossl_bio_prov_init_bio_method:PBIO_METHOD;
function bio_core_write_ex(bio : PBIO;{const} data : PByte; data_len : size_t; written : Psize_t):integer;
function ossl_prov_bio_write_ex(bio : POSSL_CORE_BIO;const data : Pointer; data_len : size_t; written : Psize_t):integer;
function bio_core_read_ex( bio : PBIO; data : PUTF8Char; data_len : size_t; bytes_read : Psize_t):integer;
function ossl_prov_bio_read_ex( bio : POSSL_CORE_BIO; data : Pointer; data_len : size_t; bytes_read : Psize_t):integer;
function bio_core_puts(bio : PBIO;const str : PUTF8Char):integer;
function ossl_prov_bio_puts(bio : POSSL_CORE_BIO;const str : PUTF8Char):integer;
function ossl_prov_bio_gets( bio : POSSL_CORE_BIO; buf : PUTF8Char; size : integer):integer;
function bio_core_gets( bio : PBIO; buf : PUTF8Char; size : integer):integer;
function bio_core_ctrl( bio : PBIO; cmd : integer; num : long; ptr : Pointer):long;
function ossl_prov_bio_ctrl( bio : POSSL_CORE_BIO; cmd : integer; num : long; ptr : Pointer):integer;
function bio_core_new( bio : PBIO):integer;
function bio_core_free( bio : PBIO):integer;
function ossl_prov_bio_free( bio : POSSL_CORE_BIO):integer;
function ossl_bio_new_from_core_bio( provctx : PPROV_CTX; corebio : POSSL_CORE_BIO):PBIO;
function ossl_prov_bio_up_ref( bio : POSSL_CORE_BIO):integer;




var
    c_bio_new_file   : TOSSL_FUNC_BIO_new_file_fn;
    c_bio_new_membuf : TOSSL_FUNC_BIO_new_membuf_fn;
    c_bio_read_ex    : TOSSL_FUNC_BIO_read_ex_fn;
    c_bio_write_ex   : TOSSL_FUNC_BIO_write_ex_fn;
    c_bio_gets       : TOSSL_FUNC_BIO_gets_fn;
    c_bio_puts       : TOSSL_FUNC_BIO_puts_fn;
    c_bio_ctrl       : TOSSL_FUNC_BIO_ctrl_fn;
    c_bio_up_ref     : TOSSL_FUNC_BIO_up_ref_fn;
    c_bio_free       : TOSSL_FUNC_BIO_free_fn;
    c_bio_vprintf    : TOSSL_FUNC_BIO_vprintf_fn;

implementation
uses
     OpenSSL3.openssl.core_dispatch,         openssl3.crypto.bio.bio_meth,
     openssl3.providers.common.provider_ctx, openssl3.crypto.bio.bio_lib;

function ossl_prov_bio_up_ref( bio : POSSL_CORE_BIO):integer;
begin
    if not Assigned(c_bio_up_ref ) then Exit(0);
    Result := c_bio_up_ref(bio);
end;


function ossl_bio_new_from_core_bio( provctx : PPROV_CTX; corebio : POSSL_CORE_BIO):PBIO;
var
    corebiometh : PBIO_METHOD;
begin
    corebiometh := ossl_prov_ctx_get0_core_bio_method(provctx);
    if corebiometh = nil then
       Exit(nil);
    Result := BIO_new(corebiometh);
    if Result =  nil then
        Exit(nil);
    if 0>= ossl_prov_bio_up_ref(corebio) then
    begin
        BIO_free(Result);
        Exit(nil);
    end;
    BIO_set_data(Result, corebio);
    // Added by Administrator 2022-09-24 15:33:21
    Result.ptrinfo := TypeInfo(POSSL_CORE_BIO);
end;

function ossl_prov_bio_free( bio : POSSL_CORE_BIO):integer;
begin
    if not Assigned(c_bio_free ) then Exit(0);
    Result := c_bio_free(bio);
end;

function bio_core_free( bio : PBIO):integer;
begin
    BIO_set_init(bio, 0);
    ossl_prov_bio_free(BIO_get_data(bio));
    Result := 1;
end;

function bio_core_new( bio : PBIO):integer;
begin
    BIO_set_init(bio, 1);
    Result := 1;
end;

function ossl_prov_bio_ctrl( bio : POSSL_CORE_BIO; cmd : integer; num : long; ptr : Pointer):integer;
begin
    if not Assigned(c_bio_ctrl) then Exit(-1);
    Result := c_bio_ctrl(bio, cmd, num, ptr);
end;

function bio_core_ctrl( bio : PBIO; cmd : integer; num : long; ptr : Pointer):long;
begin
    Result := ossl_prov_bio_ctrl(BIO_get_data(bio), cmd, num, ptr);
end;

function bio_core_gets( bio : PBIO; buf : PUTF8Char; size : integer):integer;
begin
    Result := ossl_prov_bio_gets(BIO_get_data(bio), buf, size);
end;


function ossl_prov_bio_gets( bio : POSSL_CORE_BIO; buf : PUTF8Char; size : integer):integer;
begin
    if not Assigned(c_bio_gets ) then Exit(-1);
    Result := c_bio_gets(bio, buf, size);
end;

function ossl_prov_bio_puts(bio : POSSL_CORE_BIO;const str : PUTF8Char):integer;
begin
    if not Assigned(c_bio_puts ) then Exit(-1);
    Result := c_bio_puts(bio, str);
end;

function bio_core_puts(bio : PBIO;const str : PUTF8Char):integer;
begin
    Result := ossl_prov_bio_puts(BIO_get_data(bio), str);
end;

function ossl_prov_bio_read_ex( bio : POSSL_CORE_BIO; data : Pointer; data_len : size_t; bytes_read : Psize_t):integer;
begin
    if not Assigned(c_bio_read_ex) then Exit(0);
    Result := c_bio_read_ex(bio, data, data_len, bytes_read);
end;

function bio_core_read_ex( bio : PBIO; data : PUTF8Char; data_len : size_t; bytes_read : Psize_t):integer;
begin
    Result := ossl_prov_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
end;

function ossl_prov_bio_write_ex(bio : POSSL_CORE_BIO;const data : Pointer; data_len : size_t; written : Psize_t):integer;
begin
    if not Assigned(c_bio_write_ex) then Exit(0);
    Result := c_bio_write_ex(bio, data, data_len, written);
end;

function bio_core_write_ex(bio : PBIO;{const} data : PByte; data_len : size_t; written : Psize_t):integer;
begin
    Result := ossl_prov_bio_write_ex(BIO_get_data(bio), data, data_len, written);
end;


function ossl_bio_prov_init_bio_method:PBIO_METHOD;
var
  corebiometh : PBIO_METHOD;
begin
    corebiometh := nil;
    corebiometh := BIO_meth_new(BIO_TYPE_CORE_TO_PROV, 'BIO to Core filter');
    if (corebiometh = nil)
             or   (0>= BIO_meth_set_write_ex(corebiometh, bio_core_write_ex) )
             or   (0>= BIO_meth_set_read_ex(corebiometh, bio_core_read_ex))
             or   (0>= BIO_meth_set_puts(corebiometh, bio_core_puts) )
             or   (0>= BIO_meth_set_gets(corebiometh, bio_core_gets))
             or   (0>= BIO_meth_set_ctrl(corebiometh, bio_core_ctrl))
             or   (0>= BIO_meth_set_create(corebiometh, bio_core_new))
             or   (0>= BIO_meth_set_destroy(corebiometh, bio_core_free)) then
    begin
        BIO_meth_free(corebiometh);
        Exit(nil);
    end;
    Result := corebiometh;
end;

function ossl_prov_bio_from_dispatch(fns : POSSL_DISPATCH):integer;
begin
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_BIO_NEW_FILE:
            if not Assigned(c_bio_new_file) then
               c_bio_new_file := _OSSL_FUNC_BIO_new_file(fns);
            //break;
        OSSL_FUNC_BIO_NEW_MEMBUF:
            if not Assigned(c_bio_new_membuf) then
               c_bio_new_membuf := _OSSL_FUNC_BIO_new_membuf(fns);
            //break;
        OSSL_FUNC_BIO_READ_EX:
            if not Assigned(c_bio_read_ex ) then
               c_bio_read_ex := _OSSL_FUNC_BIO_read_ex(fns);
            //break;
        OSSL_FUNC_BIO_WRITE_EX:
            if not Assigned(c_bio_write_ex ) then
               c_bio_write_ex := _OSSL_FUNC_BIO_write_ex(fns);
            //break;
        OSSL_FUNC_BIO_GETS:
            if not Assigned(c_bio_gets) then
               c_bio_gets := _OSSL_FUNC_BIO_gets(fns);
            //break;
        OSSL_FUNC_BIO_PUTS:
            if not Assigned(c_bio_puts) then
               c_bio_puts := _OSSL_FUNC_BIO_puts(fns);
            //break;
        OSSL_FUNC_BIO_CTRL:
            if not Assigned(c_bio_ctrl) then
               c_bio_ctrl := _OSSL_FUNC_BIO_ctrl(fns);
            //break;
        OSSL_FUNC_BIO_UP_REF:
            if not Assigned(c_bio_up_ref ) then
               c_bio_up_ref := _OSSL_FUNC_BIO_up_ref(fns);
            //break;
        OSSL_FUNC_BIO_FREE:
            if not Assigned(c_bio_free ) then
               c_bio_free := _OSSL_FUNC_BIO_free(fns);
            //break;
        OSSL_FUNC_BIO_VPRINTF:
            if not Assigned(c_bio_vprintf ) then
               c_bio_vprintf := _OSSL_FUNC_BIO_vprintf(fns);
            //break;
        end;
        Inc(fns);
    end;
    Result := 1;
end;

end.
