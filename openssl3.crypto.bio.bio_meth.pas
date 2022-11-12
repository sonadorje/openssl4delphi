unit openssl3.crypto.bio.bio_meth;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;
type
  Tbwrite_func = function (p1: PBIO ; {const} p2: PByte ;p3: size_t; p4: Psize_t):int;
  Tbputs = function(p1: PBIO; const p2: PUTF8Char): Integer;
  Tbread_func = function(p1: PBIO; p2: PUTF8Char; p3: size_t; p4: Psize_t): Integer;

  Tgets_func = function(p1: PBIO; p2: PUTF8Char; p3: Integer): Integer;

  Tctrl_func = function(p1: PBIO; p2: Integer; p3: Integer;p4: Pointer): Integer;
  Tcreate_func = function(p1: PBIO): Integer;

  Tdestroy_func = function(p1: PBIO): Integer;

  function BIO_meth_set_puts(biom : PBIO_METHOD; bputs : Tbputs):integer;
  function BIO_meth_set_write_ex( biom : PBIO_METHOD; bwrite : Tbwrite_func):integer;
  function BIO_meth_set_read_ex( biom : PBIO_METHOD; bread : Tbread_func):integer;
  function BIO_meth_set_gets(biom: PBIO_METHOD; bgets: Tgets_func): Integer;
  function BIO_meth_set_ctrl(biom: PBIO_METHOD; ctrl: Tctrl_func): Integer;
  function BIO_meth_set_create(biom: PBIO_METHOD; create: Tcreate_func): Integer;
  function BIO_meth_set_destroy(biom: PBIO_METHOD; destroy: Tdestroy_func): Integer;
  function bwrite_conv(bio : PBIO;{const} data : PByte; datal : size_t; written : Psize_t):integer;
  function bread_conv( bio : PBIO; data : PUTF8Char; datal : size_t; readbytes : Psize_t):integer;
  function BIO_meth_new(_type : integer;const name : PUTF8Char):PBIO_METHOD;
  procedure BIO_meth_free( biom : PBIO_METHOD);

var
  bio_type_lock: PCRYPTO_RWLOCK  = nil;

implementation
uses
    openssl3.crypto.mem, openssl3.crypto.o_str,
    OpenSSL3.Err;





procedure BIO_meth_free( biom : PBIO_METHOD);
begin
    if biom <> nil then begin
        OPENSSL_free(Pointer(biom.name));
        OPENSSL_free(Pointer(biom));
    end;
end;

function BIO_meth_new(_type : integer;const name : PUTF8Char):PBIO_METHOD;
var
  biom : PBIO_METHOD;
begin
    biom := OPENSSL_zalloc(sizeof(TBIO_METHOD));
    OPENSSL_strdup(biom.name , name);
    if (biom = nil) or  (biom.name = nil) then
    begin
        OPENSSL_free(Pointer(biom));
        ERR_raise(ERR_LIB_BIO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    biom.&type := _type;
    Result := biom;
end;

function bread_conv( bio : PBIO; data : PUTF8Char; datal : size_t; readbytes : Psize_t):integer;
var
  ret : integer;
begin
    if datal > INT_MAX then datal := INT_MAX;
    ret := bio.method.bread_old(bio, data, int (datal));
    if ret <= 0 then
    begin
        readbytes^ := 0;
        Exit(ret);
    end;
    readbytes^ := size_t( ret);
    Result := 1;
end;




function bwrite_conv(bio : PBIO;{const} data : PByte; datal : size_t; written : Psize_t):integer;
var
  ret : integer;
begin
    if datal > INT_MAX then
       datal := INT_MAX;
    ret := bio.method.bwrite_old(bio, data, int (datal)); //function b64_write
    if ret <= 0 then
    begin
        written^ := 0;
        Exit(ret);
    end;
    written^ := size_t( ret);
    Result := 1;
end;

function BIO_meth_set_destroy(biom: PBIO_METHOD; destroy: Tdestroy_func): Integer;
begin
  biom.destroy := destroy;
  Result := 1;
end;

function BIO_meth_set_create(biom: PBIO_METHOD; create: Tcreate_func): Integer;
begin
   biom.create := create;
   Result := 1;
end;

function BIO_meth_set_ctrl(biom: PBIO_METHOD; ctrl: Tctrl_func): Integer;
begin
   biom.ctrl := ctrl;
   Result := 1;
end;

function BIO_meth_set_gets(biom: PBIO_METHOD; bgets: Tgets_func): Integer;
begin
    biom.bgets := bgets;
    Exit( 1);
end;

function BIO_meth_set_puts( biom : PBIO_METHOD; bputs : Tbputs):integer;
begin
    biom.bputs := bputs;
    Result := 1;
end;

function BIO_meth_set_read_ex( biom : PBIO_METHOD; bread : Tbread_func):integer;
begin
    biom.bread_old := nil;
    biom.bread := bread;
    Result := 1;
end;

function BIO_meth_set_write_ex( biom : PBIO_METHOD; bwrite : Tbwrite_func):integer;
begin
    biom.bwrite_old := nil;
    biom.bwrite := bwrite;
    Result := 1;
end;


end.
