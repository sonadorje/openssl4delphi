unit openssl3.test.testutil.basic_output;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api;


  procedure test_open_streams;
  procedure test_adjust_streams_tap_level( level : integer);
  procedure test_close_streams;
  function test_vprintf_stdout( fmt : PUTF8Char; ap: array of const):integer;
  function test_vprintf_stderr( fmt : PUTF8Char; ap: array of const):integer;
  function test_flush_stdout:integer;
  function test_flush_stderr:integer;
  function test_vprintf_tapout( fmt : PUTF8Char; ap: array of const):integer;
  function test_vprintf_taperr( fmt : PUTF8Char; ap: array of const):integer;
  function test_flush_tapout:integer;
  function test_flush_taperr:integer;

var
  tap_out: PBIO  = nil;
  tap_err: PBIO  = nil;
  bio_out: PBIO = nil;
  bio_err: PBIO = nil;

implementation
uses openssl3.crypto.bio.bss_file,  openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bf_prefix, openssl3.crypto.bio.bio_print;

procedure test_open_streams;
begin
    tap_out := BIO_new_fp(@System.Output{stdout}, BIO_NOCLOSE or BIO_FP_TEXT);
    tap_err := BIO_new_fp(@System.ErrOutput{stderr}, BIO_NOCLOSE or BIO_FP_TEXT);
{$IFDEF __VMS}
    tap_out := BIO_push(BIO_new(BIO_f_linebuffer), tap_out);
    tap_err := BIO_push(BIO_new(BIO_f_linebuffer), tap_err);
{$ENDIF}
    tap_out := BIO_push(BIO_new(BIO_f_prefix), tap_out);
    tap_err := BIO_push(BIO_new(BIO_f_prefix), tap_err);

    bio_out := BIO_push(BIO_new(BIO_f_prefix), tap_out);
    bio_err := BIO_push(BIO_new(BIO_f_prefix), tap_err);
    BIO_set_prefix(bio_out, PUTF8Char('# '));
    BIO_set_prefix(bio_err, PUTF8Char('# '));
    {OPENSSL_}assert(bio_out <> nil);
    {OPENSSL_}assert(bio_err <> nil);
end;


procedure test_adjust_streams_tap_level( level : integer);
begin
    BIO_set_indent(tap_out, level);
    BIO_set_indent(tap_err, level);
end;


procedure test_close_streams;
begin
    {
     * The rest of the chain is freed by the BIO_free_all calls below, so
     * we only need to free the last one in the bio_out and bio_err chains.
     }
    BIO_free(bio_out);
    BIO_free(bio_err);
    BIO_free_all(tap_out);
    BIO_free_all(tap_err);
end;


function test_vprintf_stdout( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := BIO_vprintf(bio_out, fmt, ap);
end;


function test_vprintf_stderr( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := BIO_vprintf(bio_err, fmt, ap);
end;


function test_flush_stdout:integer;
var
  p: Pointer;
begin
    p := nil;
    Result := BIO_ctrl(bio_out,BIO_CTRL_FLUSH,0, p);//BIO_flush(bio_out);
end;


function test_flush_stderr:integer;
var
  p: Pointer;
begin
    p := nil;
    Result := BIO_ctrl(bio_err,BIO_CTRL_FLUSH,0, p);//BIO_flush(bio_err);
end;


function test_vprintf_tapout( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := BIO_vprintf(tap_out, fmt, ap);
end;


function test_vprintf_taperr( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := BIO_vprintf(tap_err, fmt, ap);
end;


function test_flush_tapout:integer;
var
  p: Pointer;
begin
    p := nil;
    Result := BIO_ctrl(tap_out,BIO_CTRL_FLUSH,0, p);//BIO_flush(tap_out);
end;


function test_flush_taperr:integer;
var
  p: Pointer;
begin
    p := nil;
    Result := BIO_ctrl(tap_err,BIO_CTRL_FLUSH,0, p);//BIO_flush(tap_err);
end;

end.
