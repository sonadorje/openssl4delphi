unit openssl3.crypto.cryptlib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

procedure OPENSSL_die(const &message, filename : string; lineNumber : integer; ErrorAddr: Pointer);
function ossl_check_const_void_sk_type(const sk : Pstack_st_void):POPENSSL_STACK;

function ossl_check_void_type( ptr : Pointer):Pointer;
  function ossl_check_void_sk_type( sk : Pstack_st_void):POPENSSL_STACK;
function sk_EX_CALLBACK_num(const sk : Pstack_st_EX_CALLBACK):integer;
procedure sk_EX_CALLBACK_pop_free( sk : Pstack_st_EX_CALLBACK; freefunc : sk_EX_CALLBACK_freefunc);
function sk_EX_CALLBACK_value(const sk : Pstack_st_EX_CALLBACK; idx : integer):PEX_CALLBACK;

implementation
uses openssl3.crypto.stack;






function sk_EX_CALLBACK_value(const sk : Pstack_st_EX_CALLBACK; idx : integer):PEX_CALLBACK;
begin
   Result := PEX_CALLBACK(OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;





function sk_EX_CALLBACK_num(const sk : Pstack_st_EX_CALLBACK):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK( sk))
end;

procedure sk_EX_CALLBACK_pop_free( sk : Pstack_st_EX_CALLBACK; freefunc : sk_EX_CALLBACK_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;




function ossl_check_void_type( ptr : Pointer):Pointer;
begin
  Exit(ptr);
end;


function ossl_check_void_sk_type( sk : Pstack_st_void):POPENSSL_STACK;
begin
  Exit(POPENSSL_STACK( sk));
end;



function ossl_check_const_void_sk_type(const sk : Pstack_st_void):POPENSSL_STACK;
begin
   Exit(POPENSSL_STACK( sk));
end;


procedure OPENSSL_die(const &message, filename : string; lineNumber : integer; ErrorAddr: Pointer);
var
  S: String;
begin

    s := Format('%s:%d: OpenSSL internal error: %s, address $%x'#10,
                      [filename, lineNumber, &message, Pred(Integer(ErrorAddr))]);
    Writeln(s);
{$IFNDEF MSWINDOWS}
    abort();
{$ELSE}
     (* Win32 abort() customarily shows a dialog, but we just did that... *)

{$if not defined(_WIN32_WCE)}
    //raise Exception.Create(S + '.Signal types:' + IntToStr(SIGABRT));
{$endif }
    Halt(3);
{$endif}



end;

end.
