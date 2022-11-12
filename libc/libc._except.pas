unit libc._except;

interface
uses OpenSSL.Api, libc.dosexcpt;

{$LINK   ta.obj}
const
  CPP_EXCEPT_CODE = $0EEFFACE;
  PAS_EXCEPT_CODE = $0EEDFADE;

 procedure __doGlobalUnwind; external;
 procedure _setexc( p : PEXCEPTIONREGISTRATIONRECORD);
 function ExcHandler( p : PEXCEPTIONREPORTRECORD; q : PEXCEPTIONREGISTRATIONRECORD; r : PCONTEXTRECORD; s : PVOID):Cardinal;

implementation


function ExcHandler( p : PEXCEPTIONREPORTRECORD; q : PEXCEPTIONREGISTRATIONRECORD; r : PCONTEXTRECORD; s : PVOID):Cardinal;
begin
{$IFDEF DEBUGGER_EXCEPTION_HOOKS}
    {
      Ignore the debugger exception.  The debugger should tossed this
      exception; maybe it fell asleep.
    }
    if p.ExceptionNum = _DELPHI_DEBUGGER_XCPT_CODE then
       Exit(XCPT_CONTINUE_EXECUTION);
{$ENDIF}
    if (p.ExceptionNum = CPP_EXCEPT_CODE)  or  (p.ExceptionNum = PAS_EXCEPT_CODE) then
    begin
      _EAX := UInt32(q);
      _EDX := UInt32(p);
      __doGlobalUnwind();
  {
    FIXME:
    Hey, this is a problem: __call_terminate() has a try/catch
    in it.  That sucking sound you hear is the linker pulling
    all of the PostInc(C) EH code into your lean-and-mean C application.
  }
      __call_terminate();
    end;
    if (p.ExceptionNum = XCPT_UNABLE_TO_GROW_STACK)  and  (_stkchk <> 0) then
       _ErrorExit('Stack Overflow!');
    if _UserHandlerPtr then
       if (( *_UserHandlerPtr)(p, q, r, s) = XCPT_CONTINUE_EXECUTION)
          Exit((XCPT_CONTINUE_EXECUTION));
    if _HandlerPtr then
       if (( *_HandlerPtr)(p, q, r, s) = XCPT_CONTINUE_EXECUTION)
          Exit((XCPT_CONTINUE_EXECUTION));
{$IFDEF DEBUGGER_EXCEPTION_HOOKS}
    if __pCPPdebugHook  and
  ( *__pCPPdebugHook = 1  or  *__pCPPdebugHook = 2 then  and
  (p.ExceptionNum < $eedface  or  p.ExceptionNum > $eefface))
    begin
       __raiseDebuggerException(2, { XXDNrawException }
                               3,
                               q,
                               p,
                               r
                               );
    end;
{$ENDIF}
    if p.ExceptionNum = STATUS_FATAL_APP_EXIT then
    begin
        { Abort unhandled so generate default action }
        _do_abort();
    end;
    Result := XCPT_CONTINUE_SEARCH;
end;


procedure _setexc( p : PEXCEPTIONREGISTRATIONRECORD);
begin
    p.prev_structure := nil;
    p.ExceptionHandler := ExcHandler;
    _SetExceptionHandler(p);
end;


end.
