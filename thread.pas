unit thread;

interface
uses OpenSSL.Api, System.Classes, System.Types, Winapi.Windows;

type
  Tthread_func = procedure (p1: Pointer);
  Tthread_sig = procedure();
  Tendfunc = procedure ( __retval: Uint32);
  Tstart_address_func = procedure(p1: Pointer);
  Tstartaddr_func = function(p1: Pointer): UInt32;   stdcall;
  Pthread_sig = ^Tthread_sig;
  _thread_adoption_data_st = record
     dummy: UTF8Char;
  end;
  _PTHREAD_ADOPTION_DATA = ^_thread_adoption_data_st;

  __seed_t = record
  	 lo, hi: Uint32;
  end ;

  P_thread_data = ^_thread_data;
  _thread_data = record
    thread_link       : P_thread_data;
    thread_arglist    : Pointer;
    thread_handle     : THANDLE;
    thread_errno,
    thread_doserrno   : integer;
    thread_func       : Tthread_func;
    thread_token,
    thread_template   : Pbyte;
    thread_mbshift,
    thread_wcshift    : integer;
    thread_sig        : Pthread_sig;
    thread_excep,
    thread_time,
    thread_cvt,
    thread_strbuf,
    thread_wstrbuf,
    thread_passbuf,
    thread_pathbuf    : Pointer;
    thread_seed       : __seed_t;
    thread_exceptvars : Pointer;
{$if defined(_MBCS)}
    thread_lead_byte,
{$ENDIF}
    thread_ex_mode,
    thread_xtra       : integer;
end;

 TTHREAD_DATA = _thread_data;
 PTHREAD_DATA = ^TTHREAD_DATA;

  function new_thread( t : PTHREAD_DATA; endfunc : Tendfunc): DWORD;
  function new_thread_helper( t : PTHREAD_DATA):DWORD;
  procedure _unadopt_thread( thd : _PTHREAD_ADOPTION_DATA);
  function _adopt_thread( start_address : Tstart_address_func; arglist : Pointer; free_flag : integer):_PTHREAD_ADOPTION_DATA;
  function _beginthreadNT( start_address : Tstart_address_func; stack_size : Uint32; arglist, security_attr : Pointer; create_flags : Cardinal; thread_id : PUint32; ex_mode: int):Cardinal;
  function _beginthread( start_address : Tstart_address_func; stack_size : Uint32; arglist : Pointer):Cardinal;
  function _beginthreadex(__security : Pointer; __stksize : Uint32; __startaddr : Tstartaddr_func; __arglist : Pointer; __initflag : Uint32; __threadaddr : PUint32):Cardinal;
  procedure _endthread;
  procedure _endthreadex( __retval : Uint32);

 var
    _tlsindex, _stkindex: Pointer;

implementation
uses libc.dosexcpt, libc._except;



function new_thread( t : PTHREAD_DATA; endfunc : Tendfunc):DWORD;
var
  hand : TEXCEPTIONREGISTRATIONRECORD;
  info : _MEMORY_BASIC_INFORMATION;
  extra : DWORD;
  ov : OSVERSIONINFO;
  retval : Uint32;
begin
    extra := 0;
    ov.dwOSVersionInfoSize := sizeof (ov);
    GetVersionEx (&ov);
    if ov.dwPlatformId = 1 then {  If under Win95 we cannot go below
                               *  64K above what the system says is
                               *  the bottom of the stack
                               }
        extra := $10000;
    { Save a pointer to the thread data structure in NT's thread
     * local storage.
     }
    _tlsindex := Pointer( t);
    { Store the thread's stack base in the thread local storage.
     }
    VirtualQuery(Pointer( @info), info, sizeof(info));
    _stkindex := PUTF8Char(info.AllocationBase) + extra;
{$IF not defined(WIN64)}
// FIXME
    _ExceptInit(t.thread_exceptvars);
{$ENDIF}
    { Set up the RTL exception handler.  Save a pointer to
     * its registration record in the thread data, so that
     * _endthread() can remove it.
     }
    _setexc(&hand);
    t.thread_excep := &hand;
{$IF not defined(_WIN64)}
    { Reset the fpu control word since the OS has probably changed it on us }
    _fpreset();
{$ENDIF}
    { Call the thread starting address.  If the function returns a value,
       we hold it in retval, and pass it along to the endfunc.  This allows
       us to have both _beginthreadex and _beginthread routines come through
       here and pass the proper values to _endthread and _endthreadex.
     }
    if t.thread_ex_mode then
       retval = ( *((Uint32  ( *) Pointer( )t.thread_func))(t.thread_arglist);
    else
        retval := ( *((Uint32 _USERENTRY ( *) Pointer( )t.thread_func))(t.thread_arglist);
    if endfunc then endfunc(retval);
    return 0;   { may never get here }
end;


function new_thread_helper( t : PTHREAD_DATA):DWORD;
begin
    if t.thread_ex_mode then Exit(new_thread (t, _endthreadex));
    else
        Result := new_thread (t, (void (_RTLENTRY *) (Uint32))_endthread);
end;


procedure _unadopt_thread( thd : _PTHREAD_ADOPTION_DATA);
begin
    if thd then _thread_data_del((THREAD_DATA*)thd);
end;


function _adopt_thread( start_address : Tstart_address_func; arglist : Pointer; free_flag : integer):_PTHREAD_ADOPTION_DATA;
var
  t : PTHREAD_DATA;
begin
    t := _thread_data();
    if 0>= t then begin
        errno := ENOMEM;
        Exit(nil);
    end;
    t.thread_func := start_address;
    t.thread_arglist := arglist;
    new_thread (t, nil);  // nil means don't call _endthread at the end
    _unsetexc(t.thread_excep);
    if free_flag then begin
        _thread_data_del(t);
        errno := 0;  // reset errno so this nil doesn't look like an error.
        t := nil;
    end;
    Result := (_PTHREAD_ADOPTION_DATA)t;
end;


function _beginthreadNT( start_address : Tstart_address_func; stack_size : Uint32; arglist, security_attr : Pointer; create_flags : Cardinal; thread_id : Uint32 Plong):Cardinal;
begin
    Exit(__beginthreadNT (start_address, stack_size, arglist,);
                            security_attr, create_flags, thread_id, 0);
end;


function _beginthread( start_address : Tstart_address_func; stack_size : Uint32; arglist : Pointer):Cardinal;
begin
    Result := _beginthreadNT(start_address, stack_size, arglist, 0, 0, 0);
end;


function _beginthreadex(__security : Pointer; __stksize : Uint32; __startaddr : T__startaddr_func; __arglist : Pointer; __initflag : Uint32;var __threadaddr : Uint32):Cardinal;
var
  ret : Cardinal;
begin
    ret := __beginthreadNT(Tstartaddr_func __startaddr, __stksize,
                          __arglist, __security,
                          (ulong )__initflag,
                          (Uint32 Plong  )__threadaddr,
                          1 { the 1 here indicates ex-mode }
);
    if ret = (ulong  then -1)
        ret := 0;
    Result := ret;
end;


procedure _endthread;
var
  t : PTHREAD_DATA;

  h : HANDLE;
begin
    if t = _thread_data( then ) <> nil then
    begin
        _unsetexc(t.thread_excep);
        h := t.thread_handle;
        _thread_data_del(t);
        CloseHandle(h);
    end;
    ExitThread(0);
end;


procedure _endthreadex( __retval : Uint32);
var
  t : PTHREAD_DATA;
begin
    if t = _thread_data( then ) <> nil then
    begin
        _unsetexc(t.thread_excep);
        _thread_data_del(t);
    end;
    ExitThread(__retval);
end;

end.
