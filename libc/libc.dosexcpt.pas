unit libc.dosexcpt;

interface
uses OpenSSL.Api, Winapi.Windows;

type
   PEXCEPTIONREPORTRECORD  = ^_EXCEPTIONREPORTRECORD;
   CONTEXTRECORD           = _CONTEXT ;
   PCONTEXTRECORD          = ^_CONTEXT;

   _EXCEPTIONREPORTRECORD = record
      ExceptionNum,
      fHandlerFlags               : ULONG;
      NestedExceptionReportRecord : PEXCEPTIONREPORTRECORD;
      ExceptionAddress            : PVOID;
      cParameters                 : ULONG;
      ExceptionInfo               : array[0..(EXCEPTION_MAXIMUM_PARAMETERS)-1] of ULONG;
  end;

  TEXCEPTIONREPORTRECORD = _EXCEPTIONREPORTRECORD ;



  PEXCEPTIONREGISTRATIONRECORD  = ^_EXCEPTIONREGISTRATIONRECORD;
  TERR_FUNC = function(p1: PEXCEPTIONREPORTRECORD ;
                       p2: PEXCEPTIONREGISTRATIONRECORD;
                       p3: PCONTEXTRECORD;
                       p4: PVOID): ULONG ;

  _EXCEPTIONREGISTRATIONRECORD = record
      [volatile] prev_structure: PEXCEPTIONREGISTRATIONRECORD;
      ExceptionHandler: TERR_FUNC;
  end;
  TEXCEPTIONREGISTRATIONRECORD = _EXCEPTIONREGISTRATIONRECORD ;


implementation

end.
