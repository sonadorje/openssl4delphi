unit libc.stdio.io;

interface
uses libc.error, System.SysUtils,
     {$IF Defined(MSWINDOWS)}   Winapi.Windows, {$ENDIF}
    System.TypInfo, System.Math;


const
  Exxx  =  EINVAL;  (* NT errors that are unused or don't map to Unix *)
  _dosErrorToSV: array[0..298] of int8 =
(
    0,
    EINVAL,     (* ERROR_INVALID_FUNCTION            1 *)
    ENOENT,     (* ERROR_FILE_NOT_FOUND              2 *)
    ENOENT,     (* ERROR_PATH_NOT_FOUND              3 *)
    EMFILE,     (* ERROR_TOO_MANY_OPEN_FILES         4 *)
    EACCES,     (* ERROR_ACCESS_DENIED               5 *)
    EBADF,      (* ERROR_INVALID_HANDLE              6 *)
    ENOMEM,     (* ERROR_ARENA_TRASHED               7 *)
    ENOMEM,     (* ERROR_NOT_ENOUGH_MEMORY           8 *)
    ENOMEM,     (* ERROR_INVALID_BLOCK               9 *)
    E2BIG,      (* ERROR_BAD_ENVIRONMENT            10 *)
    ENOEXEC,    (* ERROR_BAD_FORMAT                 11 *)
    EINVAL,     (* ERROR_INVALID_ACCESS             12 *)
    EINVAL,     (* ERROR_INVALID_DATA               13 *)
    EFAULT,     (*                                  14 *)
    ENOENT,     (* ERROR_INVALID_DRIVE              15 *)
    EACCES,     (* ERROR_CURRENT_DIRECTORY          16 *)
    EXDEV,      (* ERROR_NOT_SAME_DEVICE            17 *)
    ENOENT,     (* ERROR_NO_MORE_FILES              18 *)
    EROFS,      (* ERROR_WRITE_PROTECT              19 *)
    ENXIO,      (* ERROR_BAD_UNIT                   20 *)
    EBUSY,      (* ERROR_NOT_READY                  21 *)
    EIO,        (* ERROR_BAD_COMMAND                22 *)
    EIO,        (* ERROR_CRC                        23 *)
    EIO,        (* ERROR_BAD_LENGTH                 24 *)
    EIO,        (* ERROR_SEEK                       25 *)
    EIO,        (* ERROR_NOT_DOS_DISK               26 *)
    ENXIO,      (* ERROR_SECTOR_NOT_FOUND           27 *)
    EBUSY,      (* ERROR_OUT_OF_PAPER               28 *)
    EIO,        (* ERROR_WRITE_FAULT                29 *)
    EIO,        (* ERROR_READ_FAULT                 30 *)
    EIO,        (* ERROR_GEN_FAILURE                31 *)
    EACCES,     (* ERROR_SHARING_VIOLATION          32 *)
    EACCES,     (* ERROR_LOCK_VIOLATION             33 *)
    ENXIO,      (* ERROR_WRONG_DISK                 34 *)
    ENFILE,     (* ERROR_FCB_UNAVAILABLE            35 *)
    ENFILE,     (* ERROR_SHARING_BUFFER_EXCEEDED    36 *)
    EFAULT,     (* ERROR_CODE_PAGE_MISMATCHED       37 *)
    EFAULT,     (* ERROR_HANDLE_EOF                 38 *)
    EFAULT,     (* ERROR_HANDLE_DISK_FULL           39 *)
    EFAULT,     (*%msg%ERROR_BAD_COMMAND            40 *)
    EFAULT,     (*%msg%ERROR_CRC                    41 *)
    EFAULT,     (*%msg%ERROR_BAD_LENGTH             42 *)
    EFAULT,     (*%msg%ERROR_SEEK                   43 *)
    EFAULT,     (*%msg%ERROR_NOT_DOS_DISK           44 *)
    EFAULT,     (*%msg%ERROR_SECTOR_NOT_FOUND       45 *)
    EFAULT,     (*%msg%ERROR_OUT_OF_PAPER           46 *)
    EFAULT,     (*%msg%ERROR_WRITE_FAULT            47 *)
    EFAULT,     (*%msg%ERROR_READ_FAULT             48 *)
    EFAULT,     (*%msg%ERROR_GEN_FAILURE            49 *)
    ENODEV,     (* ERROR_NOT_SUPPORTED              50 *)
    EBUSY,      (* ERROR_REM_NOT_LIST               51 *)
    EEXIST,     (* ERROR_DUP_NAME                   52 *)
    ENOENT,     (* ERROR_BAD_NETPATH                53 *)
    EBUSY,      (* ERROR_NETWORK_BUSY               54 *)
    ENODEV,     (* ERROR_DEV_NOT_EXIST              55 *)
    EAGAIN,     (* ERROR_TOO_MANY_CMDS              56 *)
    EIO,        (* ERROR_ADAP_HDW_ERR               57 *)
    EIO,        (* ERROR_BAD_NET_RESP               58 *)
    EIO,        (* ERROR_UNEXP_NET_ERR              59 *)
    EINVAL,     (* ERROR_BAD_REM_ADAP               60 *)
    EFBIG,      (* ERROR_PRINTQ_FULL                61 *)
    ENOSPC,     (* ERROR_NO_SPOOL_SPACE             62 *)
    ENOENT,     (* ERROR_PRINT_CANCELLED            63 *)
    ENOENT,     (* ERROR_NETNAME_DELETED            64 *)
    EACCES,     (* ERROR_NETWORK_ACCESS_DENIED      65 *)
    ENODEV,     (* ERROR_BAD_DEV_TYPE               66 *)
    ENOENT,     (* ERROR_BAD_NET_NAME               67 *)
    ENFILE,     (* ERROR_TOO_MANY_NAMES             68 *)
    EIO,        (* ERROR_TOO_MANY_SESS              69 *)
    EAGAIN,     (* ERROR_SHARING_PAUSED             70 *)
    EINVAL,     (* ERROR_REQ_NOT_ACCEP              71 *)
    EAGAIN,     (* ERROR_REDIR_PAUSED               72 *)
    EFAULT,     (* ERROR_SBCS_ATT_WRITE_PROT        73 *)
    EFAULT,     (* ERROR_SBCS_GENERAL_FAILURE       74 *)
    EFAULT,     (* ERROR_XGA_OUT_MEMORY             75 *)
    EFAULT,     (*                                  76 *)
    EFAULT,     (*                                  77 *)
    EFAULT,     (*                                  78 *)
    EFAULT,     (*                                  79 *)
    EEXIST,     (* ERROR_FILE_EXISTS                80 *)
    EFAULT,     (* ERROR_DUP_FCB                    81 *)
    EACCES,     (* ERROR_CANNOT_MAKE                82 *)
    EACCES,     (* ERROR_FAIL_I24                   83 *)
    ENFILE,     (* ERROR_OUT_OF_STRUCTURES          84 *)
    EEXIST,     (* ERROR_ALREADY_ASSIGNED           85 *)
    EPERM,      (* ERROR_INVALID_PASSWORD           86 *)
    EINVAL,     (* ERROR_INVALID_PARAMETER          87 *)
    EIO,        (* ERROR_NET_WRITE_FAULT            88 *)
    EAGAIN,     (* ERROR_NO_PROC_SLOTS              89 *)
    Exxx,       (* ERROR_NOT_FROZEN                 90 *)
    Exxx,       (* ERR_TSTOVFL                      91 *)
    Exxx,       (* ERR_TSTDUP                       92 *)
    Exxx,       (* ERROR_NO_ITEMS                   93 *)
    Exxx,       (*                                  94 *)
    Exxx,       (* ERROR_INTERRUPT                  95 *)
    Exxx,       (*                                  96 *)
    Exxx,       (*                                  97 *)
    Exxx,       (*                                  98 *)
    EBUSY,      (* ERROR_DEVICE_IN_USE              99 *)
    EAGAIN,     (* ERROR_TOO_MANY_SEMAPHORES       100 *)
    EAGAIN,     (* ERROR_EXCL_SEM_ALREADY_OWNED    101 *)
    Exxx,       (* ERROR_SEM_IS_SET                102 *)
    Exxx,       (* ERROR_TOO_MANY_SEM_REQUESTS     103 *)
    Exxx,       (* ERROR_INVALID_AT_INTERRUPT_TIME 104 *)
    Exxx,       (* ERROR_SEM_OWNER_DIED            105 *)
    Exxx,       (* ERROR_SEM_USER_LIMIT            106 *)
    EXDEV,      (* ERROR_DISK_CHANGE               107 *)
    EACCES,     (* ERROR_DRIVE_LOCKED              108 *)
    EPIPE,      (* ERROR_BROKEN_PIPE               109 *)
    ENOENT,     (* ERROR_OPEN_FAILED               110 *)
    Exxx,       (* ERROR_BUFFER_OVERFLOW           111 *)
    ENOSPC,     (* ERROR_DISK_FULL                 112 *)
    EMFILE,     (* ERROR_NO_MORE_SEARCH_HANDLES    113 *)
    EBADF,      (* ERROR_INVALID_TARGET_HANDLE     114 *)
    EFAULT,     (* ERROR_PROTECTION_VIOLATION      115 *)
    Exxx,       (* ERROR_VIOKBD_REQUEST            116 *)
    Exxx,       (* ERROR_INVALID_CATEGORY          117 *)
    Exxx,       (* ERROR_INVALID_VERIFY_SWITCH     118 *)
    Exxx,       (* ERROR_BAD_DRIVER_LEVEL          119 *)
    Exxx,       (* ERROR_CALL_NOT_IMPLEMENTED      120 *)
    Exxx,       (* ERROR_SEM_TIMEOUT               121 *)
    Exxx,       (* ERROR_INSUFFICIENT_BUFFER       122 *)
    ENOENT,     (* ERROR_INVALID_NAME              123 *)
    EINVAL,     (* ERROR_INVALID_LEVEL             124 *)
    Exxx,       (* ERROR_NO_VOLUME_LABEL           125 *)
    Exxx,       (* ERROR_MOD_NOT_FOUND             126 *)
    ESRCH,      (* ERROR_PROC_NOT_FOUND            127 *)
    ECHILD,     (* ERROR_WAIT_NO_CHILDREN          128 *)
    ECHILD,     (* ERROR_CHILD_NOT_COMPLETE        129 *)
    EBADF,      (* ERROR_DIRECT_ACCESS_HANDLE      130 *)
    EINVAL,     (* ERROR_NEGATIVE_SEEK             131 *)
    EACCES,     (* ERROR_SEEK_ON_DEVICE            132 *)
    Exxx,       (* ERROR_IS_JOIN_TARGET            133 *)
    Exxx,       (* ERROR_IS_JOINED                 134 *)
    Exxx,       (* ERROR_IS_SUBSTED                135 *)
    Exxx,       (* ERROR_NOT_JOINED                136 *)
    Exxx,       (* ERROR_NOT_SUBSTED               137 *)
    Exxx,       (* ERROR_JOIN_TO_JOIN              138 *)
    Exxx,       (* ERROR_SUBST_TO_SUBST            139 *)
    Exxx,       (* ERROR_JOIN_TO_SUBST             140 *)
    Exxx,       (* ERROR_SUBST_TO_JOIN             141 *)
    EAGAIN,     (* ERROR_BUSY_DRIVE                142 *)
    Exxx,       (* ERROR_SAME_DRIVE                143 *)
    Exxx,       (* ERROR_DIR_NOT_ROOT              144 *)
    ENOTEMPTY,  (* ERROR_DIR_NOT_EMPTY             145 *)
    Exxx,       (* ERROR_IS_SUBST_PATH             146 *)
    Exxx,       (* ERROR_IS_JOIN_PATH              147 *)
    Exxx,       (* ERROR_PATH_BUSY                 148 *)
    Exxx,       (* ERROR_IS_SUBST_TARGET           149 *)
    Exxx,       (* ERROR_SYSTEM_TRACE              150 *)
    Exxx,       (* ERROR_INVALID_EVENT_COUNT       151 *)
    Exxx,       (* ERROR_TOO_MANY_MUXWAITERS       152 *)
    Exxx,       (* ERROR_INVALID_LIST_FORMAT       153 *)
    Exxx,       (* ERROR_LABEL_TOO_LONG            154 *)
    Exxx,       (* ERROR_TOO_MANY_TCBS             155 *)
    Exxx,       (* ERROR_SIGNAL_REFUSED            156 *)
    Exxx,       (* ERROR_DISCARDED                 157 *)
    EACCES,     (* ERROR_NOT_LOCKED                158 *)
    Exxx,       (* ERROR_BAD_THREADID_ADDR         159 *)
    Exxx,       (* ERROR_BAD_ARGUMENTS             160 *)
    ENOENT,     (* ERROR_BAD_PATHNAME              161 *)
    Exxx,       (* ERROR_SIGNAL_PENDING            162 *)
    Exxx,       (* ERROR_UNCERTAIN_MEDIA           163 *)
    EAGAIN,     (* ERROR_MAX_THRDS_REACHED         164 *)
    Exxx,       (* ERROR_MONITORS_NOT_SUPPORTED    165 *)
    Exxx,       (* ERROR_UNC_DRIVER_NOT_INSTALLED  166 *)
    EACCES,     (* ERROR_LOCK_FAILED               167 *)
    Exxx,       (* ERROR_SWAPIO_FAILED             168 *)
    Exxx,       (* ERROR_SWAPIN_FAILED             169 *)
    Exxx,       (* ERROR_BUSY                      170 *)
    Exxx,       (*                                 171 *)
    Exxx,       (*                                 172 *)
    Exxx,       (* ERROR_CANCEL_VIOLATION          173 *)
    Exxx,       (* ERROR_ATOMIC_LOCK_NOT_SUPPORTED 174 *)
    Exxx,       (* ERROR_READ_LOCKS_NOT_SUPPORTED  175 *)
    Exxx,       (*                                 176 *)
    Exxx,       (*                                 177 *)
    Exxx,       (*                                 178 *)
    Exxx,       (*                                 179 *)
    Exxx,       (* ERROR_INVALID_SEGMENT_NUMBER    180 *)
    Exxx,       (* ERROR_INVALID_CALLGATE          181 *)
    Exxx,       (* ERROR_INVALID_ORDINAL           182 *)
    EEXIST,     (* ERROR_ALREADY_EXISTS            183 *)
    ECHILD,     (* ERROR_NO_CHILD_PROCESS          184 *)
    Exxx,       (* ERROR_CHILD_ALIVE_NOWAIT        185 *)
    Exxx,       (* ERROR_INVALID_FLAG_NUMBER       186 *)
    Exxx,       (* ERROR_SEM_NOT_FOUND             187 *)
    Exxx,       (* ERROR_INVALID_STARTING_CODESEG  188 *)
    Exxx,       (* ERROR_INVALID_STACKSEG          189 *)
    Exxx,       (* ERROR_INVALID_MODULETYPE        190 *)
    Exxx,       (* ERROR_INVALID_EXE_SIGNATURE     191 *)
    Exxx,       (* ERROR_EXE_MARKED_INVALID        192 *)
    Exxx,       (* ERROR_BAD_EXE_FORMAT            193 *)
    Exxx,       (* ERROR_ITERATED_DATA_EXCEEDS_64k 194 *)
    Exxx,       (* ERROR_INVALID_MINALLOCSIZE      195 *)
    Exxx,       (* ERROR_DYNLINK_FROM_INVALID_RING 196 *)
    Exxx,       (* ERROR_IOPL_NOT_ENABLED          197 *)
    Exxx,       (* ERROR_INVALID_SEGDPL            198 *)
    Exxx,       (* ERROR_AUTODATASEG_EXCEEDS_64k   199 *)
    Exxx,       (* ERROR_RING2SEG_MUST_BE_MOVABLE  200 *)
    Exxx,       (* ERROR_RELOC_CHAIN_XEEDS_SEGLIM  201 *)
    Exxx,       (* ERROR_INFLOOP_IN_RELOC_CHAIN    202 *)
    Exxx,       (* ERROR_ENVVAR_NOT_FOUND          203 *)
    Exxx,       (* ERROR_NOT_CURRENT_CTRY          204 *)
    Exxx,       (* ERROR_NO_SIGNAL_SENT            205 *)
    ENOENT,     (* ERROR_FILENAME_EXCED_RANGE      206 *)
    Exxx,       (* ERROR_RING2_STACK_IN_USE        207 *)
    Exxx,       (* ERROR_META_EXPANSION_TOO_LONG   208 *)
    Exxx,       (* ERROR_INVALID_SIGNAL_NUMBER     209 *)
    Exxx,       (* ERROR_THREAD_1_INACTIVE         210 *)
    Exxx,       (* ERROR_INFO_NOT_AVAIL            211 *)
    Exxx,       (* ERROR_LOCKED                    212 *)
    Exxx,       (* ERROR_BAD_DYNALINK              213 *)
    Exxx,       (* ERROR_TOO_MANY_MODULES          214 *)
    EAGAIN,     (* ERROR_NESTING_NOT_ALLOWED       215 *)
    Exxx,       (* ERROR_CANNOT_SHRINK             216 *)
    Exxx,       (* ERROR_ZOMBIE_PROCESS            217 *)
    Exxx,       (* ERROR_STACK_IN_HIGH_MEMORY      218 *)
    Exxx,       (* ERROR_INVALID_EXITROUTINE_RING  219 *)
    Exxx,       (* ERROR_GETBUF_FAILED             220 *)
    Exxx,       (* ERROR_FLUSHBUF_FAILED           221 *)
    Exxx,       (* ERROR_TRANSFER_TOO_LONG         222 *)
    Exxx,       (* ERROR_FORCENOSWAP_FAILED        223 *)
    Exxx,       (* ERROR_SMG_NO_TARGET_WINDOW      224 *)
    Exxx,       (*                                 225 *)
    Exxx,       (*                                 226 *)
    Exxx,       (*                                 227 *)
    Exxx,       (* ERROR_NO_CHILDREN               228 *)
    Exxx,       (* ERROR_INVALID_SCREEN_GROUP      229 *)
    EPIPE,      (* ERROR_BAD_PIPE                  230 *)
    EAGAIN,     (* ERROR_PIPE_BUSY                 231 *)
    Exxx,       (* ERROR_NO_DATA                   232 *)
    EPIPE,      (* ERROR_PIPE_NOT_CONNECTED        233 *)
    Exxx,       (* ERROR_MORE_DATA                 234 *)
    Exxx,       (*                                 235 *)
    Exxx,       (*                                 236 *)
    Exxx,       (*                                 237 *)
    Exxx,       (*                                 238 *)
    Exxx,       (*                                 239 *)
    Exxx,       (* ERROR_VC_DISCONNECTED           240 *)
    Exxx,       (*                                 241 *)
    Exxx,       (*                                 242 *)
    Exxx,       (*                                 243 *)
    Exxx,       (*                                 244 *)
    Exxx,       (*                                 245 *)
    Exxx,       (*                                 246 *)
    Exxx,       (*                                 247 *)
    Exxx,       (*                                 248 *)
    Exxx,       (*                                 249 *)
    Exxx,       (* ERROR_CIRCULARITY_REQUESTED     250 *)
    Exxx,       (* ERROR_DIRECTORY_IN_CDS          251 *)
    Exxx,       (* ERROR_INVALID_FSD_NAME          252 *)
    Exxx,       (* ERROR_INVALID_PATH              253 *)
    Exxx,       (* ERROR_INVALID_EA_NAME           254 *)
    Exxx,       (* ERROR_EA_LIST_INCONSISTENT      255 *)
    Exxx,       (* ERROR_EA_LIST_TOO_LONG          256 *)
    Exxx,       (* ERROR_NO_META_MATCH             257 *)
    Exxx,       (* ERROR_FINDNOTIFY_TIMEOUT        258 *)
    Exxx,       (* ERROR_NO_MORE_ITEMS             259 *)
    Exxx,       (* ERROR_SEARCH_STRUC_REUSED       260 *)
    Exxx,       (* ERROR_CHAR_NOT_FOUND            261 *)
    Exxx,       (* ERROR_TOO_MUCH_STACK            262 *)
    Exxx,       (* ERROR_INVALID_ATTR              263 *)
    Exxx,       (* ERROR_INVALID_STARTING_RING     264 *)
    Exxx,       (* ERROR_INVALID_DLL_INIT_RING     265 *)
    Exxx,       (* ERROR_CANNOT_COPY               266 *)
    Exxx,       (* ERROR_DIRECTORY                 267 *)
    Exxx,       (* ERROR_OPLOCKED_FILE             268 *)
    Exxx,       (* ERROR_OPLOCK_THREAD_EXISTS      269 *)
    Exxx,       (* ERROR_VOLUME_CHANGED            270 *)
    Exxx,       (* ERROR_FINDNOTIFY_HANDLE_IN_USE  271 *)
    Exxx,       (* ERROR_FINDNOTIFY_HANDLE_CLOSED  272 *)
    Exxx,       (* ERROR_NOTIFY_OBJECT_REMOVED     273 *)
    Exxx,       (* ERROR_ALREADY_SHUTDOWN          274 *)
    Exxx,       (* ERROR_EAS_DIDNT_FIT             275 *)
    Exxx,       (* ERROR_EA_FILE_CORRUPT           276 *)
    Exxx,       (* ERROR_EA_TABLE_FULL             277 *)
    Exxx,       (* ERROR_INVALID_EA_HANDLE         278 *)
    Exxx,       (* ERROR_NO_CLUSTER                279 *)
    Exxx,       (* ERROR_CREATE_EA_FILE            280 *)
    Exxx,       (* ERROR_CANNOT_OPEN_EA_FILE       281 *)
    Exxx,       (* ERROR_EAS_NOT_SUPPORTED         282 *)
    Exxx,       (* ERROR_NEED_EAS_FOUND            283 *)
    Exxx,       (* ERROR_DUPLICATE_HANDLE          284 *)
    Exxx,       (* ERROR_DUPLICATE_NAME            285 *)
    Exxx,       (* ERROR_EMPTY_MUXWAIT             286 *)
    Exxx,       (* ERROR_MUTEX_OWNED               287 *)
    Exxx,       (* ERROR_NOT_OWNER                 288 *)
    Exxx,       (* ERROR_PARAM_TOO_SMALL           289 *)
    Exxx,       (* ERROR_TOO_MANY_HANDLES          290 *)
    Exxx,       (* ERROR_TOO_MANY_OPENS            291 *)
    Exxx,       (* ERROR_WRONG_TYPE                292 *)
    Exxx,       (* ERROR_UNUSED_CODE               293 *)
    Exxx,       (* ERROR_THREAD_NOT_TERMINATED     294 *)
    Exxx,       (* ERROR_INIT_ROUTINE_FAILED       295 *)
    Exxx,       (* ERROR_MODULE_IN_USE             296 *)
    Exxx,       (* ERROR_NOT_ENOUGH_WATCHPOINTS    297 *)
    Exxx        (* ERROR_TOO_MANY_POSTS            298 *)
);

  LAST_ERROR = (sizeof(_dosErrorToSV)-1);
  INT_MAX = $7fffffff;
  FOPEN_MAX	= 20;
  BUFSIZ = 1024;		(* size of buffer used by setbuf *)
  WCIO_UNGETWC_BUFSIZE = 1;
  SEEK_SET	=0;	(* set file offset to offset *)
	SEEK_CUR	=1;	(* set file offset to current plus offset *)
	SEEK_END	=2;	(* set file offset to EOF plus offset *)

 	__SLBF = $0001	       ;(*  line buffered *)
	__SNBF = $0002	       ;(*  unbuffered *)
	__SRD = $0004	       ;(*  OK to read *)
	__SWR = $0008	       ;(*  OK to write *)
       (*  RD and WR are never simultaneously asserted *)
	__SRW = $0010	       ;(*  open for reading & writing *)
	__SEOF = $0020	       ;(*  found EOF *)
	__SERR = $0040	       ;(*  found error *)
	__SMBF = $0080	       ;(*  _buf is from malloc *)
	__SAPP = $0100	       ;(*  fdopen()ed in append mode *)
	__SSTR = $0200	       ;(*  this is an sprintf/snprintf string *)
	__SOPT = $0400	       ;(*  do fseek() optimization *)
	__SNPT = $0800	       ;(*  do not do fseek() optimization *)
	__SOFF = $1000	       ;(*  set iff _offset is in fact correct *)
	__SMOD = $2000	       ;(*  true => fgetln modified _p text *)
	__SALC = $4000	       ;(*  allocate string space dynamically *)

  (*
 * Type ids for argument type table.
 *)
 T_UNUSED	=0;
 T_SHORT	=	1;
 T_U_SHORT	=2;
 TP_SHORT	=3;
 T_INT		=4;
 T_U_INT	=	5;
 TP_INT		=6;
 T_LONG		=7;
 T_U_LONG	=8;
 TP_LONG	=	9;
 T_LLONG	=	10;
 T_U_LLONG	=11;
 TP_LLONG	=12;
 T_DOUBLE	=13;
 T_LONG_DOUBLE	=14;
 TP_CHAR		=15;
 TP_VOID		=16;
 T_PTRINT	=17;
 TP_PTRINT	=18;
 T_SIZEINT	=19;
 T_SSIZEINT	=20;
 TP_SSIZEINT	=21;
 T_MAXINT	=22;
 T_MAXUINT	=23;
 TP_MAXINT	=24;

type
  PClass = ^TClass;
  PPbyte = ^PByte;
  PPVarRec = ^PVarRec;
  PObject = ^TObject;
  uint16_t = uint16;
  int16_t = Int16;
  int8_t = Int8;
  uint8_t = UInt8;
  Puint8_t = ^uint8_t;
  uint64_t = Uint64;
  __int64_t = Int64;
  __off_t = __int64_t;
  off_t = __off_t;
  bool     = Boolean ;
  uint32_t = UInt32;
  int32_t  = int32;
  long = LongInt;
  longlong = int64;
  Plonglong = ^longlong;
  ulonglong = UInt64;
  Pulonglong = ^ulonglong;
  ulong = Uint32;
  Pulong = ^ulong;
  PLong = ^long;
  short = SmallInt;
  Pshort = ^short;
  ushort = Word;
  Pushort = ^ushort;
  int = Integer;
  longdouble = Extended;
  float = Single;
  PAMQPChar = PByte;
  AMQPChar = AnsiChar;
  va_list = Array of TVarRec;
  Pva_list = ^va_list;
  PPva_list = ^Pva_list;
  (*According to the on-line docs (search for TVarRec), array of const
    parameters are treated like array of TVarRec by the compiler.*)
  ptrdiff_t = LongInt;
  {$IFDEF OS64}
  size_t = Uint64;
  ssize_t = int64;

  {$ELSE}
  size_t = uint32;
  Psize_t = ^size_t;
  ssize_t = int32;
  {$Endif}

  __sbuf = record
    _base: PByte;
    _size: int;
  end;

  __siov = record
    iov_base : pointer;
    iov_len  : size_t;
  end;
  __Psiov = ^__siov;

__suio = record

  uio_iov    : __Psiov;
  uio_iovcnt,
  uio_resid  : size_t;
end;
  __Psuio = ^__suio;

  Tfmemopen_cookie = record
    head, tail, cur, eob : Pchar;
  end;
  Pfmemopen_cookie = ^Tfmemopen_cookie;

  Tclose = function(p: Pointer): int;
  Pclose = ^Tclose;
  Tread = function(p1, p2: Pointer; size: size_t): ssize_t;
  Pread = ^Tread;
  //__off_t	(*_seek) (void *, __off_t, int);
  Tseek = function(p: Pointer; offset: __off_t; pos: int): __off_t;
  Pseek = ^Tseek;
  //ssize_t	(*_write)(void *, const void *, size_t);
  Twrite = function(p1: Pointer; const p2: Pointer; size: size_t): ssize_t;
  Pwrite = ^Twrite;
  //int	(*_flush)(void *);
  Tflush = function(p: Pointer): int;
  Pflush = ^Tflush;
  intmax_t = int32;

 FILE_st = record

  curp : PByte;
  buffer : PByte;
  level, bsize : integer;
  istemp, flags : uint16;
  hold : WideChar;
  fd : byte;
  token : Byte;
end;

PFILE = ^FILE_st ;

mbstate_t = record
  __mbstateL : __int64_t;
  __mbstate8 : array[0..127] of byte;
end;
Pmbstate_t = ^mbstate_t;

wchar_io_data = record

  wcio_mbstate_in,
  wcio_mbstate_out   : mbstate_t;
  wcio_ungetwc_buf   : array[0..(WCIO_UNGETWC_BUFSIZE)-1] of WideChar;
  wcio_ungetwc_inbuf : size_t;
  wcio_mode          : integer;
end;
 Pwchar_io_data = ^wchar_io_data;


  Tcleanup = procedure ();
  Pcleanup = ^Tcleanup;

  Tfunction = function (fp: PFILE): int;
  Pfunction = ^Tfunction;

  Pglue = ^Tglue;
  Tglue = record

    next : Pglue;
    niobs : integer;
    iobs : PFILE;
  end;

  function PreDec(var n: size_t): Integer;
  procedure free(P: Pointer);
  procedure memcpy(Dest: Pointer; const source: Pointer; count: Integer);
  function __sfileno(p: PFILE): Integer;
  function __sseek(cookie: Pointer; offset : off_t; whence : integer):off_t;
  function isdigit( c : integer):bool; overload; inline;
  Function IsDigit( ch: Char ): Boolean; overload; inline;
  Function IsAlpha( ch: Char ): Boolean; inline;
  Function IsUpper( ch:Char ): Boolean; inline;
  function IsSpace(Ch: Char): Boolean; inline;
  function GetVariableTypeInfo(pvar: Pointer): PTypeInfo;
  function __sflush( fp : PFILE):integer;
  function _fwalk(func: Pfunction) :integer;
  function fflush( fp : PFILE):integer;
  //function memchr(const buf: Pointer; c: Char; len: size_t): Pointer;
  function memchr(const bigptr: PChar; ch : Char; len : size_t): Pointer;
  function __UNCONST(a: Pointer): Pointer;

  function WCIO_GET(fp: PFILE): Pwchar_io_data;
  procedure _SET_ORIENTATION(fp: PFILE; mode: int) ;
  function cantwrite(fp: PFILE): bool;
  function __swsetup(fp : PFILE):integer;
  procedure __sinit;

  procedure _cleanup;
  procedure __smakebuf(fp : PFILE);
  procedure memset(var X; Value: Integer; Count: NativeInt );
  procedure va_copy(orgap, ap: array of const);
  function __sfvwrite(fp : PFILE; uio: __Psuio):integer;
  function to_digit(c: Char): Integer; inline;
  function __sferror(p: PFILE): bool; inline;
  function __srefill(fp : PFILE):integer;
  function __sflush_locked(fp : PFILE):integer;
  function HASUB(fp: PFILE): bool;inline;
  procedure	FREEUB(fp: PFILE) ;inline;

  function wcschr(__wcs: Pchar; __wc: char): PWideChar;
  function strtoimax(nptr: PChar; endptr: PPChar; base: Integer): intmax_t;
  function __swhatbuf(fp : PFILE; bufsize : Psize_t; couldbetty : Pinteger):integer;
  function __senvbuf(var fp : PFILE; size : Psize_t; couldbetty : Pinteger):integer;
  function strtoi(const nptr:PChar; endptr : PPChar; base : integer; lo, hi : intmax_t;rstatus : Pinteger):intmax_t;
  function _setmode( fildes, mode : integer):integer;
  function __IOerror( dosErr : integer):integer;
  function __doserrno:PInteger;

  var
  __errno, __sdidinit: int;
  __cleanup: Tcleanup ;
  _nfile: Uint32;
   _doserrno: Integer;



function __DOSerror:integer;
function __NTerror:integer;

implementation
uses thread;

function __NTerror:integer;
begin
    Result := __IOerror(int (GetLastError) and LongInt($ffff));
end;



function __DOSerror:integer;
var
  dosErr : DWORD;
begin
    dosErr := GetLastError() and LongInt($ffff);
    __IOerror(dosErr and $ffff);
    Result := (dosErr);
end;



function __doserrno:PInteger;
begin
    Result := (@_thread_data.thread_doserrno);
end;



function __IOerror( dosErr : integer):integer;
var
  val : integer;
  label _ser_maybeSVer, _ser_dosError, _ser_errorFault, _ser_end;
begin
    val := dosErr;
    if val < 0 then
       if (val <= LAST_ERROR) then
           goto _ser_dosError;
{
  Being defensive, we must assume that the error routine can be passed
  a bad argument.  In such circumstances, complaining about the
  parameter seems the most reasonable thing to do.
}
_ser_errorFault:
    val := ERROR_INVALID_FUNCTION;
_ser_dosError:
    _doserrno := val;
    val := _dosErrorToSV[val];
    goto _ser_end ;
{
  This function may be called with a negated System V error code when
  no appropriate DOS error code exists.  In such cases the doserrno
  is set to non-zero, but using a number which has no known cause.
}
_ser_maybeSVerr:
    val := -val;
{$IF defined(MINIRTL)}
    { We are letting Dinkumware handle perror, but they don't give us
       a way to find the maximum errno value.  Since __IOerror is only
       called from the Borland low level RTL we can assume our maximum
       is okay for now. }
    if val >= 50 then #else
    if val >= _sys_nerr then
{$ENDIF}
        goto _ser_errorFault ;
    _doserrno := -1;
se_r_end:
    errno := val;
    Result := -1;
end;



function _setmode( fildes, mode : integer):integer;
var
  newmode : integer;
begin
    if uint32(fildes) >= _nfile then
        Exit((__IOerror (-EBADF)));
    newmode := mode and (O_TEXT or O_BINARY );
    if (newmode  = mode)  and
       (newmode <> int (O_TEXT or O_BINARY)) then
    begin
        mode := _openfd [fildes];
        if mode = 0 then { 0 means the file is not open }
        begin
            Exit((__IOerror (-EBADF)));
        end;
        _openfd[fildes] := (mode and not (O_TEXT or O_BINARY)) or newmode;
        Exit(((mode and (O_TEXT or O_BINARY))));
    end
    else
        Result := (__IOerror (-EINVAL));
end;

//define _FLOCK_TRYLOCK(fp) pthread_mutex_trylock(&_FLOCK(fp))
function ftrylockfile(fp : PFILE):integer;
var
  ret : integer;
begin
{$IF Defined(POSIX)}
    ret := EINVAL;
    if fp <> nil then
    begin
        ret := pthread_mutex_trylock(fp);
    end;
    Result := ret;
{$ENDIF}
end;


function _FLOCK(fp: PFILE):pthread_mutex_t;
begin
   Result := _EXT(fp)._lock;
end;

procedure flockfile(fp : PFILE);
var
  aHandle     : THandle;
  aFileSize   : Integer;
  //aFileName   : String;
begin
{$IF Defined(MSWINDOWS)}

    aHandle      := fp^._file;//CreateFile(PChar(aFileName),GENERIC_READ, 0, nil, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0); // get the handle of the file
    try
        aFileSize   := fp^._lbfsize;// GetFileSize(aHandle,nil); //get the file size for use in the  lockfile function
        Win32Check(LockFile(aHandle,0,0,aFileSize,0)); //lock the file
        //Win32Check(UnlockFile(aHandle,0,0,aFileSize,0));//unlock the file
    finally
        //CloseHandle(aHandle);//Close the handle of the file.
    end;
{$ELSEIF Defined(POSIX)}
    if fp <> nil then
    begin
        pthread_mutex_lock(@_FLOCK(fp));
    end;
{$ENDIF POSIX}

end;

//define _FLOCK_UNLOCK(fp)  pthread_mutex_unlock(&_FLOCK(fp))

procedure funlockfile( fp : PFILE);
var
  aHandle     : THandle;
  aFileSize   : Integer;
  //aFileName   : String;
begin
{$IF Defined(MSWINDOWS)}

    aHandle      := fp^._file;//CreateFile(PChar(aFileName),GENERIC_READ, 0, nil, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0); // get the handle of the file
    try
        aFileSize   := fp^._lbfsize;// GetFileSize(aHandle,nil); //get the file size for use in the  lockfile function
        Win32Check(UnlockFile(aHandle,0,0,aFileSize,0));//unlock the file
    finally
        CloseHandle(aHandle);//Close the handle of the file.
    end;
{$ELSEIF Defined(POSIX)}
    if fp <> nil then begin
        pthread_mutex_unlock(@_FLOCK(fp));
    end;
{$ENDIF}
end;

procedure FUNLOCK_FILE(fp: PFILE);
begin
   if (__isthreaded) then
      funlockfile(fp);
end;

procedure FLOCK_FILE(fp: PFILE);
begin
  if (__isthreaded) then
     flockfile(fp);
end;

function __sflush_locked(fp : PFILE):integer;
var
  r : integer;
begin
  FLOCK_FILE(fp);
  r := __sflush(fp);
  FUNLOCK_FILE(fp);
  Result := (r);
end;

function lflush(fp : PFILE):integer;
begin
  if (fp._flags and (__SLBF or __SWR) ) = (__SLBF or __SWR) then
     Exit((__sflush_locked(fp)));
  Result := (0);
end;

//bionic\libc\stdio\refill.c
function __srefill(fp : PFILE):integer;
begin

  if  0>= __sdidinit then
     __sinit();
  fp._r := 0;

  if (fp._flags and __SEOF)>0 then
     Exit(-1);

  if (fp._flags and __SRD )= 0 then
  begin
    if (fp._flags and __SRW) = 0 then
    begin
      __errno := EBADF;
      fp._flags  := fp._flags  or __SERR;
      Exit(-1);
    end;

    if (fp._flags and __SWR)>0 then
    begin
      if __sflush(fp)>0 then
        Exit((EOF));
      fp._flags := fp._flags and  (not __SWR);
      fp._w := 0;
      fp._lbfsize := 0;
    end;
    fp._flags  := fp._flags  or __SRD;
  end
  else
  begin

    if HASUB(fp ) then
    begin
      FREEUB(fp);
      fp._r := fp._ur;
      if  fp._r <> 0 then
      begin
        fp._p := fp._up;
        Exit((0));
      end;
    end;
  end;
  if fp._bf._base = nil then
     __smakebuf(fp);

  if (fp._flags and (__SLBF or __SNBF) ) then
  begin

    fp._flags  := fp._flags  or __SIGN;
    _fwalk(lflush);
    fp._flags &= ~__SIGN;
    /
    if fp._flags and (__SLBF|__SWR then ) = (__SLBF|__SWR) then
        __sflush(fp);
  end;
  fp._p := fp._bf._base;
  fp._r := ( *fp._read)(fp._cookie, (char *)fp._p, fp._bf._size);
  fp._flags &= ~__SMOD;  /
  if fp._r <= 0 then begin
    if fp._r = 0 then
      fp._flags  := fp._flags  or __SEOF;
    else begin
      fp._r := 0;
      fp._flags  := fp._flags  or __SERR;
    end;
    Exit((EOF));
  end;
  Result := (0);
end;
{ Find the first occurrence of WC in WCS.  }
//openbsd-master\src-master\lib\libc\string\wcschr.c
function wcschr(__wcs: Pwchar_t; __wc: wchar_t): Pwchar_t;
var
  p: Pwchar_t;
begin
   p := __wcs;
  while True do
  begin
    if p^ = __wc then
    begin
      Exit(Pwchar_t(p));
    end;

    //if (!*p)
    if  p^ = 0 then
       Exit(nil);
    Inc(p);
  end;
end;

//https://embeddedartistry.github.io/libc/d8/d0c/iswspace_8c_source.html
function iswspace( wc : wint_t):integer;
begin
  if (wc > 0)  and  (wcschr(@spaces, wchar_t(wc)) <> nil)  then
     Result := 1
  else
     Result := 0;
end;

function __sferror(p: PFILE): bool;
begin
 	 Result := (p._flags and __SERR) <> 0;
end;

function to_digit(c: Char): Integer;
begin
   Result :=	Ord(c) - Ord('0');
end;

function __sfvwrite(fp : PFILE; uio: __Psuio):integer;
var
  len : size_t;
  p : PChar;
  iov : __Psiov;
  s : integer;
  w : ssize_t;
  nl : PChar;
  nlknown, nldist : size_t;

  blen : ptrdiff_t;
  _size : integer;
  _base: PByte;
  label err ;
  procedure COPY(n: ssize_t);
  begin
    memcpy(fp._p, p, size_t(n));
  end;

  procedure GETIOV();
  begin
    while len = 0 do
    begin
      //extra_work;
      p := iov.iov_base;
      len := iov.iov_len;
      Inc(iov);
    end;
  end;

begin
  ASSERT(fp <> nil);
  ASSERT(uio <> nil);
  if ssize_t(uio.uio_resid) < 0 then
  begin
    __errno := EINVAL;
    Exit(-1);
  end;
  if uio.uio_resid = 0 then
     Exit(0);
  { make sure we can write }
  if cantwrite(fp  ) then
  begin
    __errno := EBADF;
    Exit(-1);
  end;


  iov := uio.uio_iov;
  p := iov.iov_base;
  len := iov.iov_len;
  Inc(iov);

  if (fp._flags and __SNBF) > 0 then
  begin
    {
     * Unbuffered: write up to BUFSIZ bytes at a time.
     }
     uio.uio_resid := uio.uio_resid - w;
     while uio.uio_resid  <> 0 do
     begin
        GETIOV();
        w := fp._write^(fp._cookie, p, MIN(len, BUFSIZ));
        if w <= 0 then
           goto err;

        p  := p + w;
        len  := len - w;
        uio.uio_resid := uio.uio_resid - w;
     end;
  end
  else
  if (fp._flags and __SLBF) = 0 then
  begin
    {
     * Fully buffered: fill partially full buffer, if any,
     * and then flush.  If there is no partial buffer, write
     * one _bf._size byte chunk directly (without copying).
     *
     * String output is a special case: write as many bytes
     * as fit, but pretend we wrote everything.  This makes
     * snprintf() return the number of bytes needed, rather
     * than the number used, and avoids its write function
     * (so that the write function can be invalid).
     }
    uio.uio_resid := uio.uio_resid - w;
    while uio.uio_resid  <> 0 do
    begin
      GETIOV();
      if ( ( fp._flags and (__SALC or __SSTR) ) = (__SALC or __SSTR) )
            and  (size_t(fp._w) < len) then
      begin
        blen := fp._p - fp._bf._base;
        { Allocate space exponentially. }
        _size := fp._bf._size;
        while (size_t(_size) < blen + len) do
        begin
          _size := (_size  shl  1) + 1;
        end;

        _base := reallocMemory(fp._bf._base, size_t(_size + 1));
        if _base = nil then
           goto err;
        fp._w  := fp._w + (_size - fp._bf._size);
        fp._bf._base := _base;
        fp._bf._size := _size;
        fp._p := _base + blen;
      end;
      w := fp._w;
      if (fp._flags and __SSTR)>0 then
      begin
        if len < size_t(w) then
          w := len;
        COPY(w);  { copy MIN(fp._w,len), }
        fp._w  := fp._w - int(w);
        fp._p  := fp._p + w;
        w := len;  { but pretend copied all }
      end
      else
      if (fp._p > fp._bf._base)  and  (len > size_t(w)) then
      begin
        { fill and flush }
        COPY(w);

        fp._p  := fp._p + w;
        if fflush(fp)>0  then
          goto err;
      end
      else
      if len >= size_t(fp._bf._size) then
      begin
        { write directly }
        w := fp._bf._size;
        w := fp._write^(fp._cookie, p, size_t(w));
        if w <= 0 then
           goto err;
      end
      else
      begin
        { fill and done }
        w := len;
        COPY(w);
        fp._w  := fp._w - int(w);
        fp._p  := fp._p + w;
      end;
      p  := p + w;
      len  := len - w;
      uio.uio_resid := uio.uio_resid - w;
    end;


  end
  else
  begin
    {
     * Line buffered: like fully buffered, but we
     * must check for newlines.  Compute the distance
     * to the first newline (including the newline),
     * or `infinity' if there is none, then pretend
     * that the amount to write is MIN(len,nldist).
     }
    nlknown := 0;
    nldist := 0;  { XXX just to keep gcc happy }
    uio.uio_resid := uio.uio_resid - (w);
    while uio.uio_resid <> 0 do
    begin
      GETIOV();
      nlknown := 0;
      if  0>= nlknown then
      begin
        nl := memchr(p, #10, len);
        if nl <> nil then
           nldist :=  size_t(nl + 1 - p)
        else
           nldist :=  len + 1;
        nlknown := 1;
      end;

      s := int(MIN(len, nldist));
      w := fp._w + fp._bf._size;
      if (fp._p > fp._bf._base)  and  (s > w) then
      begin
        COPY(w);

        fp._p  := fp._p + w;
        if fflush(fp)>0 then
           goto err;
      end
      else
      if (s >= fp._bf._size) then
      begin
        w := fp._bf._size;
        w := fp._write^(fp._cookie, p, size_t(w));
        if w <= 0 then
           goto err;
      end
      else
      begin
        w := s;
        COPY(w);
        fp._w  := fp._w - int(w);
        fp._p  := fp._p + w;
      end;
      nldist := nldist - w;
      if  nldist = 0 then
      begin
        { copied the newline: flush and forget }
        if fflush(fp)>0 then
           goto err;
        nlknown := 0;
      end;
      p  := p + w;
      len  := len - w;
      uio.uio_resid := uio.uio_resid - (w);
    end;

  end;
  Exit(0);
err:
  fp._flags  := fp._flags  or __SERR;
  Result := -1;//EOF;
end;

procedure va_copy(orgap, ap: array of const);
var
  i: Integer;
begin
  for I := Low(ap) to High(ap) do
      orgap[i] := ap[i];
end;

procedure memset(var X; Value: Integer; Count: NativeInt );
begin
   FillChar(X, Count, VALUE);
end;

//NetBSD\src\usr\src\lib\libc\stdio\makebuf.c
function __senvbuf(var fp : PFILE; size : libc.Types.Psize_t; couldbetty : Pinteger):integer;
var
  evb : array[0..63] of Char;
  evp: PChar;
  flags, e : integer;
  s : intmax_t;
begin

  flags := 0;
  if snprintf(evb, sizeof(evb) , 'STDBUF%d', [fp._file]) < 0 then
    Exit(flags);

  evp := getenv(evb);
  if (evp = nil)  then
  begin
    evp := getenv('STDBUF');
    if evp = nil then
       Exit(flags);
  end;
  case  evp^ of
  'u',
  'U':
  begin
    Inc(evp);
    flags  := flags  or __SNBF;
  end;
  'l',
  'L':
  begin
    Inc(evp);
    flags  := flags  or __SLBF;
  end;
  'f',
  'F':
  begin
    Inc(evp);
    couldbetty^ := 0;
  end;
  end;
  if  not isdigit(Byte(evp)) then
    Exit(flags);
  s := strtoi(evp, nil, 0, 0, 1024 * 1024, @e);
  if e <> 0 then
     Exit(flags);
  size^ := size_t(s);
  if size^ = 0 then
     Exit(__SNBF);
  Result := flags;
end;

procedure __smakebuf(fp : PFILE);
var
  p          : pointer;
  flags      : integer;
  size       : size_t;
  couldbetty : integer;
  Info: PTypeInfo;
  label unbuf;

begin
  ASSERT(fp <> nil);
  if (fp._flags and __SNBF)>0 then
     flags := __swhatbuf(fp, @size, @couldbetty);
  if ( (fp._flags and (__SLBF or __SNBF or __SMBF) )= 0 )  and
     (fp._cookie = fp)  and  (fp._file >= 0) then
  begin
    flags  := flags  or (__senvbuf(fp, @size, @couldbetty));
    if (flags and __SNBF)>0 then
       goto unbuf;
  end;
  p := malloc(size);
  if p = nil then
     goto unbuf;

  __cleanup := _cleanup;
  flags  := flags  or __SMBF;
  fp._bf._base := p;
  fp._p := p;
  Info:= GetVariableTypeInfo(@size);
  Assert(Info = TypeInfo(int));
  fp._bf._size := int(size);
  if ( couldbetty  and  isatty(__sfileno(fp)) ) > 0 then
    flags  := flags  or __SLBF;

  fp._flags  := fp._flags  or flags;
  exit;
unbuf:
  fp._flags  := fp._flags  or __SNBF;
  fp._bf._base := @fp._nbuf;
  fp._p := @fp._nbuf;
  fp._bf._size := 1;
end;

function __swhatbuf(fp : PFILE; bufsize : libc.Types.Psize_t; couldbetty : Pinteger):integer;
var
  st : _stat;
begin
  ASSERT(fp <> nil);
  ASSERT(bufsize <> nil);
  ASSERT(couldbetty <> nil);
  if (__sfileno(fp) = -1 )  or  ( fstat(__sfileno(fp), &st) < 0)  then
  begin
    couldbetty^ := 0;
    bufsize^ := BUFSIZ;
    Exit(__SNPT);
  end;
  { could be a tty iff it is a character device }
  couldbetty^ := Int(S_ISCHR(st.st_mode));
  if st.st_blksize = 0 then
  begin
    bufsize^ := BUFSIZ;
    Exit(__SNPT);
  end;
  {
   * Optimise fseek() only if it is a regular file.  (The test for
   * __sseek is mainly paranoia.)  It is safe to set _blksize
   * unconditionally; it will only be used if __SOPT is also set.
   }
  bufsize^ := st.st_blksize;
  fp._blksize := st.st_blksize;
  if ( (st.st_mode and S_IFMT) = S_IFREG )  and  (fp._seek = @__sseek)  then
      Result := __SOPT
  else
      Result := __SNPT;
end;

//NETBSD-src\lib\libc\stdio\fileext.h
procedure _FILEEXT_SETUP(f: PFILE; fext: Psfileext) ;
begin
	(* LINTED *)
  f._ext._base := PByte(fext);
	fext._fgetstr_len := 0;
	fext._fgetstr_buf := nil;
end;

procedure _cleanup;
begin
{$IF not defined(_LIBMINC)}//  and  defined(__minix)}
  { (void) _fwalk(fclose); }
   fflush(nil);      { `cheating' }
{$endif}
end;

procedure __sinit;
var
  i : integer;
begin
  for i := 0 to FOPEN_MAX - 3-1 do
      _FILEEXT_SETUP(@usual[i], @usualext[i]);
  { make sure we clean up on exit }
  __cleanup := _cleanup;    { conservative }
  __sdidinit := 1;
end;

function _UB(fp: PFILE): __sbuf;
begin
  Result := _EXT(fp)._ub ;
end;

function HASUB(fp: PFILE): bool;
begin
  Result := _UB(fp)._base <> nil;
end;


procedure	FREEUB(fp: PFILE) ;
var
   p: Pointer;
begin
	if _UB(fp)._base <> @fp._ubuf  then
		free(_UB(fp)._base);

	p := _UB(fp)._base ;
  p := nil;
end;


function __swsetup(fp : PFILE):integer;
begin
  ASSERT(fp <> nil);
  { make sure stdio is set up }
  if  0>= __sdidinit then
     __sinit();
  {
   * If we are not writing, we had better be reading and writing.
   }
  if (fp._flags and __SWR) = 0 then
  begin
    if (fp._flags and __SRW) = 0 then
      Exit(-1);
    if (fp._flags and __SRD)>0 then
    begin
      { clobber any ungetc data }
      if HASUB(fp) then
        FREEUB(fp);
      fp._flags := fp._flags and  not(__SRD or __SEOF);
      fp._r := 0;
      fp._p := fp._bf._base;
    end;
    fp._flags  := fp._flags  or __SWR;
  end;
  {
   * Make a buffer if necessary, then set _w.
   }
  if fp._bf._base = nil then
      __smakebuf(fp);
  if (fp._flags and __SLBF)>0 then
  begin
    {
     * It is line buffered, so make _lbfsize be -_bufsize
     * for the putc() macro.  We will change _lbfsize back
     * to 0 whenever we turn off __SWR.
     }
    fp._w := 0;
    fp._lbfsize := -fp._bf._size;
  end
  else
  begin
    if (fp._flags and __SNBF)>0 then
       fp._w := 0
    else
       fp._w := fp._bf._size;
  end;
  Result := 0;
end;

function cantwrite(fp: PFILE): bool;
begin
  Result := False;
	if ( ((fp._flags and __SWR) = 0 ) or (fp._bf._base = nil) ) and
	   ( __swsetup(fp)>0 ) then
  Result := True;
end;

function WCIO_GET(fp: PFILE): Pwchar_io_data;
begin
	if nil <>_EXT(fp) then
    Result :=  @(_EXT(fp)._wcio)
  else
    Result := Pwchar_io_data(0);
end;
procedure _SET_ORIENTATION(fp: PFILE; mode: int) ;
var
  _wcio: Pwchar_io_data;
begin
	_wcio := WCIO_GET(fp);
	if (_wcio <> nil) and (_wcio.wcio_mode = 0) then
		_wcio.wcio_mode := mode;
end;

function _EXT(fp: PFILE): Psfileext;
begin
   Result := Psfileext( Pointer(fp._ext._base));
end;

//#define __UNCONST(a)	((void *)(Uint32 long)(const void *)(a))
function __UNCONST(a: Pointer): Pointer;
begin
	 Result := Pointer(LongWord(a));
end;

//https://opensource.apple.com/source/xnu/xnu-2782.30.5/bsd/libkern/memchr.c.auto.html
function memchr(const bigptr: PChar; ch : Char; len : size_t);
var
  n : size_t;
  big: Pchar;
begin
  big = Pchar(bigptr);
  for n := 0 to len-1 do 
    if big[n] = ch then 
	   Exit(Pointer(@big[n]));
  Result := nil;
end;

{
function memchr(const buf: Pointer; c: Char; len: size_t): Pointer;
var
  l: Char;
begin
  Result := buf;
  l := c;
  while len <> 0 do
  begin
    if PChar(Result)[0] = l then
      Exit;
    Inc(Integer(Result));
    Dec(len);
  end;
  Result := Nil;
end;
}

function _fwalk(func: Pfunction) :integer;
var
  fp : PFILE;
  n, ret : integer;
  g : Pglue;
begin
  ASSERT(func <> nil);
  ret := 0;
  g := @__sglue;
  while ( g <> nil )  do
  begin
    fp := g.iobs;
    n := g.niobs;
    while  n >= 0 do
    begin
      if fp._flags <> 0 then
         ret  := ret  or func^(fp);
      Inc(fp);
      Dec(n);
    end;
    g := g.next;
  end;
  Result := ret;
end;

function fflush( fp : PFILE):integer;
begin
  if fp = nil then
     Exit(_fwalk(@__sflush));
  if (fp._flags and (__SWR or __SRW) ) = 0 then
  begin
    __errno := EBADF;
    Exit(-1);
  end;
  Result := __sflush(fp);
end;


function __sflush( fp : PFILE):integer;
var
  n, t : integer;
  p: PByte;
begin
  t := fp._flags;
  if (t and __SWR) = 0 then
    Exit((0));
  p := fp._bf._base;
  if  p = nil then
    Exit((0));
  n := fp._p - p;

  fp._p := p;
  if (t and (__SLBF or __SNBF) )>0 then
     fp._w :=  0
  else
     fp._w :=  fp._bf._size;

  while ( n > 0 )  do
  begin
    t := fp._write^(fp._cookie, PChar(p), n);
    if t <= 0 then
    begin
      fp._flags  := fp._flags  or __SERR;
      Exit(-1);
    end;
    n := n- t;
    p := p + t
  end;
  Result := (0);
end;

function IsClass(Address: Pointer): Boolean; assembler;
asm
        CMP     Address, Address.vmtSelfPtr
        JNZ     @False
        MOV     Result, True
        JMP     @Exit
@False:
        MOV     Result, False
@Exit:
end;

function IsObject(Address: Pointer): Boolean; assembler;
asm
// or IsClass(Pointer(Address^));
        MOV     EAX, [Address]
        CMP     EAX, EAX.vmtSelfPtr
        JNZ     @False
        MOV     Result, True
        JMP     @Exit
@False:
        MOV     Result, False
@Exit:
end;

function GetVariableTypeInfo(pvar: Pointer): PTypeInfo;
begin
  if not Assigned(pvar) then
    Result := nil
  else if IsClass(PPointer(pvar)^) then
    Result := PClass(pvar).ClassInfo
  else if IsObject(PPointer(pvar)^) then
    Result := PObject(pvar).ClassInfo
  else
    raise Exception.Create('Unknown Result');
end;

Function IsAlpha( ch: Char ): Boolean;
begin
  Result := ch in ['a'..'z', 'A'..'Z']
end;

Function IsUpper( ch:Char ): Boolean;
begin
  Result := ch in ['A'..'Z']
end;

Function IsDigit( ch: Char ): Boolean;
Begin
  Result := ch In ['0'..'9'];
End;

function IsSpace(Ch: Char): Boolean;
begin
  Result := (Ch = #32) or (Ch = #$00A0); // Unicode non-breaking space
end;

//https://android.googlesource.com/platform/bionic.git/+/froyo/libc/stdlib/strtoimax.c
{ Like `strtol' but convert to `intmax_t'.  }
function strtoimax(nptr: PChar; endptr: PPChar; base: Integer): intmax_t;
var
  acc, cutoff : intmax_t;
  neg, any, cutlim : integer;
  s: PChar;
  c: Char;

  procedure CASE_BASE(x: Integer);
  begin
    //case x:
      if (neg>0) then
      begin
        cutlim := INTMAX_MIN mod x;
        cutoff := INTMAX_MIN div x;
      end
      else
      begin
        cutlim := INTMAX_MAX mod x;
        cutoff := INTMAX_MAX div x;
      end;
  end;

begin
  {
   * Skip white space and pick up leading +/- sign if any.
   * If base is 0, allow 0x for hex and 0 for octal, else
   }
  s := nptr;
  while isspace(c) do
  begin
    c := (s^);
    Inc(s);
  end;

  if c = '-' then
  begin
    neg := 1;
    c := s^;
    Inc(s);
  end
  else
  begin
    neg := 0;
    if c = '+' then
    begin
      c := s^;
      Inc(s);
    end;
  end;
  if ( (base = 0)  or  (base = 16) )  and
     (c = '0')  and  ( (s^ = 'x')  or  (s^ = 'X') ) then
  begin
    c := s[1];
    s  := s + 2;
    base := 16;
  end;
  if base = 0 then
     if c = '0' then
        base := 8
     else
        base := 10;
  {
   * Compute the cutoff value between legal numbers and illegal
   * numbers.  That is the largest legal value, divided by the
   * base.  An input number that is greater than this value, if
   * followed by a legal input character, is too big.  One that
   * between valid and invalid numbers is then based on the last
   * digit.  For instance, if the range for intmax_t is
   * [-9223372036854775808..9223372036854775807] and the input base
   * is 10, cutoff will be set to 922337203685477580 and cutlim to
   * either 7 (neg=0) or 8 (neg=1), meaning that if we have
   * accumulated a value > 922337203685477580, or equal but the
   * next digit is > 7 (or 8), the number is too big, and we will
   * return a range error.
   *
   * Set any if any `digits' consumed; make it negative to indicate
   * overflow.
   }
  { BIONIC: avoid division and module for common cases }
  case base of
     4:
     begin
        if neg>0 then
        begin
            cutlim := int(INTMAX_MIN mod 4);
            cutoff := INTMAX_MIN div 4;
        end
        else
        begin
            cutlim := int(INTMAX_MAX mod 4);
            cutoff := INTMAX_MAX div 4;
        end;
     end;
     8:
      CASE_BASE(8);
     10:
      CASE_BASE(10);
     16:
      CASE_BASE(16);
     else
     begin
        if neg > 0 then
           cutoff :=  INTMAX_MIN
        else
           cutoff := INTMAX_MAX;
        cutlim := cutoff mod base;
        cutoff  := cutoff  div base;
     end;
  end;
  if neg>0 then
  begin
    if cutlim > 0 then
    begin
      cutlim  := cutlim - base;
      cutoff  := cutoff + 1;
    end;
    cutlim := -cutlim;
  end;

  acc := 0;
  any := 0;

  while True do
  begin
    c := s^;
    if isdigit(c) then
      c  := Chr(Ord(c) - Ord('0'))
    else
    if (isalpha(c)) then
    begin
      if isupper(c) then
         c  := Chr(Ord(c) - (Ord('A') - 10 ))
      else
         c  := Chr(Ord(c) - (Ord('a') - 10));
    end
    else
      break;
    if Ord(c) >= base then
       break;
    if any < 0 then
       continue;
    if neg>0 then
    begin
      if (acc < cutoff)  or  ( (acc = cutoff)  and  (Ord(c) > cutlim) ) then
      begin
        any := -1;
        acc := INTMAX_MIN;
        __errno := ERANGE;
      end
      else
      begin
        any := 1;
        acc  := acc  * base;
        acc  := acc - Ord(c);
      end;
    end
    else
    begin
      if (acc > cutoff)  or  ( (acc = cutoff)  and  (Ord(c) > cutlim) ) then
      begin
        any := -1;
        acc := INTMAX_MAX;
        __errno := ERANGE;
      end
      else
      begin
        any := 1;
        acc  := acc  * base;
        acc  := acc + Ord(c);
      end;
    end;
    Inc(s);
  end;
  //if (endptr != 0)
  if endptr <> nil then
     if any>0 then
        endptr^ := Pchar(s - 1)
     else
        endptr^ := Pchar(nptr);
  Result := (acc);
end;


//https://android.googlesource.com/platform/external/dhcpcd-6.8.2/+/refs/tags/android-7.0.0_r6/compat/strtoi.c
function strtoi(const nptr:PChar; endptr : PPChar; base : integer; lo, hi : intmax_t;rstatus : Pinteger):intmax_t;
var
  serrno : integer;
  r : intmax_t;
  ep : PChar;
  rep : integer;
begin
  if endptr = nil then
     endptr := @ep;
  if rstatus = nil then
     rstatus := @rep;
  serrno := __errno;
  __errno := 0;
  r := strtoimax(nptr, endptr, base);
  rstatus^ := __errno;
  __errno := serrno;
  if rstatus^ = 0 then
  begin
    if nptr = endptr^ then
      rstatus^ := ECANCELED
    else
    if ( endptr^^ <> #0) then
      rstatus^ := ENOTSUP;
  end;

  if r < lo then
  begin
    if rstatus^ = 0 then
      rstatus^ := ERANGE;
    Exit(lo);
  end;
  if r > hi then
  begin
    if rstatus^ = 0 then
      rstatus^ := ERANGE;
    Exit(hi);
  end;
  Result := r;
end;


//https://github.com/embeddedartistry/libc
//libc-master\src\ctype
function isdigit( c : integer):bool;
begin
  Result := Cardinal(c - ord('0')) < 10;
end;

function __sseek(cookie: Pointer; offset : off_t; whence : integer):off_t;
var
  fp : PFILE;
  ret : off_t;
begin
  fp := cookie;
  ASSERT(cookie <> nil);
  ASSERT(cookie = fp._cookie);
  ret := FileSeek(__sfileno(fp), offset, whence);
  if ret = off_t( long(-1)) then
    fp._flags := fp._flags and (not __SOFF)
  else
  begin
    fp._flags  := fp._flags  or __SOFF;
    fp._offset := ret;
  end;
  Result := ret;
end;

function __sfileno(p: PFILE): Integer;
begin
  if p._file = -1 then
     Result := -1
  else
     Result := int(ushort(p._file));
end;

procedure memcpy(Dest: Pointer; const source: Pointer; count: Integer);
begin
   move(Source^,Dest^, Count);
end;

procedure free(P: Pointer);
begin
   FreeMemory(P);
end;

initialization
  _doserrno := __doserrno^;

end.
