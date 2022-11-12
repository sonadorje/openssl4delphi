unit libc.error;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

const
{$if defined(_KERNEL) or defined(_KMEMUSER)}
(* pseudo-errors returned inside kernel to modify return to process *)
	EJUSTRETURN	 = -2;		(* don't modify regs, just return *)
	ERESTART     = -3;		(* restart syscall *)
	EPASSTHROUGH = -4;		(* ioctl not handled by this layer *)
	EDUPFD	     = -5;		(* Dup given fd *)
	EMOVEFD		   = -6;		(* Move given fd *)
{$endif}

//{$if defined(__minix)}
(* Now define _SIGN*as "" or "-" depending on _SYSTEM. *)
{$ifdef _SYSTEM}
    _SIGN = -1;
    OK    = 0;
{$else}
   _SIGN = 1;
{$endif}
 	EPERM		= (_SIGN*1 );		(* Operation not permitted *)
	ENOENT		= (_SIGN*2 );		(* No such file or directory *)
	ESRCH		= (_SIGN*3 );		(* No such process *)
	EINTR		= (_SIGN*4 );		(* Interrupted system call *)
	EIO		    = (_SIGN*5 );		(* Input/output error *)
	ENXIO		= (_SIGN*6 );		(* Device not configured *)
	E2BIG		= (_SIGN*7 );		(* Argument list too long *)
	ENOEXEC		= (_SIGN*8 );		(* Exec format error *)
	EBADF		= (_SIGN*9 );		(* Bad file descriptor *)
	ECHILD		= (_SIGN*10 );		(* No child processes *)
	EDEADLK		= (_SIGN*11 );		(* Resource deadlock avoided *)
					(* 11 was EAGAIN *)
	ENOMEM		= (_SIGN*12 );		(* Cannot allocate memory *)
	EACCES		= (_SIGN*13 );		(* Permission denied *)
	EFAULT		= (_SIGN*14 );		(* Bad address *)
	ENOTBLK		= (_SIGN*15 );		(* Block device required *)
	EBUSY		= (_SIGN*16 );		(* Device busy *)
	EEXIST		= (_SIGN*17 );		(* File exists *)
	EXDEV		= (_SIGN*18 );		(* Cross-device link *)
	ENODEV		= (_SIGN*19 );		(* Operation not supported by device *)
	ENOTDIR		= (_SIGN*20 );		(* Not a directory *)
	EISDIR		= (_SIGN*21 );		(* Is a directory *)
	EINVAL		= (_SIGN*22 );		(* Invalid argument *)
	ENFILE		= (_SIGN*23 );		(* Too many open files in system *)
	EMFILE		= (_SIGN*24 );		(* Too many open files *)
	ENOTTY		= (_SIGN*25 );		(* Inappropriate ioctl for device *)
	ETXTBSY		= (_SIGN*26 );		(* Text file busy *)
	EFBIG		= (_SIGN*27 );		(* File too large *)
	ENOSPC		= (_SIGN*28 );		(* No space left on device *)
	ESPIPE		= (_SIGN*29 );		(* Illegal seek *)
	EROFS		= (_SIGN*30 );		(* Read-only file system *)
	EMLINK		= (_SIGN*31 );		(* Too many links *)
	EPIPE		= (_SIGN*32 );		(* Broken pipe *)

(* math software *)
	EDOM		= (_SIGN*33 );		(* Numerical argument out of domain *)
	ERANGE		= (_SIGN*34 );		(* Result too large or too small *)

(* non-blocking and interrupt i/o *)
	EAGAIN		= (_SIGN*35 );		(* Resource temporarily unavailable *)
	EWOULDBLOCK	= EAGAIN ;		(* Operation would block *)
	EINPROGRESS	= (_SIGN*36 );		(* Operation now in progress *)
	EALREADY	= (_SIGN*37 );		(* Operation already in progress *)

(* ipc/network software -- argument errors *)
	ENOTSOCK	= (_SIGN*38 );		(* Socket operation on non-socket *)
	EDESTADDRREQ	= (_SIGN*39 );		(* Destination address required *)
	EMSGSIZE	= (_SIGN*40 );		(* Message too long *)
	EPROTOTYPE	= (_SIGN*41 );		(* Protocol wrong type for socket *)
	ENOPROTOOPT	= (_SIGN*42 );		(* Protocol option not available *)
	EPROTONOSUPPORT	= (_SIGN*43 );		(* Protocol not supported *)
	ESOCKTNOSUPPORT	= (_SIGN*44 );		(* Socket type not supported *)
	EOPNOTSUPP	= (_SIGN*45 );		(* Operation not supported *)
	EPFNOSUPPORT	= (_SIGN*46 );		(* Protocol family not supported *)
	EAFNOSUPPORT	= (_SIGN*47 );		(* Address family not supported by protocol family *)
	EADDRINUSE	= (_SIGN*48 );		(* Address already in use *)
	EADDRNOTAVAIL	= (_SIGN*49 );		(* Can't assign requested address *)

(* ipc/network software -- operational errors *)
	ENETDOWN	= (_SIGN*50 );		(* Network is down *)
	ENETUNREACH	= (_SIGN*51 );		(* Network is unreachable *)
	ENETRESET	= (_SIGN*52 );		(* Network dropped connection on reset *)
	ECONNABORTED	= (_SIGN*53 );		(* Software caused connection abort *)
	ECONNRESET	= (_SIGN*54 );		(* Connection reset by peer *)
	ENOBUFS		= (_SIGN*55 );		(* No buffer space available *)
	EISCONN		= (_SIGN*56 );		(* Socket is already connected *)
	ENOTCONN	= (_SIGN*57 );		(* Socket is not connected *)
	ESHUTDOWN	= (_SIGN*58 );		(* Can't send after socket shutdown *)
	ETOOMANYREFS	= (_SIGN*59 );		(* Too many references: can't splice *)
	ETIMEDOUT	= (_SIGN*60 );		(* Operation timed out *)
	ECONNREFUSED	= (_SIGN*61 );		(* Connection refused *)

	ELOOP		= (_SIGN*62 );		(* Too many levels of symbolic links *)
	ENAMETOOLONG	= (_SIGN*63 );		(* File name too long *)

(* should be rearranged *)
	EHOSTDOWN	= (_SIGN*64 );		(* Host is down *)
	EHOSTUNREACH	= (_SIGN*65 );		(* No route to host *)
	ENOTEMPTY	= (_SIGN*66 );		(* Directory not empty *)

(* quotas & mush *)
	EPROCLIM	= (_SIGN*67 );		(* Too many processes *)
	EUSERS		= (_SIGN*68 );		(* Too many users *)
	EDQUOT		= (_SIGN*69 );		(* Disc quota exceeded *)

(* Network File System *)
	ESTALE		= (_SIGN*70 );		(* Stale NFS file handle *)
	EREMOTE		= (_SIGN*71 );		(* Too many levels of remote in path *)
	EBADRPC		= (_SIGN*72 );		(* RPC struct is bad *)
	ERPCMISMATCH	= (_SIGN*73 );		(* RPC version wrong *)
	EPROGUNAVAIL	= (_SIGN*74 );		(* RPC prog. not avail *)
	EPROGMISMATCH	= (_SIGN*75 );		(* Program version wrong *)
	EPROCUNAVAIL	= (_SIGN*76 );		(* Bad procedure for program *)

	ENOLCK		= (_SIGN*77 );		(* No locks available *)
	ENOSYS		= (_SIGN*78 );		(* Function not implemented *)

	EFTYPE		= (_SIGN*79 );		(* Inappropriate file type or format *)
	EAUTH		= (_SIGN*80 );		(* Authentication error *)
	ENEEDAUTH	= (_SIGN*81 );		(* Need authenticator *)

(* SystemV IPC *)
	EIDRM		= (_SIGN*82 );		(* Identifier removed *)
	ENOMSG		= (_SIGN*83 );		(* No message of desired type *)
	EOVERFLOW	= (_SIGN*84 );		(* Value too large to be stored in data type *)

(* Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995 *)
	EILSEQ		= (_SIGN*85 );		(* Illegal byte sequence *)

(* From IEEE Std 1003.1-2001 *)
(* Base, Realtime, Threads or Thread Priority Scheduling option errors *)
 ENOTSUP		= (_SIGN*86 );		(* Not supported *)

(* Realtime option errors *)
 ECANCELED	= (_SIGN*87 );		(* Operation canceled *)

(* Realtime, XSI STREAMS option errors *)
 EBADMSG		= (_SIGN*88 );		(* Bad or Corrupt message *)

(* XSI STREAMS option errors  *)
 ENODATA		= (_SIGN*89 );		(* No message available *)
 ENOSR		= (_SIGN*90 );		(* No STREAM resources *)
 ENOSTR		= (_SIGN*91 );		(* Not a STREAM *)
 ETIME		= (_SIGN*92 );		(* STREAM ioctl timeout *)

(* File system extended attribute errors *)
	ENOATTR		= (_SIGN*93 );		(* Attribute not found *)

(* Realtime, XSI STREAMS option errors *)
	EMULTIHOP	= (_SIGN*94 );		(* Multihop attempted *)
	ENOLINK		= (_SIGN*95 );		(* Link has been severed *)
	EPROTO		= (_SIGN*96 );		(* Protocol error *)

	ELAST		= (_SIGN*96 );		(* Must equal largest errno *)



(* minix-specific error codes *)
 ERESTART     = (_SIGN*200 );  (* service restarted *)
 ENOTREADY    = (_SIGN*201 );  (* source or destination is not ready *)
 EDEADSRCDST  = (_SIGN*202 );  (* source or destination is not alive *)
 EDONTREPLY   = (_SIGN*203 );  (* pseudo-code: don't send a reply *)
 EGENERIC     = (_SIGN*204 );  (* generic error *)
 EPACKSIZE    = (_SIGN*205 );  (* invalid packet size for some protocol *)
 EURG         = (_SIGN*206 );  (* urgent data present *)
 ENOURG       = (_SIGN*207 );  (* no urgent data present *)
 ELOCKED      = (_SIGN*208 );  (* can't send message due to deadlock *)
 EBADCALL     = (_SIGN*209 );  (* illegal system call number *)
 ECALLDENIED  = (_SIGN*210 );  (* no permission for system call *)
 ETRAPDENIED  = (_SIGN*211 );  (* IPC trap not allowed *)
 EBADREQUEST  = (_SIGN*212 );  (* destination cannot handle request *)
 EBADMODE     = (_SIGN*213 );  (* badmode in ioctl *)
 ENOCONN      = (_SIGN*214 );  (* no such connection *)
 EDEADEPT     = (_SIGN*215 );  (* specified endpoint is not alive *)
 EBADEPT      = (_SIGN*216 );  (* specified endpoint is bad *)
 EBADCPU      = (_SIGN*217 );  (* requested CPU does not work *)

//#endif (* defined(__minix) *)
implementation

end.
