(*
 * Cryptographic API Prototypes and Definitions
 *
 * Copyright (C) 2016 Vincent Hardy <vincent.hardy.be@gmail.com>
 *
 * You may retrieve the latest version of this file at
 * https://github.com/delphiunderground/wwsapi
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 *)

unit ncrypt;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

type
  ULONG_PTR = LongWord;   //http://wiki.delphi-jedi.org/wiki/JCL_Help:ULONG_PTR

//
// NCrypt handles
//
  NCRYPT_HANDLE = ULONG_PTR;
  NCRYPT_PROV_HANDLE = ULONG_PTR;
  NCRYPT_KEY_HANDLE = ULONG_PTR;
  NCRYPT_HASH_HANDLE = ULONG_PTR;
  NCRYPT_SECRET_HANDLE = ULONG_PTR;


implementation

end.
