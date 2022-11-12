unit OpenSSL3.crypto.rsa.rsa_x931;

interface
uses OpenSSL.Api;

function RSA_padding_add_X931(&to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
  function RSA_padding_check_X931(&to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
  function RSA_X931_hash_id( nid : integer):integer;

implementation
uses OpenSSL3.Err;

function RSA_padding_add_X931(&to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
var
  j : integer;

  p : PByte;
begin
    {
     * Absolute minimum amount of padding is 1 header nibble, 1 padding
     * nibble and 2 trailer bytes: but 1 hash if is already in 'from'.
     }
    j := tlen - flen - 2;
    if j < 0 then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(-1);
    end;
    p := PByte( &to);
    { If no padding start and end nibbles are in one byte }
    if j = 0 then
    begin
        PostInc(p)^ :=  $6A;
    end
    else
    begin
        PostInc(p)^ :=  $6B;
        if j > 1 then
        begin
            memset(p, $BB, j - 1);
            p  := p + (j - 1);
        end;
        PostInc(p)^ :=  $BA;
    end;
    memcpy(p, from, uint32( flen));
    p  := p + flen;
    p^ := $CC;
    Result := 1;
end;


function RSA_padding_check_X931(&to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
var
  i, j : integer;

  p : PByte;

  c : Byte;
begin
    i := 0;
    p := from;
    if (num <> flen)  or  (( p^ <> $6A)  and  ( p^ <> $6B)) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_HEADER);
        Exit(-1);
    end;
    if PostInc(p)^ = $6B  then
    begin
        j := flen - 3;
        for i := 0 to j-1 do
        begin
            c := PostInc(p)^;
            if c = $BA then break;
            if c <> $BB then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING);
                Exit(-1);
            end;
        end;
        j  := j - i;
        if i = 0 then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING);
            Exit(-1);
        end;
    end
    else
    begin
        j := flen - 2;
    end;
    if p[j] <> $CC then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_TRAILER);
        Exit(-1);
    end;
    memcpy(&to, p, uint32( j));
    Result := j;
end;


function RSA_X931_hash_id( nid : integer):integer;
begin
    case nid of
    NID_sha1:
        Exit($33);
    NID_sha256:
        Exit($34);
    NID_sha384:
        Exit($36);
    NID_sha512:
        Exit($35);
    end;
    Result := -1;
end;


end.
