
function HOST_l2c( l : uint32;var c : PByte):uint32;
begin
   PostInc(c)^ := Byte(((l) shr 24) and $ff);
   PostInc(c)^ := Byte(((l) shr 16) and $ff);
   PostInc(c)^ := Byte(((l) shr  8) and $ff);
   PostInc(c)^ := Byte(((l) ) and $ff);
   Result := l;
end;

function HASH_FINAL( md : PByte; c : PHASH_CTX):integer;
var
  p : PByte;
  n : size_t;
begin
    p := PByte( @c.data);
    n := c.num;
    p[n] := $80;
    PostInc(n);
    if n > (HASH_CBLOCK - 8) then
    begin
        memset(p + n, 0, HASH_CBLOCK - n);
        n := 0;
        HASH_BLOCK_DATA_ORDER(c, p, 1);
    end;
    memset(p + n, 0, HASH_CBLOCK - 8 - n);
    p  := p + (HASH_CBLOCK - 8);
{$IF defined(DATA_ORDER_IS_BIG_ENDIAN)}
    HOST_l2c(c.Nh, p);
    HOST_l2c(c.Nl, p);
{$elseif defined(DATA_ORDER_IS_LITTLE_ENDIAN)}
    (void)HOST_l2c(c.Nl, p);
    (void)HOST_l2c(c.Nh, p);
{$IFEND}
    p  := p - HASH_CBLOCK;
    HASH_BLOCK_DATA_ORDER(c, p, 1);
    c.num := 0;
    OPENSSL_cleanse(p, HASH_CBLOCK);

    HASH_MAKE_STRING(c, md);

    Result := 1;
end;

procedure HOST_c2l(var c : PByte; var l : uint32);
begin
  l := (uint32( PostInc(c)^)) shl 24;
  l := l or ((uint32( PostInc(c)^)) shl 16);
  l := l or ((uint32( PostInc(c)^)) shl  8);
  l := l or ((uint32( PostInc(c)^))    );
end;

function ROTATE(a,n: uint32):uint32;
begin
   Result :=(((a) shl (n)) or (((a)and $ffffffff) shr (32-(n))));
end;

function HASH_UPDATE( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer;
var
  data, p : PByte;

  l : HASH_LONG;

  n : size_t;
begin
     data := data_;
    if len = 0 then Exit(1);
    l := (c.Nl + ((HASH_LONG(len))  shl  3)) and $ffffffff;
    if l < c.Nl then { overflow }
        Inc(c.Nh);
    c.Nh  := c.Nh + (HASH_LONG(len  shr  29));// might cause compiler warning on 16-bit
    c.Nl := l;
    n := c.num;
    if n <> 0 then
    begin
        p := PByte( @c.data);
        if (len >= HASH_CBLOCK)  or  (len + n >= HASH_CBLOCK) then
        begin
            memcpy(p + n, data, HASH_CBLOCK - n);
            HASH_BLOCK_DATA_ORDER(c, p, 1);
            n := HASH_CBLOCK - n;
            data  := data + n;
            len  := len - n;
            c.num := 0;
            {
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             }
            memset(p, 0, HASH_CBLOCK); { keep it zeroed }
        end
        else
        begin
            memcpy(p + n, data, len);
            c.num  := c.num + Uint32 (len);
            Exit(1);
        end;
    end;
    n := len div HASH_CBLOCK;
    if n > 0 then
    begin
        HASH_BLOCK_DATA_ORDER(c, data, n);
        n  := n  * HASH_CBLOCK;
        data  := data + n;
        len  := len - n;
    end;
    if len <> 0 then
    begin
        p := PByte( @c.data);
        c.num := Uint32 (len);
        memcpy(p, data, len);
    end;
    Result := 1;
end;

