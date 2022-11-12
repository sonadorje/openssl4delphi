unit OpenSSL3.crypto.x509.v3_addr;

interface
uses OpenSSL.Api, SysUtils;

const
  ADDR_RAW_BUF_LEN = 16;

  function length_from_afi(const afi : uint32):integer;
  function addr_expand(addr : PByte;const bs : PASN1_BIT_STRING; _length : integer; fill : Byte):integer;
  function i2r_address(_out : PBIO;const afi : uint32; fill : Byte; bs : PASN1_BIT_STRING):integer;
  function i2r_IPAddressOrRanges(_out : PBIO;const indent : integer; aors : PIPAddressOrRanges; afi : uint32):integer;
  function i2r_IPAddrBlocks(const method : PX509V3_EXT_METHOD; ext : Pointer; _out : PBIO; indent : integer):integer;
  function IPAddressOrRange_cmp(const a, b : PIPAddressOrRange; length : integer):integer;
  function v4IPAddressOrRange_cmp(const a, b : PPIPAddressOrRange):integer;
  function v6IPAddressOrRange_cmp(const a, b : PPIPAddressOrRange):integer;
  function range_should_be_prefix(const min, max : PByte; _length : integer):integer;
  function make_addressPrefix(result1 : PPIPAddressOrRanges; addr : PByte;const prefixlen : integer):integer;
  function make_addressRange(result1 : PPIPAddressOrRanges; min, max : PByte;const length : integer):integer;
  function make_IPAddressFamily(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):PIPAddressFamily;
  function X509v3_addr_add_inherit(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):integer;
  function make_prefix_or_range(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):PIPAddressOrRanges;
  function X509v3_addr_add_prefix(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32; a : PByte;const prefixlen : integer):integer;
  function X509v3_addr_add_range(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32; min, max : PByte):integer;
  function extract_min_max( aor : PIPAddressOrRange; min, max : PByte; length : integer):integer;
  function X509v3_addr_get_range(aor : PIPAddressOrRange;const afi : uint32; min, max : PByte;const length : integer):integer;
  function IPAddressFamily_cmp(const a_, b_ : PPIPAddressFamily):integer;
  function X509v3_addr_is_canonical( addr : PIPAddrBlocks):integer;
  function IPAddressOrRanges_canonize(aors : PIPAddressOrRange;const afi : uint32):integer;
  function X509v3_addr_canonize( addr : PIPAddrBlocks):integer;
  function v2i_IPAddrBlocks(const method : Pv3_ext_method; ctx : Pv3_ext_ctx; values : PSTACK_st_CONF_VALUE):Pointer;
  function X509v3_addr_inherits( addr : PIPAddrBlocks):integer;
  function addr_contains( parent, child : PIPAddressOrRanges; length : integer):integer;
  function X509v3_addr_subset( a, b : PIPAddrBlocks):integer;
  function addr_validate_path_internal( ctx : PX509_STORE_CTX; chain : PSTACK_st_X509; ext : PIPAddrBlocks):integer;
  function X509v3_addr_validate_path( ctx : PX509_STORE_CTX):integer;
  function X509v3_addr_validate_resource_set( chain : PSTACK_st_X509; ext : PIPAddrBlocks; allow_inheritance : integer):integer;
  function addr_prefixlen(bs: PASN1_BIT_STRING): Integer;
  function X509v3_addr_get_afi(const f : PIPAddressFamily):uint32;

  function d2i_IPAddressRange(a : PPIPAddressRange;const _in : PPByte; len : long):PIPAddressRange;
  function i2d_IPAddressRange(const a : PIPAddressRange; _out : PPByte):integer;
  function IPAddressRange_new:PIPAddressRange;
  procedure IPAddressRange_free( a : PIPAddressRange);
  function d2i_IPAddressOrRange(a : PPIPAddressOrRange;const _in : PPByte; len : long):PIPAddressOrRange;
  function i2d_IPAddressOrRange(const a : PIPAddressOrRange; _out : PPByte):integer;
  function IPAddressOrRange_new:PIPAddressOrRange;
  procedure IPAddressOrRange_free( a : PIPAddressOrRange);
  function d2i_IPAddressChoice(a : PPIPAddressChoice;const _in : PPByte; len : long):PIPAddressChoice;
  function i2d_IPAddressChoice(const a : PIPAddressChoice; _out : PPByte):integer;
  function IPAddressChoice_new:PIPAddressChoice;
  procedure IPAddressChoice_free( a : PIPAddressChoice);
  function d2i_IPAddressFamily(a : PPIPAddressFamily;const _in : PPByte; len : long):PIPAddressFamily;
  function i2d_IPAddressFamily(const a : PIPAddressFamily; _out : PPByte):integer;
  function IPAddressFamily_new:PIPAddressFamily;
  procedure IPAddressFamily_free( a : PIPAddressFamily);
  function IPAddressRange_it:PASN1_ITEM;
  function IPAddressOrRange_it:PASN1_ITEM;
  function IPAddressChoice_it:PASN1_ITEM;
  function IPAddressFamily_it:PASN1_ITEM;
  function IPAddrBlocks_it:PASN1_ITEM;

var
  IPAddressRange_seq_tt, IPAddressOrRange_ch_tt,
  IPAddressChoice_ch_tt, IPAddressFamily_seq_tt : array of TASN1_TEMPLATE;
  IPAddrBlocks_item_tt :TASN1_TEMPLATE;
  ossl_v3_addr :TX509V3_EXT_METHOD;

implementation

uses openssl3.crypto.bio.bio_print, openssl3.crypto.x509v3, OpenSSL3.common,
     OpenSSL3.Err, OpenSSL3.openssl.conf, OpenSSL3.crypto.x509.v3_utl,
     openssl3.crypto.bio.bio_lib,  openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc,  openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_bitstr,  openssl3.crypto.asn1.a_octet,
     openssl3.crypto.o_str, openssl3.crypto.mem, openssl3.crypto.x509;


function IPAddrBlocks_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($0, -1, @IPAddrBlocks_item_tt, 0,
                    Pointer(0) , 0, ' IPAddrBlocks');

  Result := @local_it;
end;

function IPAddressFamily_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @IPAddressFamily_seq_tt,
                       sizeof(IPAddressFamily_seq_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(IPAddressFamily), ' IPAddressFamily');

   Result := @local_it;
end;




function IPAddressChoice_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($2, size_t(@PIPAddressChoice(0).&type) ,
           @IPAddressChoice_ch_tt,
       sizeof(IPAddressChoice_ch_tt) div sizeof(TASN1_TEMPLATE),
       Pointer(0) , sizeof(IPAddressChoice), ' IPAddressChoice');

   Result := @local_it;
end;


function IPAddressOrRange_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($2, size_t(@PIPAddressOrRange(0).&type) ,
                          @IPAddressOrRange_ch_tt,
              sizeof(IPAddressOrRange_ch_tt) div sizeof(TASN1_TEMPLATE),
              Pointer(0) , sizeof(TIPAddressOrRange), ' IPAddressOrRange');

  Result := @local_it;
end;

function IPAddressRange_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @IPAddressRange_seq_tt,
              sizeof(IPAddressRange_seq_tt) div sizeof(TASN1_TEMPLATE),
              Pointer(0) , sizeof(IPAddressRange), ' IPAddressRange') ;
   Result := @local_it;
end;



function d2i_IPAddressRange(a : PPIPAddressRange;const _in : PPByte; len : long):PIPAddressRange;
begin
   Result := PIPAddressRange(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, IPAddressRange_it));
end;


function i2d_IPAddressRange(const a : PIPAddressRange; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, IPAddressRange_it);
end;


function IPAddressRange_new:PIPAddressRange;
begin
   Result := PIPAddressRange(ASN1_item_new(IPAddressRange_it));
end;


procedure IPAddressRange_free( a : PIPAddressRange);
begin
 ASN1_item_free(PASN1_VALUE( a), IPAddressRange_it);
end;


function d2i_IPAddressOrRange(a : PPIPAddressOrRange;const _in : PPByte; len : long):PIPAddressOrRange;
begin
   Result := PIPAddressOrRange(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, IPAddressOrRange_it));
end;


function i2d_IPAddressOrRange(const a : PIPAddressOrRange; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, IPAddressOrRange_it);
end;


function IPAddressOrRange_new:PIPAddressOrRange;
begin
   Result := PIPAddressOrRange(ASN1_item_new(IPAddressOrRange_it));
end;


procedure IPAddressOrRange_free( a : PIPAddressOrRange);
begin
   ASN1_item_free(PASN1_VALUE( a), IPAddressOrRange_it);
end;


function d2i_IPAddressChoice(a : PPIPAddressChoice;const _in : PPByte; len : long):PIPAddressChoice;
begin
   Result := PIPAddressChoice(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, IPAddressChoice_it));
end;


function i2d_IPAddressChoice(const a : PIPAddressChoice; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, IPAddressChoice_it);
end;


function IPAddressChoice_new:PIPAddressChoice;
begin
   Result := PIPAddressChoice(ASN1_item_new(IPAddressChoice_it));
end;


procedure IPAddressChoice_free( a : PIPAddressChoice);
begin
 ASN1_item_free(PASN1_VALUE( a), IPAddressChoice_it);
end;


function d2i_IPAddressFamily(a : PPIPAddressFamily;const _in : PPByte; len : long):PIPAddressFamily;
begin
   Result := PIPAddressFamily(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, IPAddressFamily_it));
end;


function i2d_IPAddressFamily(const a : PIPAddressFamily; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, IPAddressFamily_it);
end;


function IPAddressFamily_new:PIPAddressFamily;
begin
   Result := PIPAddressFamily(ASN1_item_new(IPAddressFamily_it));
end;


procedure IPAddressFamily_free( a : PIPAddressFamily);
begin
 ASN1_item_free(PASN1_VALUE( a), IPAddressFamily_it);
end;





function X509v3_addr_get_afi(const f : PIPAddressFamily):uint32;
begin
    if (f = nil)
             or  (f.addressFamily = nil)
             or  (f.addressFamily.data = nil)
             or  (f.addressFamily.length < 2) then
       Exit(0);
    Result := (f.addressFamily.data[0] shl  8) or f.addressFamily.data[1];
end;

function addr_prefixlen(bs: PASN1_BIT_STRING): Integer;
begin
   Result := int(bs.length * 8 - (bs.flags and 7));
end;

function length_from_afi(const afi : uint32):integer;
begin
    case afi of
    IANA_AFI_IPV4:
        Exit(4);
    IANA_AFI_IPV6:
        Exit(16);
    else
        Exit(0);
    end;
end;


function addr_expand(addr : PByte;const bs : PASN1_BIT_STRING; _length : integer; fill : Byte):integer;
var
  mask : Byte;
begin
    if (bs.length < 0)  or  (bs.length > _length) then
        Exit(0);
    if bs.length > 0 then
    begin
        memcpy(addr, bs.data, bs.length);
        if (bs.flags and 7) <> 0 then
        begin
            mask := $FF  shr  (8 - (bs.flags and 7));
            if fill = 0 then
               addr[bs.length - 1] := addr[bs.length - 1] and (not mask)
            else
               addr[bs.length - 1]  := addr[bs.length - 1]  or mask;
        end;
    end;
    memset(addr + bs.length, fill, _length - bs.length);
    Result := 1;
end;


function i2r_address(_out : PBIO;const afi : uint32; fill : Byte; bs : PASN1_BIT_STRING):integer;
var
  addr : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  s : PUTF8Char;
  i, n : integer;
begin
    if bs.length < 0 then Exit(0);
    case afi of
        IANA_AFI_IPV4:
        begin
            if  0>= addr_expand(@addr, bs, 4, fill) then
                Exit(0);
            BIO_printf(_out, '%d.%d.%d.%d', [ addr[0], addr[1], addr[2], addr[3] ] );
        end;
        IANA_AFI_IPV6:
        begin
            if  0>= addr_expand(@addr, bs, 16, fill) then
                Exit(0);
            n := 16;
            while ( n > 1)  and  (addr[n - 1] = $00)  and  (addr[n - 2] = $00) do
               n  := n - (2) ;
            i := 0;
            while (i < n) do
            begin
                if i < 14 then
                   s := ':'
                else
                   s := '';
                BIO_printf(_out, '%x%s', [(addr[i]  shl  8) or addr[i + 1],s]);
                i := i+ 2;
            end;
            if i < 16 then
               BIO_puts(_out, ':');
            if i = 0 then
               BIO_puts(_out, ':');
        end
        else
        begin
            if (i > 0 ) then
               s :=  ':'
            else
               s := '';
            for i := 0 to bs.length-1 do
                BIO_printf(_out, '%s%02x', [s, bs.data[i] ]);
            BIO_printf(_out, '[%d]', [int(bs.flags and 7)]);
        end;
    end;
    Result := 1;
end;


function i2r_IPAddressOrRanges(_out : PBIO;const indent : integer; aors : PIPAddressOrRanges; afi : uint32):integer;
var
  i : integer;

  aor : PIPAddressOrRange;
begin
    for i := 0 to sk_IPAddressOrRange_num(aors)-1 do
    begin
        aor := sk_IPAddressOrRange_value(aors, i);
        BIO_printf(_out, '%*s', [indent, '']);
        case aor.&type of
            IPAddressOrRange_addressPrefix:
            begin
                if  0>= i2r_address(_out, afi, $00, aor.u.addressPrefix)  then
                    Exit(0);
                BIO_printf(_out, '/%d'#10, [addr_prefixlen(aor.u.addressPrefix)]);
                continue;
            end;
            IPAddressOrRange_addressRange:
            begin
                if  0>= i2r_address(_out, afi, $00, aor.u.addressRange.min )then
                    Exit(0);
                BIO_puts(_out, '-');
                if  0>= i2r_address(_out, afi, $FF, aor.u.addressRange.max )  then
                    Exit(0);
                BIO_puts(_out, #10);
                continue;
            end;
        end;
    end;
    Result := 1;
end;


function i2r_IPAddrBlocks(const method : PX509V3_EXT_METHOD; ext : Pointer; _out : PBIO; indent : integer):integer;
var
  addr : PIPAddrBlocks;

  i : integer;
  afi: uint;
  f : PIPAddressFamily;
begin
    addr := ext;
    for i := 0 to sk_IPAddressFamily_num(addr)-1 do
    begin
        f := sk_IPAddressFamily_value(addr, i);
        afi := X509v3_addr_get_afi(f);
        case afi of
          IANA_AFI_IPV4:
              BIO_printf(_out, '%*sIPv4', [indent, '']);

          IANA_AFI_IPV6:
              BIO_printf(_out, '%*sIPv6', [indent, '']);

          else
              BIO_printf(_out, '%*sUnknown AFI %u', [indent, '', afi]);

        end;
        if f.addressFamily.length > 2 then
        begin
            case f.addressFamily.data[2] of
            1:
                BIO_puts(_out, ' (Unicast)');

            2:
                BIO_puts(_out, ' (Multicast)');

            3:
                BIO_puts(_out, ' (Unicast/Multicast)');

            4:
                BIO_puts(_out, ' (MPLS)');

            64:
                BIO_puts(_out, ' (Tunnel)');

            65:
                BIO_puts(_out, ' (VPLS)');

            66:
                BIO_puts(_out, ' (BGP MDT)');

            128:
                BIO_puts(_out, ' (MPLS-labeled VPN)');

            else
                BIO_printf(_out, ' (Unknown SAFI %u)',
                           [UInt32 (f.addressFamily.data[2])]);

            end;
        end;
        case f.ipAddressChoice.&type of
            IPAddressChoice_inherit:
                BIO_puts(_out, ': inherit'#10);

            IPAddressChoice_addressesOrRanges:
            begin
                BIO_puts(_out, ':'#10);
                if  0>= i2r_IPAddressOrRanges(_out,
                               indent + 2,
                             f.ipAddressChoice.u.addressesOrRanges, afi)  then
                    Exit(0);
            end;
        end;
    end;
    Result := 1;
end;


function IPAddressOrRange_cmp(const a, b : PIPAddressOrRange; length : integer):integer;
var
  addr_a      : array[0..ADDR_RAW_BUF_LEN - 1] of Byte;
  addr_b      : array[0..ADDR_RAW_BUF_LEN - 1] of Byte;

  prefixlen_a,
  prefixlen_b,
  r           : integer;
begin

    prefixlen_a := 0; prefixlen_b := 0;
    case a.&type of
      IPAddressOrRange_addressPrefix:
      begin
          if  0>= addr_expand(@addr_a, a.u.addressPrefix, length, $00 ) then
              Exit(-1);
          prefixlen_a := addr_prefixlen(a.u.addressPrefix);
      end;
      IPAddressOrRange_addressRange:
      begin
          if  0>= addr_expand(@addr_a, a.u.addressRange.min, length, $00 )  then
              Exit(-1);
          prefixlen_a := length * 8;
      end;
    end;
    case b.&type of
        IPAddressOrRange_addressPrefix:
        begin

            if  0>= addr_expand(@addr_b, b.u.addressPrefix, length, $00  )then
                Exit(-1);
            prefixlen_b := addr_prefixlen(b.u.addressPrefix);
        end;
        IPAddressOrRange_addressRange:
        begin
            if  0>= addr_expand(@addr_b, b.u.addressRange.min, length, $00)  then
                Exit(-1);
            prefixlen_b := length * 8;
        end;
    end;
    r := memcmp(@addr_a, @addr_b, length );
    if r <> 0 then
        Exit(r)
    else
        Result := prefixlen_a - prefixlen_b;
end;


function v4IPAddressOrRange_cmp(const a, b : PPIPAddressOrRange):integer;
begin
    Result := IPAddressOrRange_cmp( a^, b^, 4);
end;


function v6IPAddressOrRange_cmp(const a, b : PPIPAddressOrRange):integer;
begin
    Result := IPAddressOrRange_cmp( a^, b^, 16);
end;


function range_should_be_prefix(const min, max : PByte; _length : integer):integer;
var
  mask : Byte;

  i, j : integer;
begin
    if memcmp(min, max, _length) <= 0then
        Exit(-1);
    i := 0 ;
    while (i< _length)  and  (min[i] = max[i]-1) do
      Inc(i);
    j := _length - 1;
    while ( j >= 0 ) and ( min[j] = $00)  and ( max[j] = $FF) do
      Dec(j) ;
    if i < j then Exit(-1);
    if i > j then Exit(i * 8);
    mask := min[i]  xor  max[i];
    case mask of
      $01:
          j := 7;
      $03:
          j := 6;
      $07:
          j := 5;
      $0F:
          j := 4;
      $1F:
          j := 3;
      $3F:
          j := 2;
      $7F:
          j := 1;
      else
          Exit(-1);
    end;
    if (( min[i] and mask) <> 0 ) or  ( (max[i] and mask) <> mask ) then
        Exit(-1)
    else
        Result := i * 8 + j;
end;


function make_addressPrefix(result1 : PPIPAddressOrRanges; addr : PByte;const prefixlen : integer):integer;
var
  bytelen, bitlen : integer;

  aor : PIPAddressOrRange;

  label err;
begin
    bytelen := (prefixlen + 7) div 8; bitlen := prefixlen mod 8;
    aor := IPAddressOrRange_new();
    if aor = nil then Exit(0);
    aor.&type := IPAddressOrRange_addressPrefix;

    if (aor.u.addressPrefix = nil)  then
    begin
       aor.u.addressPrefix := ASN1_BIT_STRING_new( );
       if (aor.u.addressPrefix = nil)   then
         goto err;
    end;
    if  0>= ASN1_BIT_STRING_set(aor.u.addressPrefix, addr, bytelen) then
        goto err;
    aor.u.addressPrefix.flags := aor.u.addressPrefix.flags and (not 7);
    aor.u.addressPrefix.flags  := aor.u.addressPrefix.flags  or ASN1_STRING_FLAG_BITS_LEFT;
    if bitlen > 0 then
    begin
        aor.u.addressPrefix.data[bytelen - 1] := aor.u.addressPrefix.data[bytelen - 1] and not($FF  shr  bitlen);
        aor.u.addressPrefix.flags  := aor.u.addressPrefix.flags  or (8 - bitlen);
    end;
    result1^ := aor;
    Exit(1);
 err:
    IPAddressOrRange_free(aor);
    Exit(0);
end;


function make_addressRange(result1 : PPIPAddressOrRanges; min, max : PByte;const length : integer):integer;
var
    aor       : PIPAddressOrRange;

    i,
    prefixlen : integer;
    b         : Byte;
    j         : integer;
    label   err;
begin
    prefixlen := range_should_be_prefix(min, max, length );
    if prefixlen >= 0 then
        Exit(make_addressPrefix(result1, min, prefixlen));
    aor := IPAddressOrRange_new( );
    if aor = nil then
        Exit(0);
    aor.&type := IPAddressOrRange_addressRange;
    aor.u.addressRange := IPAddressRange_new();
    if aor.u.addressRange = nil then
       goto err;
    if (aor.u.addressRange.min = nil) then
    begin
       aor.u.addressRange.min := ASN1_BIT_STRING_new();
       if aor.u.addressRange.min = nil then
          goto err;
    end;
    if (aor.u.addressRange.max = nil) then
    begin
        aor.u.addressRange.max := ASN1_BIT_STRING_new();
       if (aor.u.addressRange.max = nil) then
          goto err;
    end;
    i := length;
    while ( i > 0)  and  (min[i - 1] = $00) do
      Dec(i) ;
    if  0>= ASN1_BIT_STRING_set(aor.u.addressRange.min, min, i)  then
        goto err;
    aor.u.addressRange.min.flags := aor.u.addressRange.min.flags and (not 7);
    aor.u.addressRange.min.flags := aor.u.addressRange.min.flags  or ASN1_STRING_FLAG_BITS_LEFT;
    if i > 0 then
    begin
        b := min[i - 1];
        j := 1;
        while (b and ($FF  shr  j)) <> 0 do
            Inc(j);
        aor.u.addressRange.min.flags  := aor.u.addressRange.min.flags  or (8 - j);
    end;
    i := length;
    while ( i > 0)  and  (max[i - 1] = $FF) do
       Dec(i);
    if 0>= ASN1_BIT_STRING_set(aor.u.addressRange.max, max, i) then
       goto err;
    aor.u.addressRange.max.flags := aor.u.addressRange.max.flags and (not 7);
    aor.u.addressRange.max.flags := aor.u.addressRange.max.flags  or ASN1_STRING_FLAG_BITS_LEFT;
    if i > 0 then
    begin
        b := max[i - 1];
        j := 1;
        while (b and ($FF  shr  j)) <> ($FF  shr  j) do
            Inc(j);
        aor.u.addressRange.max.flags  := aor.u.addressRange.max.flags  or (8 - j);
    end;
    result1^ := aor;
    Exit(1);
 err:
    IPAddressOrRange_free(aor);
    Exit(0);
end;


function make_IPAddressFamily(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):PIPAddressFamily;
var
  f : PIPAddressFamily;

  key : array[0..2] of Byte;

  keylen, i : integer;

  label err;
begin
    key[0] := (afi  shr  8) and $FF;
    key[1] := afi and $FF;
    if safi <> nil then
    begin
        key[2] := safi^ and $FF;
        keylen := 3;
    end
    else
    begin
        keylen := 2;
    end;
    for i := 0 to sk_IPAddressFamily_num(addr)-1 do
    begin
        f := sk_IPAddressFamily_value(addr, i);
        if (f.addressFamily.length = keylen ) and
           (0>= memcmp(f.addressFamily.data, @key, keylen)  ) then
            Exit(f);
    end;
     f := IPAddressFamily_new();
    if f = nil then
        goto err;
    if (f.ipAddressChoice = nil) then
    begin
       f.ipAddressChoice := IPAddressChoice_new();
       if (f.ipAddressChoice = nil) then
         goto err;
    end;
    if (f.addressFamily = nil) then
    begin
        f.addressFamily := ASN1_OCTET_STRING_new();
        if (f.addressFamily = nil) then
         goto err;
    end;

    if  0>= ASN1_OCTET_STRING_set(f.addressFamily, @key, keylen) then
         goto err;
    if ( 0>= sk_IPAddressFamily_push(addr, f)) then
         goto err;
    Exit(f);
 err:
    IPAddressFamily_free(f);
    Result := nil;
end;


function X509v3_addr_add_inherit(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):integer;
var
  f : PIPAddressFamily;
begin
    f := make_IPAddressFamily(addr, afi, safi);
    if (f = nil)  or
       (f.ipAddressChoice = nil)  or
        ( (f.ipAddressChoice.&type = IPAddressChoice_addressesOrRanges)  and
          (f.ipAddressChoice.u.addressesOrRanges <> nil) ) then
        Exit(0);
    if (f.ipAddressChoice.&type = IPAddressChoice_inherit)  and
       (f.ipAddressChoice.u.inherit <> nil) then
        Exit(1);
    if (f.ipAddressChoice.u.inherit = nil)  then
    begin
       f.ipAddressChoice.u.inherit := ASN1_null_new();
       if (f.ipAddressChoice.u.inherit = nil) then
          Exit(0);
    end;
    f.ipAddressChoice.&type := IPAddressChoice_inherit;
    Result := 1;
end;


function make_prefix_or_range(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32):PIPAddressOrRanges;
var
  f : PIPAddressFamily;

  aors : PIPAddressOrRanges;
begin
    f := make_IPAddressFamily(addr, afi, safi);
    aors := nil;
    if (f = nil)  or
       (f.ipAddressChoice = nil)  or
       ( (f.ipAddressChoice.&type = IPAddressChoice_inherit)  and
         (f.ipAddressChoice.u.inherit <> nil)  ) then
        Exit(nil);
    if f.ipAddressChoice.&type = IPAddressChoice_addressesOrRanges then
       aors := f.ipAddressChoice.u.addressesOrRanges;
    if aors <> nil then
       Exit(aors);
    aors := sk_IPAddressOrRange_new_null();
    if aors = nil then
        Exit(nil);
    case afi of
    IANA_AFI_IPV4:
        sk_IPAddressOrRange_set_cmp_func(aors, v4IPAddressOrRange_cmp);
        //break;
    IANA_AFI_IPV6:
        sk_IPAddressOrRange_set_cmp_func(aors, v6IPAddressOrRange_cmp);
        //break;
    end;
    f.ipAddressChoice.&type := IPAddressChoice_addressesOrRanges;
    f.ipAddressChoice.u.addressesOrRanges := aors;
    Result := aors;
end;


function X509v3_addr_add_prefix(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32; a : PByte;const prefixlen : integer):integer;
var
  aors, aor : PIPAddressOrRanges;
begin
    aors := make_prefix_or_range(addr, afi, safi);
    if (aors = nil)  or  (0>= make_addressPrefix(@aor, a, prefixlen )  )then
        Exit(0);
    if sk_IPAddressOrRange_push(aors, aor)>0  then
        Exit(1);
    IPAddressOrRange_free(aor);
    Result := 0;
end;


function X509v3_addr_add_range(addr : PIPAddrBlocks;const afi : uint32; safi : PUInt32; min, max : PByte):integer;
var
  aors, aor : PIPAddressOrRanges;

  length : integer;
begin
    aors := make_prefix_or_range(addr, afi, safi);
    length := length_from_afi(afi);
    if aors = nil then Exit(0);
    if 0>= make_addressRange(&aor, min, max, length)  then
        Exit(0);
    if sk_IPAddressOrRange_push(aors, aor)>0  then
        Exit(1);
    IPAddressOrRange_free(aor);
    Result := 0;
end;


function extract_min_max( aor : PIPAddressOrRange; min, max : PByte; length : integer):integer;
begin
    if (aor = nil)  or  (min = nil)  or  (max = nil) then
       Exit(0);
    case aor.&type of
    IPAddressOrRange_addressPrefix:
        Exit(int((addr_expand(min, aor.u.addressPrefix, length, $00)>0)  and
             (addr_expand(max, aor.u.addressPrefix, length, $FF)>0)) );
    IPAddressOrRange_addressRange:
        Exit(int((addr_expand(min, aor.u.addressRange.min, length, $00)>0)  and
             (addr_expand(max, aor.u.addressRange.max, length, $FF)>0)) );
    end;
    Result := 0;
end;


function X509v3_addr_get_range(aor : PIPAddressOrRange;const afi : uint32; min, max : PByte;const length : integer):integer;
var
  afi_length : integer;
begin
    afi_length := length_from_afi(afi);
    if (aor = nil)  or  (min = nil)  or  (max = nil)  or
       ( afi_length = 0)  or  (length < afi_length)  or
       ( (aor.&type <> IPAddressOrRange_addressPrefix)  and
          (aor.&type <> IPAddressOrRange_addressRange) )  or
       (0>= extract_min_max(aor, min, max, afi_length))  then
        Exit(0);
    Result := afi_length;
end;


function IPAddressFamily_cmp(const a_, b_ : PPIPAddressFamily):integer;
var
  a : PASN1_OCTET_STRING ;
  b : PASN1_OCTET_STRING ;

  len, cmp : integer;
begin
    a := a_^.addressFamily;
    b := b_^.addressFamily;
    len := get_result((a.length <= b.length) , a.length , b.length);
    cmp := memcmp(a.data, b.data, len);
    Result := get_result(cmp >0, cmp , a.length - b.length);
end;


function X509v3_addr_is_canonical( addr : PIPAddrBlocks):integer;
var
  a_min : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  a_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  b_min : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  b_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;

  aors : PIPAddressOrRange;

  i, j, k : integer;

  a : PIPAddressFamily;
  b : PIPAddressFamily;
  f : PIPAddressFamily;

  length : integer;

  a1, b1: PIPAddressOrRange;
begin
   
    {
     * Empty extension is canonical.
     }
    if addr = nil then Exit(1);
    {
     * Check whether the top-level list is in order.
     }
    for i := 0 to sk_IPAddressFamily_num(addr) - 1-1 do
    begin
       a := sk_IPAddressFamily_value(addr, i);
       b := sk_IPAddressFamily_value(addr, i + 1);
        if IPAddressFamily_cmp(@a, @b) >= 0  then
            Exit(0);
    end;
    {
     * Top level's ok, now check each address family.
     }
    for i := 0 to sk_IPAddressFamily_num(addr)-1 do
    begin
        f := sk_IPAddressFamily_value(addr, i);
        length := length_from_afi(X509v3_addr_get_afi(f));
        {
         * Inheritance is canonical.  Anything other than inheritance or
         * a SEQUENCE OF IPAddressOrRange is an ASN.1 error or something.
         }
        if (f = nil)  or  (f.ipAddressChoice = nil) then
           Exit(0);
        case f.ipAddressChoice.&type of
          IPAddressChoice_inherit:
              continue;
          IPAddressChoice_addressesOrRanges:
          begin
            //
          end;
          else
              Exit(0);
        end;
        {
         * It's an IPAddressOrRanges sequence, check it.
         }
        aors := f.ipAddressChoice.u.addressesOrRanges;
        if sk_IPAddressOrRange_num(aors) = 0 then
            Exit(0);
        for j := 0 to sk_IPAddressOrRange_num(aors) - 1-1 do
        begin
            a1 := sk_IPAddressOrRange_value(aors, j);
            b1 := sk_IPAddressOrRange_value(aors, j + 1);
            if  (0>= extract_min_max(a1, @a_min, @a_max, length) )  or
                (0>= extract_min_max(b1, @b_min, @b_max, length) ) then
                Exit(0);
            {
             * Punt misordered list, overlapping start, or inverted range.
             }
            if ( memcmp(@a_min, @b_min, length) >= 0)  or
               ( memcmp(@a_min, @a_max, length) > 0)  or
               ( memcmp(@b_min, @b_max, length) > 0)   then
                Exit(0);
            {
             * Punt if adjacent or overlapping.  Check for adjacency by
             * subtracting one from b_min first.
             }
            k := length - 1;
            while ( k >= 0)  and  (PostDec(b_min[k]) = $00) do
            begin
               if memcmp(@a_max, @b_min, length)>= 0  then
                  Exit(0);
                Dec(k);
            end;

            {
             * Check for range that should be expressed as a prefix.
             }
            if (a1.&type = IPAddressOrRange_addressRange)  and
               ( range_should_be_prefix(@a_min, @a_max, length) >= 0 ) then
                Exit(0);
        end;
        {
         * Check range to see if it's inverted or should be a
         * prefix.
         }
        j := sk_IPAddressOrRange_num(aors) - 1;
        begin
            a1 := sk_IPAddressOrRange_value(aors, j);
            if (a1 <> nil)  and  (a1.&type = IPAddressOrRange_addressRange) then
            begin
                if  0>= extract_min_max(a1, @a_min, @a_max, length) then
                    Exit(0);
                if (memcmp(@a_min, @a_max, length)> 0 ) or
                   (range_should_be_prefix(@a_min, @a_max, length) >= 0)  then
                    Exit(0);
            end;
        end;
    end;
    {
     * If we made it through all that, we're happy.
     }
    Result := 1;
end;


function IPAddressOrRanges_canonize(aors : PIPAddressOrRange;const afi : uint32):integer;
var
  i, j, length : integer;

  a, b : PIPAddressOrRange;

  a_min : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  a_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  b_min : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;
  b_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;

  merged, a1 : PIPAddressOrRange;


begin
    length := length_from_afi(afi);
    {
     * Sort the IPAddressOrRanges sequence.
     }
    sk_IPAddressOrRange_sort(aors);
    {
     * Clean up representation issues, punt on duplicates or overlaps.
     }
    i := 0;
    while  i < sk_IPAddressOrRange_num(aors) - 1 do
    begin
        a := sk_IPAddressOrRange_value(aors, i);
        b := sk_IPAddressOrRange_value(aors, i + 1);

        if  (0>= extract_min_max(a, @a_min, @a_max, length) )  or
            (0>= extract_min_max(b, @b_min, @b_max, length) )then
            Exit(0);
        {
         * Punt inverted ranges.
         }
        if (memcmp(@a_min, @a_max, length) > 0)  or
           (memcmp(@b_min, @b_max, length) > 0) then
            Exit(0);
        {
         * Punt overlaps.
         }
        if memcmp(@a_max, @b_min, length) >= 0    then
            Exit(0);
        {
         * Merge if a and b are adjacent.  We check for
         * adjacency by subtracting one from b_min first.
         }
        j := length - 1;
        while ( j >= 0)  and  (PostDec(b_min[j])= $00) do
            Dec(j);
        if memcmp(@a_max, @b_min, length)= 0 then
        begin
            if  0>= make_addressRange(@merged, @a_min, @b_max, length) then
                Exit(0);
            sk_IPAddressOrRange_set(aors, i, merged);
            sk_IPAddressOrRange_delete(aors, i + 1);
            IPAddressOrRange_free(a);
            IPAddressOrRange_free(b);
            Dec(i);
            continue;
        end;

        Inc(i);
    end;
    {
     * Check for inverted final range.
     }
    j := sk_IPAddressOrRange_num(aors) - 1;
    begin
        a1 := sk_IPAddressOrRange_value(aors, j);
        if (a1 <> nil)  and  (a1.&type = IPAddressOrRange_addressRange) then
        begin
            FillChar(a_min, 0, SizeOf(a_min));
            FillChar(a_max, 0, SizeOf(a_max));
            if  0>= extract_min_max(a, @a_min, @a_max, length ) then
                Exit(0);
            if memcmp(@a_min, @a_max, length) > 0  then
                Exit(0);
        end;
    end;
    Result := 1;
end;


function X509v3_addr_canonize( addr : PIPAddrBlocks):integer;
var
  i : integer;

  f : PIPAddressFamily;
begin
    for i := 0 to sk_IPAddressFamily_num(addr)-1 do
    begin
        f := sk_IPAddressFamily_value(addr, i);
        if (f.ipAddressChoice.&type = IPAddressChoice_addressesOrRanges)  and
           (0>= IPAddressOrRanges_canonize(f.ipAddressChoice.u.addressesOrRanges,
                                        X509v3_addr_get_afi(f)) ) then
            Exit(0);
    end;
    sk_IPAddressFamily_set_cmp_func(addr, IPAddressFamily_cmp);
    sk_IPAddressFamily_sort(addr);
    if  not ossl_assert(Boolean(X509v3_addr_is_canonical(addr))) then
        Exit(0);
    Result := 1;
end;


function v2i_IPAddrBlocks(const method : Pv3_ext_method; ctx : Pv3_ext_ctx; values : PSTACK_st_CONF_VALUE):Pointer;
const
   v4addr_chars: PUTF8Char  = '0123456789.';
   v6addr_chars: PUTF8Char  = '0123456789.:abcdefABCDEF';
var
    addr       : PIPAddrBlocks;
   s,
  t          : PUTF8Char;
  i          : integer;
  val        : PCONF_VALUE;
  min,max   : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;

  afi,
  safi_      : uint32;
  safi       : PUint32;
  addr_chars : PUTF8Char;
  prefixlen,
  i1,
  i2,

  _length     : integer;
  delim      :UTF8Char;
  label err;

begin

    addr := nil;
    s := nil;
    addr := sk_IPAddressFamily_new(IPAddressFamily_cmp );
    if addr = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(values)-1 do
    begin
        val := sk_CONF_VALUE_value(values, i);

        safi := nil;
        addr_chars := nil;
        if  0>= ossl_v3_name_cmp(val.name, 'IPv4') then
        begin
            afi := IANA_AFI_IPV4;
        end
        else
        if ( 0>= ossl_v3_name_cmp(val.name, 'IPv6')) then
        begin
                  afi := IANA_AFI_IPV6;
        end
        else
        if (0>= ossl_v3_name_cmp(val.name, 'IPv4-SAFI')) then
        begin
            afi := IANA_AFI_IPV4;
            safi := @safi_;
        end
        else
        if ( 0>= ossl_v3_name_cmp(val.name, 'IPv6-SAFI')) then
        begin
            afi := IANA_AFI_IPV6;
            safi := @safi_;
        end
        else
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR,
                           Format('%s', [val.name]));
            goto err;
        end;
        case afi of
          IANA_AFI_IPV4:
              addr_chars := v4addr_chars;

          IANA_AFI_IPV6:
              addr_chars := v6addr_chars;

        end;
        _length := length_from_afi(afi);
        {
         * Handle SAFI, if any, and OPENSSL_strdup() so we can null-terminate
         * the other input values.
         }
        if safi <> nil then
        begin
            safi^ := strtoul(val.value, @t, 0);
            t  := t + (strspn(t, ' '#9));
            if (safi^ > $FF)  or  (t  <> ':')then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SAFI);
                X509V3_conf_add_error_name_value(val);
                Inc(t);
                goto err;
            end;
            t  := t + (strspn(t, ' '#9));
            OPENSSL_strdup(s, t);
        end
        else
        begin
            OPENSSL_strdup(s, val.value);
        end;
        if s = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto err;
        end;
        {
         * Check for inheritance.  Not worth additional complexity to
         * optimize this (seldom-used) case.
         }
        if strcmp(s, 'inherit') = 0  then
        begin
            if  0>= X509v3_addr_add_inherit(addr, afi, safi) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_INHERITANCE);
                X509V3_conf_add_error_name_value(val);
                goto err;
            end;
            OPENSSL_free(s);
            s := nil;
            continue;
        end;
        i1 := strspn(s, addr_chars);
        i2 := i1 + strspn(s + i1, ' '#9);
        delim := s[i2];
        Inc(i2);
        s[i1] := #0;
        if ossl_a2i_ipadd(@min, s) <> _length then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_IPADDRESS);
            X509V3_conf_add_error_name_value(val);
            goto err;
        end;
        case delim of
        '/':
        begin
            prefixlen := int(strtoul(s + i2, @t, 10));
            if (t = s + i2)  or  (t^ <> #0) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_add_error_name_value(val);
                goto err;
            end;
            if  0>= X509v3_addr_add_prefix(addr, afi, safi, @min, prefixlen ) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto err;
            end;
        end;
        '-':
        begin
            i1 := i2 + strspn(s + i2, ' '#9);
            i2 := i1 + strspn(s + i1, addr_chars);
            if (i1 = i2)  or  (s[i2] <> #0) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_add_error_name_value(val);
                goto err;
            end;
            if ossl_a2i_ipadd(@max, s + i1) <> _length then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_IPADDRESS);
                X509V3_conf_add_error_name_value(val);
                goto err;
            end;
            if memcmp(@min, @max, length_from_afi(afi)) > 0 then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
                X509V3_conf_add_error_name_value(val);
                goto err;
            end;
            if  0>= X509v3_addr_add_range(addr, afi, safi, @min, @max ) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto err;
            end;
        end;
        #0:
        begin
            if  0>= X509v3_addr_add_prefix(addr, afi, safi, @min, _length * 8) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto err;
            end;
        end;
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
            X509V3_conf_add_error_name_value(val);
            goto err;
        end;
        end;
        OPENSSL_free(s);
        s := nil;
    end;
    {
     * Canonize the result, then we're done.
     }
    if 0>= X509v3_addr_canonize(addr) then
       goto err;
    Exit(addr);
 err:
    OPENSSL_free(s);
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    Result := nil;
end;


function X509v3_addr_inherits( addr : PIPAddrBlocks):integer;
var
  i : integer;
  f : PIPAddressFamily;
begin
    if addr = nil then Exit(0);
    for i := 0 to sk_IPAddressFamily_num(addr)-1 do
    begin
        f := sk_IPAddressFamily_value(addr, i);
        if f.ipAddressChoice.&type = IPAddressChoice_inherit then
           Exit(1);
    end;
    Result := 0;
end;


function addr_contains( parent, child : PIPAddressOrRanges; length : integer):integer;
var
  p_min, p_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;

  c_min, c_max : array[0..(ADDR_RAW_BUF_LEN)-1] of Byte;

  p, c : integer;
begin
   
    if (child = nil)  or  (parent = child) then Exit(1);
    if parent = nil then Exit(0);
    p := 0;
    for c := 0 to sk_IPAddressOrRange_num(child)-1 do
    begin
        if  0>= extract_min_max(sk_IPAddressOrRange_value(child, c),
                             @c_min, @c_max, length)  then
            Exit(-1);
        while True do
        begin
            if p >= sk_IPAddressOrRange_num(parent ) then
                Exit(0);
            if  0>= extract_min_max(sk_IPAddressOrRange_value(parent, p),
                                 @p_min, @p_max, length)  then
                Exit(0);
            if memcmp(@p_max, @c_max, length) < 0   then
                continue;
            if memcmp(@p_min, @c_min, length) > 0  then
                Exit(0);
            break;
            Inc(p);
        end;
    end;
    Result := 1;
end;


function X509v3_addr_subset( a, b : PIPAddrBlocks):integer;
var
  i : integer;

  fa : PIPAddressFamily;

  j : integer;

  fb : PIPAddressFamily;
begin
    if (a = nil ) or  (a = b) then Exit(1);
    if (b = nil)  or  (X509v3_addr_inherits(a)>0)   or  (X509v3_addr_inherits(b)>0)then
        Exit(0);
    sk_IPAddressFamily_set_cmp_func(b, IPAddressFamily_cmp);
    for i := 0 to sk_IPAddressFamily_num(a)-1 do begin
        fa := sk_IPAddressFamily_value(a, i);
        j := sk_IPAddressFamily_find(b, fa);
        fb := sk_IPAddressFamily_value(b, j);
        if fb = nil then Exit(0);
        if  0>= addr_contains(fb.ipAddressChoice.u.addressesOrRanges,
                           fa.ipAddressChoice.u.addressesOrRanges,
                           length_from_afi(X509v3_addr_get_afi(fb)))  then
            Exit(0);
    end;
    Result := 1;
end;


function addr_validate_path_internal( ctx : PX509_STORE_CTX; chain : PSTACK_st_X509; ext : PIPAddrBlocks):integer;
var
  child : PIPAddrBlocks;
  i, j, ret : integer;
  x : PX509;
  fc : PIPAddressFamily;
  k : integer;
  fp : PIPAddressFamily;
  label  done;

  function validation_err(_err_: Integer): Integer;
  begin
      if ctx <> nil then
      begin
        ctx.error := _err_;
        ctx.error_depth := i;
        ctx.current_cert := x;
        ret := ctx.verify_cb(0, ctx);
      end
      else
      begin
        ret := 0;
      end;

      Result := ret;
  end;
begin
    child := nil;
    ret := 1;
    if  (not ossl_assert( (chain <> nil)  and  (sk_X509_num(chain) > 0) ) )   or
        (not ossl_assert( (ctx <> nil)  or  (ext <> nil) ) )       or
        (not ossl_assert( (ctx = nil)  or  (Assigned(ctx.verify_cb) ) )) then
    begin
        if ctx <> nil then
            ctx.error := X509_V_ERR_UNSPECIFIED;
        Exit(0);
    end;
    {
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     }
    if ext <> nil then
    begin
        i := -1;
        x := nil;
    end
    else
    begin
        i := 0;
        x := sk_X509_value(chain, i);
        ext := x.rfc3779_addr;
        if ext = nil then
           goto done;
    end;
    if  0>= X509v3_addr_is_canonical(ext) then
        if 0>=validation_err(X509_V_ERR_INVALID_EXTENSION) then
           goto done;

    sk_IPAddressFamily_set_cmp_func(ext, IPAddressFamily_cmp);
    child := sk_IPAddressFamily_dup(ext);
    if child = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        if ctx <> nil then
           ctx.error := X509_V_ERR_OUT_OF_MEM;
        ret := 0;
        goto done;
    end;
    {
     * Now walk up the chain.  No cert may list resources that its
     * parent doesn't list.
     }
    Inc(i);
    while i < sk_X509_num(chain) do
    begin
        x := sk_X509_value(chain, i);
        if  0>= X509v3_addr_is_canonical(x.rfc3779_addr)  then
           if 0>= validation_err(X509_V_ERR_INVALID_EXTENSION) then
               goto done;
        if x.rfc3779_addr = nil then
        begin
            for j := 0 to sk_IPAddressFamily_num(child)-1 do
            begin
                fc := sk_IPAddressFamily_value(child, j);
                if fc.ipAddressChoice.&type <> IPAddressChoice_inherit then
                begin
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                end;
            end;
            continue;
        end;
        sk_IPAddressFamily_set_cmp_func(x.rfc3779_addr,  IPAddressFamily_cmp);
        for j := 0 to sk_IPAddressFamily_num(child)-1 do
        begin
            fc := sk_IPAddressFamily_value(child, j);
            k := sk_IPAddressFamily_find(x.rfc3779_addr, fc);
            fp := sk_IPAddressFamily_value(x.rfc3779_addr, k);
            if fp = nil then
            begin
                if (fc.ipAddressChoice.&type =
                    IPAddressChoice_addressesOrRanges) then
                begin
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                end;
                continue;
            end;
            if fp.ipAddressChoice.&type = IPAddressChoice_addressesOrRanges then
            begin
                if (fc.ipAddressChoice.&type = IPAddressChoice_inherit)  or
                   (0<= addr_contains(fp.ipAddressChoice.u.addressesOrRanges,
                                     fc.ipAddressChoice.u.addressesOrRanges,
                                     length_from_afi(X509v3_addr_get_afi(fc)))) then
                    sk_IPAddressFamily_set(child, j, fp)
                else
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            end;
        end;
        Inc(i);
    end;
    {
     * Trust anchor can't inherit.
     }
    if x.rfc3779_addr <> nil then
    begin
        for j := 0 to sk_IPAddressFamily_num(x.rfc3779_addr)-1 do
        begin
            fp := sk_IPAddressFamily_value(x.rfc3779_addr, j);
            if (fp.ipAddressChoice.&type = IPAddressChoice_inherit)  and
               ( sk_IPAddressFamily_find(child, fp) >= 0 )  then
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
        end;
    end;
 done:
    sk_IPAddressFamily_free(child);
    Exit(ret);
end;


function X509v3_addr_validate_path( ctx : PX509_STORE_CTX):integer;
begin
    if (ctx.chain = nil)
             or  (sk_X509_num(ctx.chain)  = 0)
             or  (not Assigned(ctx.verify_cb) )then
    begin
        ctx.error := X509_V_ERR_UNSPECIFIED;
        Exit(0);
    end;
    Result := addr_validate_path_internal(ctx, ctx.chain, nil);
end;


function X509v3_addr_validate_resource_set( chain : PSTACK_st_X509; ext : PIPAddrBlocks; allow_inheritance : integer):integer;
begin
    if ext = nil then Exit(1);
    if (chain = nil)  or  (sk_X509_num(chain)= 0) then
        Exit(0);
    if  (0>= allow_inheritance)  and  (0<=X509v3_addr_inherits(ext) ) then
        Exit(0);
    Result := addr_validate_path_internal(nil, chain, ext);
end;

initialization
   IPAddressRange_seq_tt := [
     get_ASN1_TEMPLATE( 0,  0,  size_t(@PIPAddressRange(0). min), ' min' , ASN1_BIT_STRING_it) ,
     get_ASN1_TEMPLATE( 0,  0,  size_t(@PIPAddressRange(0). max), ' max' , ASN1_BIT_STRING_it)
   ] ;

   IPAddressOrRange_ch_tt := [
      get_ASN1_TEMPLATE( 0,  0,  size_t(@PIPAddressOrRange(0). u.addressPrefix), ' u.addressPrefix' , ASN1_BIT_STRING_it) ,
      get_ASN1_TEMPLATE( 0,  0,  size_t(@PIPAddressOrRange(0). u.addressRange), ' u.addressRange' , IPAddressRange_it)
   ] ;

   IPAddressChoice_ch_tt := [
      get_ASN1_TEMPLATE( 0,  0,  size_t(@PIPAddressChoice(0).u.inherit), ' u.inherit' , ASN1_NULL_it) ,
      get_ASN1_TEMPLATE( (($2 shl  1)), 0,  size_t(@PIPAddressChoice(0). u.addressesOrRanges), ' u.addressesOrRanges' , IPAddressOrRange_it)
   ] ;

   IPAddressFamily_seq_tt := [
      get_ASN1_TEMPLATE ( 0,  0,  size_t(@PIPAddressFamily(0). addressFamily), ' addressFamily' , ASN1_OCTET_STRING_it) ,
      get_ASN1_TEMPLATE ( 0,  0,  size_t(@PIPAddressFamily(0). ipAddressChoice), ' ipAddressChoice' , IPAddressChoice_it)
    ] ;

    IPAddrBlocks_item_tt := get_ASN1_TEMPLATE(
       (($2 shl  1)), 0,  0, ' IPAddrBlocks' , IPAddressFamily_it) ;


    ossl_v3_addr := get_V3_EXT_METHOD(
        NID_sbgp_ipAddrBlock,       // nid
        0,                          // flags
        IPAddrBlocks_it, // template
        nil, nil, nil, nil,                 // old functions, ignored
        nil,                          // i2s
        nil,                          // s2i
        nil,                          // i2v
        v2i_IPAddrBlocks,           // v2i
        i2r_IPAddrBlocks,           // i2r
        nil,                          // r2i
        nil                        // extension-specific data
    );
end.
