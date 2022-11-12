unit openssl3.crypto.asn1.asn1_parse;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  ASN1_PARSE_MAXDEPTH = 128;

function ASN1_tag2str( tag : integer):PUTF8Char;

function ASN1_parse_dump(bp : PBIO;const pp : PByte; len : long; indent, dump : integer):integer;
function asn1_print_info( bp : PBIO; offset : long; depth, hl : integer; len : long; tag, xclass, constructed, indent : integer):integer;

function asn1_parse2(bp : PBIO;const pp : PPByte; length : long; offset, depth, indent, dump : integer):integer;

implementation
uses openssl3.crypto.bio.bio_lib, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.a_object, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_dump,
     openssl3.crypto.bio.bio_print, openssl3.crypto.bio.bf_prefix;


function asn1_print_info( bp : PBIO; offset : long; depth, hl : integer; len : long; tag, xclass, constructed, indent : integer):integer;
var
    str          : array[0..127] of UTF8Char;
    pop_f_prefix : integer;
    saved_indent : long;
    i            : integer;
    bio          : PBIO;
    p :PUTF8Char;
    label _err;
begin
    pop_f_prefix := 0;
    saved_indent := -1;
    i := 0;
    bio := nil;
    if (constructed and V_ASN1_CONSTRUCTED) > 0 then
       p := 'cons: '
    else
       p := 'prim: ';
    if constructed <> (V_ASN1_CONSTRUCTED or 1) then
    begin
        if BIO_snprintf(str, sizeof(str) , '%5ld:d=%-2d hl=%ld l=%4ld %s',
                         [offset, depth, long(hl), len, p]) <= 0 then
            goto _err ;
    end
    else
    begin
        if BIO_snprintf(str, sizeof(str) , '%5ld:d=%-2d hl=%ld l=inf  %s',
                         [offset, depth, long(hl), p]) <= 0 then
            goto _err ;
    end;
    if bp <> nil then
    begin
        if BIO_set_prefix(bp, PUTF8Char(@str)) <= 0 then
        begin
            bio := BIO_new(BIO_f_prefix);
            bp := BIO_push(bio, bp);
            if (bio  = nil) or  (bp = nil) then
                goto _err ;
            pop_f_prefix := 1;
        end;
        saved_indent := BIO_get_indent(bp);
        if (BIO_set_prefix(bp, @str) <= 0)  or  (BIO_set_indent(bp, indent) < 0) then
            goto _err ;
    end;
    {
     * BIO_set_prefix made a copy of |str|, so we can safely use it for
     * something else, ASN.1 tag printout.
     }
    p := str;
    if (xclass and V_ASN1_PRIVATE) = V_ASN1_PRIVATE then
        BIO_snprintf(str, sizeof(str), 'priv [ %d ] ', [tag])
    else if ((xclass and V_ASN1_CONTEXT_SPECIFIC) = V_ASN1_CONTEXT_SPECIFIC) then
        BIO_snprintf(str, sizeof(str), 'cont [ %d ]', [tag])
    else if ((xclass and V_ASN1_APPLICATION) = V_ASN1_APPLICATION) then
        BIO_snprintf(str, sizeof(str), 'appl [ %d ]', [tag])
    else if (tag > 30) then
        BIO_snprintf(str, sizeof(str), '<ASN1 %d>', [tag])
    else
        p := ASN1_tag2str(tag);
    i := int(BIO_printf(bp, '%-18s', [p]) > 0);
 _err:
    if saved_indent >= 0 then
       BIO_set_indent(bp, saved_indent);
    if pop_f_prefix > 0 then
       BIO_pop(bp);
    BIO_free(bio);
    Result := i;
end;

function asn1_parse2(bp : PBIO;const pp : PPByte; length : long; offset, depth, indent, dump : integer):integer;
var
  p,
  ep,
  tot,
  op          : PByte;
  opp         : PByte;
  len         : long;
  tag,
  xclass,
  ret,
  nl,
  hl,
  j,
  r           : integer;

  o           : PASN1_OBJECT;
  os          : PASN1_OCTET_STRING;
  ai          : PASN1_INTEGER;
  ae          : PASN1_ENUMERATED;

  dump_indent,
  dump_cont   : integer;
  sp          : PByte;
  tmp1        : long;
  printable,
  i           : integer;
  tmp2        : PByte;
  label _end;
begin
    ret := 0;
    o := nil;
    os := nil;
    ai := nil;
    ae := nil;
    { ASN1_BMPSTRING *bmp=nil; }
    dump_cont := 0;
    if depth > ASN1_PARSE_MAXDEPTH then
    begin
        BIO_puts(bp, 'BAD RECURSION DEPTH\n');
        Exit(0);
    end;
    dump_indent := 6;            { Because we know BIO_dump_indent() }
    p := pp^;
    tot := p + length;
    while length > 0 do
    begin
        op := p;
        j := ASN1_get_object(@p, @len, @tag, @xclass, length);
        if (j and $80) > 0 then
        begin
            BIO_puts(bp, 'Error in encoding\n');
            goto _end ;
        end;
        hl := (p - op);
        length  := length - hl;
        {
         * if j = $21 it is a constructed indefinite length object
         }
        if 0>= asn1_print_info(bp, long(offset) + long(op - pp^), depth,
                             hl, len, tag, xclass, j, get_result(indent>0 , depth , 0)) then
            goto _end ;
        if (j and V_ASN1_CONSTRUCTED) > 0 then
        begin
           sp := p;
            ep := p + len;
            if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
                goto _end ;
            if len > length then
            begin
                BIO_printf(bp, 'length is greater than %ld\n', [length]);
                goto _end ;
            end;
            if (j = $21)  and  (len = 0) then
            begin
                while true do
                begin
                    r := asn1_parse2(bp, @p, long(tot - p),
                                    offset + (p - pp^), depth + 1,
                                    indent, dump);
                    if r = 0 then
                       goto _end ;
                    if (r = 2)  or  (p >= tot) then
                    begin
                        len := p - sp;
                        break;
                    end;
                end;
            end
            else
            begin
                tmp1 := len;
                while p < ep do
                begin
                    sp := p;
                    r := asn1_parse2(bp, @p, tmp1,
                                    offset + (p - pp^), depth + 1,
                                    indent, dump);
                    if r = 0 then
                       goto _end ;
                    tmp1  := tmp1 - (p - sp);
                end;
            end;
        end
        else
        if (xclass <> 0) then
        begin
            p  := p + len;
            if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
                goto _end ;
        end
        else
        begin
            nl := 0;
            if (tag = V_ASN1_PRINTABLESTRING )  or
                (tag = V_ASN1_T61STRING)  or
                (tag = V_ASN1_IA5STRING)  or
                (tag = V_ASN1_VISIBLESTRING)  or
                (tag = V_ASN1_NUMERICSTRING)  or
                (tag = V_ASN1_UTF8STRING)  or
                (tag = V_ASN1_UTCTIME)  or  (tag = V_ASN1_GENERALIZEDTIME) then
            begin
                if BIO_write(bp, PUTF8Char(':'), 1) <= 0 then
                    goto _end ;
                if (len > 0)  and  (BIO_write(bp, PUTF8Char(p), int(len))
                    <> int(len))  then
                    goto _end ;
            end
            else
            if (tag = V_ASN1_OBJECT) then
            begin
                opp := op;
                if d2i_ASN1_OBJECT(@o, @opp, len + hl) <> nil  then
                begin
                    if BIO_write(bp, PUTF8Char(':'), 1) <= 0 then
                        goto _end ;
                    i2a_ASN1_OBJECT(bp, o);
                end
                else
                begin
                    if BIO_puts(bp, ':BAD OBJECT') <= 0  then
                        goto _end ;
                    dump_cont := 1;
                end;
            end
            else
            if (tag = V_ASN1_BOOLEAN) then
            begin
                if len <> 1 then
                begin
                    if BIO_puts(bp, ':BAD BOOLEAN') <= 0 then
                        goto _end ;
                    dump_cont := 1;
                end;
                if len > 0 then
                   BIO_printf(bp, ':%u', [p[0]]);
            end
            else
            if (tag = V_ASN1_BMPSTRING) then
            begin
                { do the BMP thang }
            end
            else
            if (tag = V_ASN1_OCTET_STRING)then
            begin
                printable := 1;
                opp := op;
                os := d2i_ASN1_OCTET_STRING(nil, @opp, len + hl);
                if (os <> nil)  and  (os.length > 0) then
                begin
                    opp := os.data;
                    {
                     * testing whether the octet string is printable
                     }
                    for i := 0 to os.length-1 do
                    begin
                        if (opp[i] < Ord(' '))  and
                             (opp[i] <> Ord(#10))  and
                             (opp[i] <> Ord(#13))  and
                             (opp[i] <> Ord(#9))  or  (opp[i] > Ord('~')) then
                        begin
                            printable := 0;
                            break;
                        end;
                    end;
                    if printable > 0 then { printable string }
                    begin
                        if BIO_write(bp, PUTF8Char(':'), 1) <= 0 then
                            goto _end ;
                        if BIO_write(bp, PUTF8Char(opp), os.length) <= 0 then
                            goto _end ;
                    end
                    else
                    if (0>= dump) then
                        {
                         * not printable => print octet string as hex dump
                         }
                    begin
                        if BIO_write(bp, PUTF8Char('[HEX DUMP]:'), 11) <= 0  then
                            goto _end ;
                        for i := 0 to os.length-1 do
                        begin
                            if BIO_printf(bp, '%02X', [opp[i]]) <= 0  then
                                goto _end ;
                        end;
                    end
                    else
                        { print the normal dump }
                    begin
                        if 0>= nl then
                        begin
                            if BIO_write(bp, PUTF8Char(#10), 1) <= 0 then
                                goto _end ;
                        end;
                        if BIO_dump_indent(bp,
                                            PUTF8Char(opp),
                            get_result( (dump = -1)  or  (dump >os.length) , os.length , dump),
                                            dump_indent) <= 0 then
                            goto _end ;
                        nl := 1;
                    end;
                end;
                ASN1_OCTET_STRING_free(os);
                os := nil;
            end
            else
            if (tag = V_ASN1_INTEGER) then
            begin
                opp := op;
                ai := d2i_ASN1_INTEGER(nil, @opp, len + hl);
                if ai <> nil then
                begin
                    if BIO_write(bp, PUTF8Char(':'), 1) <= 0 then
                        goto _end ;
                    if ai.&type = V_ASN1_NEG_INTEGER then
                       if (BIO_write(bp, PUTF8Char('-'), 1) <= 0) then
                            goto _end ;
                    for i := 0 to ai.length-1 do
                    begin
                        if BIO_printf(bp, '%02X', [ai.data[i]]) <= 0  then
                            goto _end ;
                    end;
                    if ai.length = 0 then
                    begin
                        if BIO_write(bp, PUTF8Char('00'), 2) <= 0 then
                            goto _end ;
                    end;
                end
                else
                begin
                    if BIO_puts(bp, ':BAD INTEGER') <= 0  then
                        goto _end ;
                    dump_cont := 1;
                end;
                ASN1_INTEGER_free(ai);
                ai := nil;
            end
            else
            if (tag = V_ASN1_ENUMERATED) then
            begin
                opp := op;
                ae := d2i_ASN1_ENUMERATED(nil, @opp, len + hl);
                if ae <> nil then
                begin
                    if BIO_write(bp, PUTF8Char(':'), 1) <= 0 then
                        goto _end ;
                    if ae.&type = V_ASN1_NEG_ENUMERATED then
                       if (BIO_write(bp, PUTF8Char('-'), 1) <= 0) then
                            goto _end ;
                    for i := 0 to ae.length-1 do
                    begin
                        if BIO_printf(bp, '%02X', [ae.data[i]]) <= 0  then
                            goto _end ;
                    end;
                    if ae.length = 0 then
                    begin
                        if BIO_write(bp, PUTF8Char('00'), 2) <= 0 then
                           goto _end ;
                    end;
                end
                else
                begin
                    if BIO_puts(bp, PUTF8Char(':BAD ENUMERATED')) <= 0  then
                        goto _end ;
                    dump_cont := 1;
                end;
                ASN1_ENUMERATED_free(ae);
                ae := nil;
            end
            else
            if (len > 0)  and  (dump > 0) then
            begin
                if 0>= nl then
                begin
                    if BIO_write(bp, PUTF8Char(#10), 1) <= 0 then
                        goto _end ;
                end;
                if BIO_dump_indent(bp,  PUTF8Char(p),
                               get_result((dump = -1)  or  (dump > len) , len , dump),
                                    dump_indent) <= 0 then
                    goto _end ;
                nl := 1;
            end;
            if dump_cont >0 then
            begin
                tmp2 := op + hl;
                if BIO_puts(bp, ':[' ) <= 0 then
                    goto _end ;
                for i := 0 to len-1 do
                begin
                    if BIO_printf(bp, '%02X', [tmp2[i]]) <= 0  then
                        goto _end ;
                end;
                if BIO_puts(bp, ']') <= 0  then
                    goto _end ;
                dump_cont := 0;
            end;
            if 0>= nl then
            begin
                if BIO_write(bp, PUTF8Char(#10), 1) <= 0 then
                    goto _end ;
            end;
            p  := p + len;
            if (tag = V_ASN1_EOC)  and  (xclass = 0) then
            begin
                ret := 2;        { End of sequence }
                goto _end ;
            end;
        end;
        length  := length - len;
    end;
    ret := 1;
 _end:
    ASN1_OBJECT_free(o);
    ASN1_OCTET_STRING_free(os);
    ASN1_INTEGER_free(ai);
    ASN1_ENUMERATED_free(ae);
    pp^ := p;
    Result := ret;
end;



function ASN1_parse_dump(bp : PBIO;const pp : PByte; len : long; indent, dump : integer):integer;
begin
    Result := asn1_parse2(bp, @pp, len, 0, 0, indent, dump);
end;


function ASN1_tag2str( tag : integer):PUTF8Char;
const // 1d arrays
  tag2str : array[0..30] of PUTF8Char = (
    {0-4}'EOC', 'BOOLEAN', 'INTEGER', 'BITSTRING', 'OCTETSTRING',
    {5-9}'NULL', 'OBJECT', 'OBJECTDESCRIPTOR', 'EXTERNAL', 'REAL',
    {10-13}'ENUMERATED', '<ASN111>', 'UTF8STRING', '<ASN113>',
    {15-17}'<ASN114>', '<ASN115>', 'SEQUENCE', 'SET',
    {18-20}'NUMERICSTRING', 'PRINTABLESTRING', 'T61STRING',
    {21-24}'VIDEOTEXSTRING', 'IA5STRING', 'UTCTIME', 'GENERALIZEDTIME',
    {25-27}'GRAPHICSTRING', 'VISIBLESTRING', 'GENERALSTRING',
    {28-30}'UNIVERSALSTRING', '<ASN129>', 'BMPSTRING' );

begin
    if (tag = V_ASN1_NEG_INTEGER )  or  (tag = V_ASN1_NEG_ENUMERATED) then
        tag := tag and not $100;
    if (tag < 0)  or  (tag > 30) then
       Exit('(unknown)');
    Result := tag2str[tag];
end;


end.
