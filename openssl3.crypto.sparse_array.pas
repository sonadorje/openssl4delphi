unit openssl3.crypto.sparse_array;

interface
uses OpenSSL.Api;

type
  Tsparse_array_leaf_func1 = procedure(p1: ossl_uintmax_t; p2: Pointer);
  Tsparse_array_leaf_func2 = procedure(p1: ossl_uintmax_t; p2, p3: Pointer);
  Tsparse_array_node_func = procedure(p: PPointer);
  trampoline_st = record
    func: Tsparse_array_leaf_func1;
  end;
  Ptrampoline_st = ^trampoline_st;

const
   OPENSSL_SA_BLOCK_BITS = 12;
   SA_BLOCK_MAX = (1 shl OPENSSL_SA_BLOCK_BITS);
   SA_BLOCK_MASK = (SA_BLOCK_MAX-1);
   SA_BLOCK_MAX_LEVELS = ( (  int(sizeof ( ossl_uintmax_t )) * 8 + OPENSSL_SA_BLOCK_BITS - 1 ) div OPENSSL_SA_BLOCK_BITS );

function ossl_sa_new():POPENSSL_SA;
procedure ossl_sa_free( sa : POPENSSL_SA);
procedure sa_doall(const sa : POPENSSL_SA; node_func : Tsparse_array_node_func; leaf_func : Tsparse_array_leaf_func2; arg : Pointer);
procedure sa_free_node( p : PPointer);
procedure ossl_sa_free_leaves( sa : POPENSSL_SA);
procedure sa_free_leaf( n : ossl_uintmax_t; p, arg : Pointer);
function ossl_sa_num(const sa : POPENSSL_SA):size_t;
procedure ossl_sa_doall(const sa : POPENSSL_SA; leaf : Tsparse_array_leaf_func1);
procedure trampoline( n : ossl_uintmax_t; l, arg : Pointer);
procedure ossl_sa_doall_arg(const sa : POPENSSL_SA; leaf : Tsparse_array_leaf_func2; arg : Pointer);
function ossl_sa_get(const sa : POPENSSL_SA; n : ossl_uintmax_t):Pointer;
function ossl_sa_set( sa : POPENSSL_SA; posn : ossl_uintmax_t; val : Pointer):integer;
function alloc_node: PPointer;

implementation

uses
openssl3.crypto.mem;


function alloc_node: PPointer;
begin
    Result := OPENSSL_zalloc(SA_BLOCK_MAX * sizeof(Pointer ));
    //SetLength(Result, SA_BLOCK_MAX)
end;

function ossl_sa_set( sa : POPENSSL_SA; posn : ossl_uintmax_t; val : Pointer):integer;
var
  i, level : integer;
  n : ossl_uintmax_t;
  p : PPointer;
begin
{$POINTERMATH ON}
    level := 1;
    n := posn;
    if sa = nil then Exit(0);
    for level := 1 to SA_BLOCK_MAX_LEVELS-1 do
    begin
        n  := n shr  OPENSSL_SA_BLOCK_BITS;
        if n = 0 then
            break;
    end;

    while sa.levels < level do
    begin
        p := alloc_node();
        if p = nil then Exit(0);
        p[0] := sa.nodes;
        sa.nodes := p;
        Inc(sa.levels);
    end;
    if sa.top < posn then
       sa.top := posn;
    p := sa.nodes;
    level := sa.levels - 1;
    while ( level > 0) do
    begin
        i := (posn  shr  (OPENSSL_SA_BLOCK_BITS * level)) and SA_BLOCK_MASK;

        if p[i] = nil then
        begin
           p[i] := alloc_node();
           if (p[i] = nil)   then
              Exit(0);
        end;
        p := p[i];
        Dec(level);
    end;

    p  := p + (posn and SA_BLOCK_MASK);
    if (val = nil)  and  (p^ <> nil) then
       Dec(sa.nelem)
    else
    if (val <> nil)  and  (p^ = nil) then
        Inc(sa.nelem);
    p^ := val;
    Result := 1;
{$POINTERMATH ON}
end;

function ossl_sa_get(const sa : POPENSSL_SA; n : ossl_uintmax_t):Pointer;
var
  level, idx: integer;
  p : PPointer;
begin
{$POINTERMATH ON}
    Result := nil;
    if (sa = nil)  or  (sa.nelem = 0) then
        Exit(nil);
    if n <= sa.top then
    begin
        p := sa.nodes;
        level := sa.levels - 1;
        while ( p <> nil)  and  (level > 0)do
        begin
            idx := (n  shr (OPENSSL_SA_BLOCK_BITS * level)) and SA_BLOCK_MASK;
            p := PPointer(p[idx]);
            Dec(level);
        end;
        if p = nil then
           Result := nil
        else
           Result := p[n and SA_BLOCK_MASK];

    end;

{$POINTERMATH OFF}
end;

procedure ossl_sa_doall_arg(const sa : POPENSSL_SA; leaf : Tsparse_array_leaf_func2; arg : Pointer);
begin
    if sa <> nil then
       sa_doall(sa, nil, leaf, arg);
end;

procedure trampoline( n : ossl_uintmax_t; l, arg : Pointer);
begin
    Ptrampoline_st(arg).func(n, l);
end;

function ossl_sa_num(const sa : POPENSSL_SA):size_t;
begin
    Result := get_result(sa = nil , 0 , sa.nelem);
end;

//void ossl_sa_doall(const OPENSSL_SA *sa, void (*leaf)(ossl_uintmax_t, void *))
procedure ossl_sa_doall(const sa : POPENSSL_SA; leaf : Tsparse_array_leaf_func1);
var
  tramp : trampoline_st;
begin
    tramp.func := leaf;
    if sa <> nil then
       sa_doall(sa, nil, @trampoline, @tramp);
end;


procedure sa_free_leaf( n : ossl_uintmax_t; p, arg : Pointer);
begin
    OPENSSL_free(p);
end;

procedure ossl_sa_free_leaves( sa : POPENSSL_SA);
begin
    sa_doall(sa, &sa_free_node, @sa_free_leaf, nil);
    OPENSSL_free(sa);
end;

procedure sa_free_node( p :PPointer);
begin
    OPENSSL_free(p);
end;


procedure sa_doall(const sa : POPENSSL_SA; node_func : Tsparse_array_node_func; leaf_func : Tsparse_array_leaf_func2; arg : Pointer);
var
  i     :array[0..(SA_BLOCK_MAX_LEVELS)-1] of integer;
  p     :PPointer;
  nodes :array[0..(SA_BLOCK_MAX_LEVELS)-1] of Pointer;
  idx   :ossl_uintmax_t;
  l, n  :integer;
begin
{$POINTERMATH ON}
    idx := 0;
    l := 0;
    i[0] := 0;
    nodes[0] := sa.nodes;
    while l >= 0 do
    begin
        n := i[l];
        p := nodes[l]; // 当l=0时，p指向sa.nodes
        if n >= SA_BLOCK_MAX then
        begin
            if (p <> nil)  and  (Assigned(node_func) )then
                node_func(p);
            Dec(l);
            idx := idx  shr OPENSSL_SA_BLOCK_BITS;
        end
        else
        begin
            i[l] := n + 1;
            if (p <> nil)  and ( p[n] <> nil) then
            begin
                idx := (idx and not SA_BLOCK_MASK) or n;
                if l < sa.levels - 1 then
                begin
                    i[PreInc(l)] := 0;
                    nodes[l] := p[n];
                    idx := idx shl OPENSSL_SA_BLOCK_BITS;
                end
                else
                if Assigned(leaf_func) then
                begin
                    leaf_func(idx, p[n], arg);
                end;
            end;
        end;
    end;
{$POINTERMATH OFF}
end;



procedure ossl_sa_free( sa : POPENSSL_SA);
begin
    sa_doall(sa, sa_free_node, nil, nil);
    OPENSSL_free(sa);
end;


function ossl_sa_new:POPENSSL_SA;
begin
   Result := OPENSSL_zalloc(sizeof(TOPENSSL_SA));
end;


end.
