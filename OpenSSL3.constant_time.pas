unit OpenSSL3.constant_time;

interface
uses OpenSSL.Api;

function constant_time_eq_int( a, b : integer):uint32;
function constant_time_eq( a, b : uint32):uint32;
function constant_time_is_zero( a : uint32):uint32;
function constant_time_msb( a : uint32):uint32;

function constant_time_is_zero_8( a : uint32):Byte;

function constant_time_select_8( mask, a, b : Byte):Byte;

function constant_time_select( mask, a, b : uint32):integer;

implementation





















end.
