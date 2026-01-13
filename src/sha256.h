
#pragma once

#include <iosfwd>

#include "types.h"

constexpr const u64 SHA256_HASH_BYTES = 32;

struct Sha256Hash
{
	char value[ SHA256_HASH_BYTES ];
};

Sha256Hash sha256( const u8 *data, u64 size );

inline Sha256Hash sha256( const char *data, u64 size )
{
	return sha256( reinterpret_cast<const u8*>( data ), size );
}

Sha256Hash sha256( const char *filepath, i32 *errorCode = nullptr );

std::ostream & operator << ( std::ostream &out, const Sha256Hash &hash );