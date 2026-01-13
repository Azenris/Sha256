
#include <iostream>
#include <filesystem>
#include <fstream>

#include "sha256.h"

static inline u32 sr( u32 data, i32 shift )
{
	return ( data >> shift );
}

static inline u32 rr( u32 data, i32 rotates )
{
	return ( data >> rotates ) | ( data << ( 32 - rotates ) );
}

static inline u32 sigma0( u32 data )
{
	return rr( data, 7 ) ^ rr( data, 18 ) ^ sr( data, 3 );
}

static inline u32 sigma1( u32 data )
{
	return rr( data, 17 ) ^ rr( data, 19 ) ^ sr( data, 10 );
}

static inline u32 usigma0( u32 data )
{
	return rr( data, 2 ) ^ rr( data, 13 ) ^ rr( data, 22 );
}

static inline u32 usigma1( u32 data )
{
	return rr( data, 6 ) ^ rr( data, 11 ) ^ rr( data, 25 );
}

static inline u32 choice( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( ~data0 & data2 );
}

static inline u32 majority( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( data0 & data2 ) ^ ( data1 & data2 );
}

// cube root of the first 64 prime numbers
constexpr const u32 Sha256Constants[ 64 ] =
{
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
};

struct Sha256Context
{
	const u8 *data;
	u32 a;
	u32 b;
	u32 c;
	u32 d;
	u32 e;
	u32 f;
	u32 g;
	u32 h;
};

static Sha256Hash sha256_create_hash( Sha256Context *context )
{
	Sha256Hash hash;
	hash.value[  0 ] = ( context->a >> 24 ) & 0xFF;
	hash.value[  1 ] = ( context->a >> 16 ) & 0xFF;
	hash.value[  2 ] = ( context->a >>  8 ) & 0xFF;
	hash.value[  3 ] = ( context->a >>  0 ) & 0xFF;
	hash.value[  4 ] = ( context->b >> 24 ) & 0xFF;
	hash.value[  5 ] = ( context->b >> 16 ) & 0xFF;
	hash.value[  6 ] = ( context->b >>  8 ) & 0xFF;
	hash.value[  7 ] = ( context->b >>  0 ) & 0xFF;
	hash.value[  8 ] = ( context->c >> 24 ) & 0xFF;
	hash.value[  9 ] = ( context->c >> 16 ) & 0xFF;
	hash.value[ 10 ] = ( context->c >>  8 ) & 0xFF;
	hash.value[ 11 ] = ( context->c >>  0 ) & 0xFF;
	hash.value[ 12 ] = ( context->d >> 24 ) & 0xFF;
	hash.value[ 13 ] = ( context->d >> 16 ) & 0xFF;
	hash.value[ 14 ] = ( context->d >>  8 ) & 0xFF;
	hash.value[ 15 ] = ( context->d >>  0 ) & 0xFF;
	hash.value[ 16 ] = ( context->e >> 24 ) & 0xFF;
	hash.value[ 17 ] = ( context->e >> 16 ) & 0xFF;
	hash.value[ 18 ] = ( context->e >>  8 ) & 0xFF;
	hash.value[ 19 ] = ( context->e >>  0 ) & 0xFF;
	hash.value[ 20 ] = ( context->f >> 24 ) & 0xFF;
	hash.value[ 21 ] = ( context->f >> 16 ) & 0xFF;
	hash.value[ 22 ] = ( context->f >>  8 ) & 0xFF;
	hash.value[ 23 ] = ( context->f >>  0 ) & 0xFF;
	hash.value[ 24 ] = ( context->g >> 24 ) & 0xFF;
	hash.value[ 25 ] = ( context->g >> 16 ) & 0xFF;
	hash.value[ 26 ] = ( context->g >>  8 ) & 0xFF;
	hash.value[ 27 ] = ( context->g >>  0 ) & 0xFF;
	hash.value[ 28 ] = ( context->h >> 24 ) & 0xFF;
	hash.value[ 29 ] = ( context->h >> 16 ) & 0xFF;
	hash.value[ 30 ] = ( context->h >>  8 ) & 0xFF;
	hash.value[ 31 ] = ( context->h >>  0 ) & 0xFF;
	return hash;
}

static void sha256_process_block( Sha256Context *context )
{
	u32 words[ 64 ];

	const u8 *data = context->data;

	// -- message schedule ---
	for ( i32 w = 0; w < 16; ++w )
	{
		u32 d0 = *data++;
		u32 d1 = *data++;
		u32 d2 = *data++;
		u32 d3 = *data++;

		words[ w ] = ( d0 << 24 ) | ( d1 << 16 ) | ( d2 << 8 ) | d3;
	}

	for ( i32 w = 16; w < 64; ++w )
	{
		words[ w ] = sigma1( words[ w - 2 ] ) + words[ w - 7 ] + sigma0( words[ w - 15 ] ) + words[ w - 16 ];
	}

	// -- compression --
	u32 a = context->a;
	u32 b = context->b;
	u32 c = context->c;
	u32 d = context->d;
	u32 e = context->e;
	u32 f = context->f;
	u32 g = context->g;
	u32 h = context->h;

	for ( i32 w = 0; w < 64; ++w )
	{
		u32 t0 = words[ w ] + Sha256Constants[ w ] + usigma1( e ) + choice( e, f, g ) + h;
		u32 t1 = usigma0( a ) + majority( a, b, c );

		h = g;
		g = f;
		f = e;
		e = d + t0;
		d = c;
		c = b;
		b = a;
		a = t0 + t1;
	}

	context->a += a;
	context->b += b;
	context->c += c;
	context->d += d;
	context->e += e;
	context->f += f;
	context->g += g;
	context->h += h;
}

Sha256Hash sha256( const u8 *data, u64 size )
{
	Sha256Context context =
	{
		.a = 0x6a09e667,
		.b = 0xbb67ae85,
		.c = 0x3c6ef372,
		.d = 0xa54ff53a,
		.e = 0x510e527f,
		.f = 0x9b05688c,
		.g = 0x1f83d9ab,
		.h = 0x5be0cd19,
	};

	// -- full blocks --
	for ( u64 blockIdx = 0, blockCount = size / 64; blockIdx < blockCount; ++blockIdx )
	{
		context.data = data;
		sha256_process_block( &context );
		data += 64;
	}

	// -- final blocks --
	u8 finalBlocks[ 64 * 2 ];
	u64 finalBlockSize = size & 63;
	memcpy( finalBlocks, data, finalBlockSize );

	finalBlocks[ finalBlockSize++ ] = 0b10000000;

	// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
	u64 padding = 64 - ( ( size + 1 + 8 ) & 63 );
	memset( &finalBlocks[ finalBlockSize ], 0, padding );
	finalBlockSize += padding;

	// -- length of message (big endian) --
	u64 bits = size * 8;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 56 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 48 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 40 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 32 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 24 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 16 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >>  8 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >>  0 ) & 0xFF;

	context.data = finalBlocks;
	sha256_process_block( &context );

	if ( finalBlockSize > 64 )
	{
		context.data = finalBlocks + 64;
		sha256_process_block( &context );
	}

	// -- output --
	return sha256_create_hash( &context );
}

Sha256Hash sha256( const char *filepath, i32 *errorCode )
{
	if ( errorCode )
		*errorCode = 0;

	if ( !std::filesystem::is_regular_file( filepath ) )
	{
		if ( errorCode )
			*errorCode = 2;
		return {};
	}

	std::ifstream file( filepath, std::ios::binary );
	if ( !file )
	{
		if ( errorCode )
			*errorCode = 3;
		return {};
	}

	u8 buffer[ 64 * 2 ];
	u64 totalBytes = 0;

	Sha256Context context =
	{
		.data = buffer,
		.a = 0x6a09e667,
		.b = 0xbb67ae85,
		.c = 0x3c6ef372,
		.d = 0xa54ff53a,
		.e = 0x510e527f,
		.f = 0x9b05688c,
		.g = 0x1f83d9ab,
		.h = 0x5be0cd19,
	};

	while ( file.read( (char *)buffer, 64 ) || file.gcount() >= 0 )
	{
		std::streamsize bytesRead = file.gcount();

		if ( bytesRead == 64 )
		{
			// -- full blocks --
			sha256_process_block( &context );
			totalBytes += bytesRead;
		}
		else
		{
			// -- final blocks --
			totalBytes += bytesRead;

			buffer[ bytesRead++ ] = 0b10000000;

			// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
			u64 padding = 64 - ( ( totalBytes + 1 + 8 ) & 63 );
			memset( &buffer[ bytesRead ], 0, padding );
			bytesRead += padding;

			// -- length of message (big endian) --
			u64 bits = totalBytes * 8;
			buffer[ bytesRead++ ] = ( bits >> 56 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 48 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 40 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 32 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 24 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 16 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >>  8 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >>  0 ) & 0xFF;

			sha256_process_block( &context );

			if ( bytesRead > 64 )
			{
				context.data = buffer + 64;
				sha256_process_block( &context );
			}

			break;
		}
	}

	// -- output --
	return sha256_create_hash( &context );
}

std::ostream & operator << ( std::ostream &out, const Sha256Hash &hash )
{
	constexpr char hex[] = "0123456789abcdef";
	for ( i32 i = 0; i < SHA256_HASH_BYTES; ++i )
	{
		u8 v = hash.value[ i ];
		out << hex[ ( v >> 4 ) & 15 ] << hex[ v & 15 ];
	}
	return out;
}