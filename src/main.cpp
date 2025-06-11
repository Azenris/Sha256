
// System Includes
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>

// Includes
#include "types.h"

static inline u32 sr( u32 data, i32 shift )
{
	return ( data >> shift );
}

static inline u32 sl( u32 data, i32 shift )
{
	return ( data << shift );
}

static inline u32 rr( u32 data, i32 rotates )
{
	return ( data >> rotates ) | ( data << ( 32 - rotates ) );
}

static inline u32 rl( u32 data, i32 rotates )
{
	return ( data << rotates ) | ( data >> ( 32 - rotates ) );
}

static inline u32 xor_3word( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 ^ data1 ) ^ data2;
}

static inline u32 sigma0( u32 data )
{
	return rr( data, 7 ) ^ rr( data, 18 ) ^ sr( data, 3 );
};

static inline u32 sigma1( u32 data )
{
	return rr( data, 17 ) ^ rr( data, 19 ) ^ sr( data, 10 );
};

static inline u32 usigma0( u32 data )
{
	return rr( data, 2 ) ^ rr( data, 13 ) ^ rr( data, 22 );
};

static inline u32 usigma1( u32 data )
{
	return rr( data, 6 ) ^ rr( data, 11 ) ^ rr( data, 25 );
};

static inline u32 choice( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( ~data0 & data2 );
};

static inline u32 majority( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( data0 & data2 ) ^ ( data1 & data2 );
};

// cube root of the first 64 prime numbers
constexpr const u32 constants[ 64 ] =
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

enum RESULT_CODE
{
	RESULT_CODE_SUCCESS,
	RESULT_CODE_MISSING_ARGUMENTS,
	RESULT_CODE_NOT_A_FILE,
	RESULT_CODE_FAILED_TO_OPEN_FILE,
};

constexpr const u64 SHA256_HASH_BYTES = 32;

struct Sha256Hash
{
	char value[ SHA256_HASH_BYTES ];
};

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

Sha256Hash sha256( const char *dataIn, u64 size )
{
	// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
	u64 padding = 64 - ( ( size + 1 + 8 ) & 63 );

	std::vector<u8> data;
	data.reserve( size + 1 + 8 + padding );
	data.assign( dataIn, dataIn + size );

	// -- padding --
	data.push_back( 0b10000000 );
	data.resize( data.size() + padding );

	// -- length of message (big endian) --
	u64 bits = size * 8;
	data.push_back( ( bits >> 54 ) & 0xFF );
	data.push_back( ( bits >> 48 ) & 0xFF );
	data.push_back( ( bits >> 40 ) & 0xFF );
	data.push_back( ( bits >> 32 ) & 0xFF );
	data.push_back( ( bits >> 24 ) & 0xFF );
	data.push_back( ( bits >> 16 ) & 0xFF );
	data.push_back( ( bits >>  8 ) & 0xFF );
	data.push_back( ( bits >>  0 ) & 0xFF );

	u32 a = 0x6a09e667;
	u32 b = 0xbb67ae85;
	u32 c = 0x3c6ef372;
	u32 d = 0xa54ff53a;
	u32 e = 0x510e527f;
	u32 f = 0x9b05688c;
	u32 g = 0x1f83d9ab;
	u32 h = 0x5be0cd19;

	u8 *dataByte = data.data();
	u32 words[ 64 ];

	for ( u64 blockIdx = 0, blockCount = ( data.size() / 64 ); blockIdx < blockCount; ++blockIdx )
	{
		// -- message schedule ---
		u32 *word = words;

		for ( i32 w = 0; w < 16; ++w )
		{
			u32 d0 = *dataByte++;
			u32 d1 = *dataByte++;
			u32 d2 = *dataByte++;
			u32 d3 = *dataByte++;

			*word++ = ( d0 << 24 ) | ( d1 << 16 ) | ( d2 << 8 ) | d3;
		}

		for ( i32 w = 16; w < 64; ++w )
		{
			*word++ = sigma1( word[ -2 ] ) + word[ -7 ] + sigma0( word[ -15 ] ) + word[ -16 ];
		}

		// -- compression --
		u32 h0 = a;
		u32 h1 = b;
		u32 h2 = c;
		u32 h3 = d;
		u32 h4 = e;
		u32 h5 = f;
		u32 h6 = g;
		u32 h7 = h;

		word = words;
		const u32 *k = constants;

		for ( i32 w = 0; w < 64; ++w )
		{
			u32 t0 = *word++ + *k++ + usigma1( e ) + choice( e, f, g ) + h;
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

		a += h0;
		b += h1;
		c += h2;
		d += h3;
		e += h4;
		f += h5;
		g += h6;
		h += h7;
	}

	// -- output --
	Sha256Hash hash;
	hash.value[  0 ] = ( a >> 24 ) & 0xFF;
	hash.value[  1 ] = ( a >> 16 ) & 0xFF;
	hash.value[  2 ] = ( a >>  8 ) & 0xFF;
	hash.value[  3 ] = ( a >>  0 ) & 0xFF;
	hash.value[  4 ] = ( b >> 24 ) & 0xFF;
	hash.value[  5 ] = ( b >> 16 ) & 0xFF;
	hash.value[  6 ] = ( b >>  8 ) & 0xFF;
	hash.value[  7 ] = ( b >>  0 ) & 0xFF;
	hash.value[  8 ] = ( c >> 24 ) & 0xFF;
	hash.value[  9 ] = ( c >> 16 ) & 0xFF;
	hash.value[ 10 ] = ( c >>  8 ) & 0xFF;
	hash.value[ 11 ] = ( c >>  0 ) & 0xFF;
	hash.value[ 12 ] = ( d >> 24 ) & 0xFF;
	hash.value[ 13 ] = ( d >> 16 ) & 0xFF;
	hash.value[ 14 ] = ( d >>  8 ) & 0xFF;
	hash.value[ 15 ] = ( d >>  0 ) & 0xFF;
	hash.value[ 16 ] = ( e >> 24 ) & 0xFF;
	hash.value[ 17 ] = ( e >> 16 ) & 0xFF;
	hash.value[ 18 ] = ( e >>  8 ) & 0xFF;
	hash.value[ 19 ] = ( e >>  0 ) & 0xFF;
	hash.value[ 20 ] = ( f >> 24 ) & 0xFF;
	hash.value[ 21 ] = ( f >> 16 ) & 0xFF;
	hash.value[ 22 ] = ( f >>  8 ) & 0xFF;
	hash.value[ 23 ] = ( f >>  0 ) & 0xFF;
	hash.value[ 24 ] = ( g >> 24 ) & 0xFF;
	hash.value[ 25 ] = ( g >> 16 ) & 0xFF;
	hash.value[ 26 ] = ( g >>  8 ) & 0xFF;
	hash.value[ 27 ] = ( g >>  0 ) & 0xFF;
	hash.value[ 28 ] = ( h >> 24 ) & 0xFF;
	hash.value[ 29 ] = ( h >> 16 ) & 0xFF;
	hash.value[ 30 ] = ( h >>  8 ) & 0xFF;
	hash.value[ 31 ] = ( h >>  0 ) & 0xFF;

	return hash;
}

int main( int argc, char *argv[] )
{
	if ( argc <= 1 )
		return RESULT_CODE_MISSING_ARGUMENTS;

	const char *filepath = argv[ 1 ];

	if ( !std::filesystem::is_regular_file( filepath ) )
		return RESULT_CODE_NOT_A_FILE;

	std::ifstream file( filepath, std::ios::binary );
	if ( !file.is_open() )
		return RESULT_CODE_FAILED_TO_OPEN_FILE;

	std::stringstream buffer;
	buffer << file.rdbuf();
	std::string fileData = buffer.str();

	Sha256Hash sha256Result = sha256( fileData.data(), fileData.size() );

	std::cout << sha256Result;

	return RESULT_CODE_SUCCESS;
}