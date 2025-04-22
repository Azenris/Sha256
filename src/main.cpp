
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

static u32 sigma0( u32 data )
{
	return rr( data, 7 ) ^ rr( data, 18 ) ^ sr( data, 3 );
};

static u32 sigma1( u32 data )
{
	return rr( data, 17 ) ^ rr( data, 19 ) ^ sr( data, 10 );
};

static u32 usigma0( u32 data )
{
	return rr( data, 2 ) ^ rr( data, 13 ) ^ rr( data, 22 );
};

static u32 usigma1( u32 data )
{
	return rr( data, 6 ) ^ rr( data, 11 ) ^ rr( data, 25 );
};

static u32 choice( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( ~data0 & data2 );
};

static u32 majority( u32 data0, u32 data1, u32 data2 )
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
	0xf7537e82,
	0xbd3af235,
	0x2ad7d2bb,
	0xeb86d391,
	0x3b1696b1,
	0x4b0f6b41,
	0x89f719fe,
	0x69037b55,
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
	char value[ SHA256_HASH_BYTES + 1 ];
};

Sha256Hash sha256( const char *dataIn, u64 size )
{
	// 1 byte of 0b100000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
	u64 padding = 64 - ( ( size + 1 + 8 ) & 63 );

	std::vector<u8> data;
	data.reserve( size + padding );
	data.assign( dataIn, dataIn + size );

	// -- padding --
	data.push_back( 0b10000000 );
	for ( i32 i = 0; i < padding; ++i )
		data.push_back( 0 );

	// -- length of message --
	data.push_back( ( size >> 54 ) & 0xFF );
	data.push_back( ( size >> 48 ) & 0xFF );
	data.push_back( ( size >> 40 ) & 0xFF );
	data.push_back( ( size >> 32 ) & 0xFF );
	data.push_back( ( size >> 24 ) & 0xFF );
	data.push_back( ( size >> 16 ) & 0xFF );
	data.push_back( ( size >>  8 ) & 0xFF );
	data.push_back( ( size >>  0 ) & 0xFF );

	u32 h0 = 0x6a09e667;
	u32 h1 = 0xbb67ae85;
	u32 h2 = 0x3c6ef372;
	u32 h3 = 0xa54ff53a;
	u32 h4 = 0x510e527f;
	u32 h5 = 0x9b05688c;
	u32 h6 = 0x1f83d9ab;
	u32 h7 = 0x5be0cd19;

	// TODO ...
	// ...

	// -- output --
	Sha256Hash hash;
	hash.value[  0 ] = ( h0 >>  0 ) & 0xFF;
	hash.value[  1 ] = ( h0 >>  8 ) & 0xFF;
	hash.value[  2 ] = ( h0 >> 16 ) & 0xFF;
	hash.value[  3 ] = ( h0 >> 24 ) & 0xFF;
	hash.value[  4 ] = ( h1 >>  0 ) & 0xFF;
	hash.value[  5 ] = ( h1 >>  8 ) & 0xFF;
	hash.value[  6 ] = ( h1 >> 16 ) & 0xFF;
	hash.value[  7 ] = ( h1 >> 24 ) & 0xFF;
	hash.value[  8 ] = ( h2 >>  0 ) & 0xFF;
	hash.value[  9 ] = ( h2 >>  8 ) & 0xFF;
	hash.value[ 10 ] = ( h2 >> 16 ) & 0xFF;
	hash.value[ 11 ] = ( h2 >> 24 ) & 0xFF;
	hash.value[ 12 ] = ( h3 >>  0 ) & 0xFF;
	hash.value[ 13 ] = ( h3 >>  8 ) & 0xFF;
	hash.value[ 14 ] = ( h3 >> 16 ) & 0xFF;
	hash.value[ 15 ] = ( h3 >> 24 ) & 0xFF;
	hash.value[ 16 ] = ( h4 >>  0 ) & 0xFF;
	hash.value[ 17 ] = ( h4 >>  8 ) & 0xFF;
	hash.value[ 18 ] = ( h4 >> 16 ) & 0xFF;
	hash.value[ 19 ] = ( h4 >> 24 ) & 0xFF;
	hash.value[ 20 ] = ( h5 >>  0 ) & 0xFF;
	hash.value[ 21 ] = ( h5 >>  8 ) & 0xFF;
	hash.value[ 22 ] = ( h5 >> 16 ) & 0xFF;
	hash.value[ 23 ] = ( h5 >> 24 ) & 0xFF;
	hash.value[ 24 ] = ( h6 >>  0 ) & 0xFF;
	hash.value[ 25 ] = ( h6 >>  8 ) & 0xFF;
	hash.value[ 26 ] = ( h6 >> 16 ) & 0xFF;
	hash.value[ 27 ] = ( h6 >> 24 ) & 0xFF;
	hash.value[ 28 ] = ( h7 >>  0 ) & 0xFF;
	hash.value[ 29 ] = ( h7 >>  8 ) & 0xFF;
	hash.value[ 30 ] = ( h7 >> 16 ) & 0xFF;
	hash.value[ 31 ] = ( h7 >> 24 ) & 0xFF;
	hash.value[ SHA256_HASH_BYTES ] = 0;
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

	std::cout << std::string_view( sha256Result.value, SHA256_HASH_BYTES ) << std::endl;

	return RESULT_CODE_SUCCESS;
}