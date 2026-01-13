
// System Includes
#include <iostream>

// Includes
#include "sha256.h"

int main( int argc, char *argv[] )
{
	if ( argc <= 1 )
		return 1;

	const char *filepath = argv[ 1 ];

	Sha256Hash sha256Result = sha256( filepath );

	std::cout << sha256Result;

	return 0;
}