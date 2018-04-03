#include "stdafx.h"

#include "rsa.h"
#include "prime.h"

static vlong from_str( const char * s )
{
	vlong x = 0;
	while (*s)
	{
		x = x * 256 + (unsigned char)*s;
		s += 1;
	}
	return x;
}

void private_key::create(const char * r1, const char * r2 )
{
	// Choose primes
	prime_factory pf;
	p = pf.find_prime( from_str(r1) );
	q = pf.find_prime( from_str(r2) );
	if ( p > q )
	{
		vlong tmp = p;
		p = q;
		q = tmp;
	}
	
	// Calculate n,e,d
	n = p*q;
	e = 65537;
	while ( gcd(p-1,e) != 1 || gcd(q-1,e) != 1 )
	{
		e += 2;
	}
	d = modinv( e, (p-1)*(q-1) );
}

vlong private_key::encrypt( const vlong& plain )
{
	return modexp( plain, e, n );
}

vlong private_key::decrypt( const vlong& cipher )
{
	// Calculate values for performing decryption
	// These could be cached, but the calculation is quite fast
	vlong u = modinv( p, q );
	vlong dp = d % (p-1);
	vlong dq = d % (q-1);
	
	// Apply chinese remainder theorem
	vlong a = modexp( cipher % p, dp, p );
	vlong b = modexp( cipher % q, dq, q );
	if ( b < a ) b += q;
	return a + p * ( ((b-a)*u) % q );
}
