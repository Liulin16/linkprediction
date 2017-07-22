package dtwlastversion;
/* Generates primes according to certain constraints
 */
import java.math.BigInteger;
import java.util.Vector;

public class PrimeGenerator {
    
    private BigInteger gen; // This number occurs just before the
                            // smallest generated prime.


    public PrimeGenerator() {

	gen = BigInteger.ONE;

    }

  
  // Returns a specified number of primes after start
    public Vector< Long > getPrimes( long start, int num ) {

	Vector< Long > p; // The primes found.

	p = new Vector< Long >( num );
	gen = BigInteger.valueOf( start - 1 );
	for( int i = 0; i < num; i++ ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen.longValue() );
	}

	return p;

    }

    // Returns a specified number of primes with at least a specified number of digits
	public Vector< BigInteger > getBigPrimes( int digits, int num ) {

	Vector< BigInteger > p; // The primes found.
	String start;           // Primes must be greater than this number.

	p = new Vector< BigInteger >( num );
	start = String.valueOf( '1' );
	for( int i = 1; i < digits; i++ ) {
	    start = start.concat( "0" );
	}
	gen = new BigInteger( start );
	for( int i = 0; i < num; i++ ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen );
	}

	return p;

    }

    
    // Returns all primes within a range of values. The lower and
    public Vector< Long > getPrimesBetween( long lb, long ub ) {

	Vector< Long > p; // The primes found.
	BigInteger stop;  // Indicates when to stop generating values.

	p = new Vector< Long >();
	gen = BigInteger.valueOf( lb - 1 );
	stop = BigInteger.valueOf( ub );
	while( gen.compareTo( stop ) <= 0 ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen.longValue() );
	}

	return p;

    }


}
