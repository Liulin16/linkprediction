/** 
 * @author Dorukhan Arslan, Didem Demirag
*/

package dtwlastversion;
import java.math.BigInteger;
import java.util.*;

public class OffLineNumbers {
    
 
    private static long lcm( long first, long second ) {

	return  first * ( second / gcd( first, second ) );

    }

    // Computes the least common multiple of two numbers.
    private static BigInteger lcm( BigInteger first, BigInteger second ) {

		return  first.multiply( second.divide( first.gcd( second ) ) );

    }

    // Computes the greatest common denominator of two numbers.
     

    private static long gcd( long first, long second ) {

		return  first % second == 0 ? second : gcd( second, first % second );

    }
    
}
