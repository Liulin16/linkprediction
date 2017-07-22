/** 
 * @author Dorukhan Arslan, Didem Demirag
*/
package dtwlastversion;
/* Generates key for DGK encryption
 */
import java.math.BigInteger;
import java.util.Random;

public class DGK_key_generator {
    
    private BigInteger u;
    private BigInteger vpvq;
    //p and q are two distinct primes of equal bit length
    private BigInteger p;
    private BigInteger q;
    
    private BigInteger n;
    private BigInteger h;
    private BigInteger g;
    
    private BigInteger pp_inv;
    private BigInteger qq_inv;
    
    private int k; //the number of bits of the RSA modulus n
    private int t; //t is the size of two small primes vp and vq
    private int l; //message space size in bits

    public DGK_key_generator(int dgk_bitlength_n, int dgk_bitlength_v, int dgk_ell) {
        this.k = dgk_bitlength_n;
        this.t = dgk_bitlength_v;
        this.l = dgk_ell;
    }
    
    public void generateKeys(){
        if (k <= 0 || l <= 0 || t < 2){
            System.out.println("Illegal parameter for DGK cryptosystem!");
            System.exit(1);
        }
        if (k % 2 != 0){
            System.out.println("Parameter k has to be an even number!");
            System.exit(1);
        }
        if ((k/2 < (l + 5)) || (k/2 < t + 2)){
            System.out.println("Parameter k has to be specified by the rules k/2 > l+4 and k/2 > t+1!");
            System.exit(1);
        }
        
       BigInteger rp, rq;
       BigInteger vp, vq;
       BigInteger tmp1, tmp2, tmp3;
       Random rnd = new Random(System.currentTimeMillis());
       
       // u is the minimal prime number > L+2
       l = l*2;
       int tmp = l + 2;
       u = BigInteger.valueOf(tmp).nextProbablePrime();
       
       // vp is a random t bit prime number
       vp = BigInteger.probablePrime(t, rnd);
       
       // vq is a random t bit prime number
       vq = BigInteger.probablePrime(t, rnd);
       
       // store the product vp*vq
       vpvq = vp.multiply(vq);
      
       // p = rp*u*vp+1 where rp is randomly chosen such that p has roughly k/2 bits
       tmp1 = u.multiply(vp);
       int needed_bits = k/2 - tmp1.bitLength();
       do{
           rp = new BigInteger(needed_bits, rnd);
           rp = rp.setBit(needed_bits-1);
           p = rp.multiply(tmp1);
           p = p.add(BigInteger.ONE);
           
       }while(!p.isProbablePrime(100));
       
       // q = rq*u*vq+1 where rq is randomly chosen such that q has roughly k/2 bits
       tmp1 = u.multiply(vq);
       needed_bits = k/2 - tmp1.bitLength();
       do{
           rq = new BigInteger(needed_bits, rnd);
           rq = rq.setBit(needed_bits-1);
           q = rq.multiply(tmp1);
           q = q.add(BigInteger.ONE);
           
       }while(!q.isProbablePrime(100));
       
       // for faster encryption
       tmp1 = p.modInverse(q);
       pp_inv = p.multiply(tmp1);
       tmp1 = q.modInverse(p);
       qq_inv = q.multiply(tmp1);
       
       // RSA modulus n
       n = p.multiply(q);
       
       
      /*
      h  = h' ^{rp * rq * u} must be random in Zn* and have order vp*vq.   
      Set h = (hp, hq) and h' = (h'p, h'q) in Zp* x Zq*
      (hp^vpvq, hq^vpvq) = (h'p^{rp*u*vp}^(rq*vq), h'q^{rq*u*vq}^(rp*vp)) = (1^(rq*vq), 1^(rp*vp)) = (1, 1)
      which means that h^(vpvq) = 1 in Zn*.
      We need to check that h is not 1 and that it is in Zn*.
      */
       tmp1 = rq.multiply(u);
       tmp2 = rp.multiply(tmp1);
       int test1 = 1;
       int test2 = 1;
       do{
        long rand;
        rand = Math.abs( rnd.nextLong() ) % n.longValue();
        tmp1 = BigInteger.valueOf( rand );
        h = tmp1.modPow(tmp2, n);
        test1 = h.compareTo(BigInteger.ONE);
        tmp1 = h.gcd(n);
        test2 = tmp1.compareTo(BigInteger.ONE);
       }while(test1 == 0 || test2 != 0);
       
      //  g is chosen at random in Zn* such that it has order uv.
        
       tmp2 = rp.multiply(rq);
       test1 = 1;
       test2 = 1;
       int test3 = 1;
       int test4 = 1;
       int test5 = 1;
       int test6 = 1;
       int test7 = 1;
       int test8 = 1;
       do{
        long rand;
        rand = Math.abs( rnd.nextLong() ) % n.longValue();
        tmp1 = BigInteger.valueOf( rand );
        g = tmp1.modPow(tmp2, n);
        
        // test if g is "good":
        
        // test1==0 if gcd(g,n)==1
        tmp1 = g.gcd(n);
        test1 = tmp1.compareTo(BigInteger.ONE);
        
        // test2==0 if g==1
        test2 = g.compareTo(BigInteger.ONE);
        
        // test3==0 if ord(g)==u
        tmp1 = g.modPow(u, n);
        test3 = tmp1.compareTo(BigInteger.ONE);
        
        //test4==0 if ord(g)==vp
        tmp1 = g.modPow(vp, n);
        test4 = tmp1.compareTo(BigInteger.ONE);
        
        // test5==0 if ord(g)==vq
        tmp1 = g.modPow(vq, n);
        test5 = tmp1.compareTo(BigInteger.ONE);
        
        //test6==0 if ord(g)==u*vp
        tmp2 = u.multiply(vp);
        tmp1 = g.modPow(tmp2, n);
        test6 = tmp1.compareTo(BigInteger.ONE);
        
        //test7==0 if ord(g)==u*vq
        tmp2 = u.multiply(vq);
        tmp1 = g.modPow(tmp2, n);
        test7 = tmp1.compareTo(BigInteger.ONE);
        
        //test8==0 if ord(g)==vp*vq
        tmp1 = g.modPow(vpvq, n);
        test8 = tmp1.compareTo(BigInteger.ONE);
        
        test2 = test2*test3*test4*test5*test6*test7*test8;          
           
       }while(test1 != 0 || test2 == 0);
        
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getPp_inv() {
        return pp_inv;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getQq_inv() {
        return qq_inv;
    }

    public BigInteger getU() {
        return u;
    }

    public BigInteger getVpvq() {
        return vpvq;
    }
}
