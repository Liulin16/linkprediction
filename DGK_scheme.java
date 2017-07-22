/** 
 * @author Dorukhan Arslan, Didem Demirag
*/
package dtwlastversion;
/* The DGK protocol
 */
import java.math.BigInteger;
import java.util.Random;

public class DGK_scheme {
    
    protected static long timeDGKEnc = 0;
    protected static long timeDGKDec = 0;
    
    protected static long startEnc, finishEnc, startDec, finishDec;
    
    // scheme parameter
    private int k;
    private int t;
    private int l;
    
    // public key
    private BigInteger n;
    private BigInteger g;
    private BigInteger h;
    private BigInteger u;
    
    //private key
    private Boolean canDecrypt;
    private BigInteger p;
    private BigInteger q;
    private BigInteger vpvq;
    
    //CRT parameters
    private Boolean secretKeyValid;
    private BigInteger pp_inv;
    private BigInteger qq_inv;
    
    public DGK_scheme(BigInteger[] pk, BigInteger[] sk, int ka, int ti, int ell){
        if (sk.length > 3){
            secretKeyValid = true;
            pp_inv = sk[3];
            qq_inv = sk[4];
        }
        else
            secretKeyValid = false;
        n = pk[0];
        g = pk[1];
        h = pk[2];
        u = pk[3];
        
        p = sk[0];
        q = sk[1];
        vpvq = sk[2];
        
        k = ka;
        t = ti;
        l = ell;
        canDecrypt = true;          
    }
    
    public DGK_scheme(BigInteger[] pk, int ti, int ell, int ka){
        secretKeyValid = false;
        n = pk[0];
        g = pk[1];
        h = pk[2];
        u = pk[3];
        t = ti;
        l = ell;
        k = ka;
        canDecrypt = false;
    }
    
    // DGK encryption
    public BigInteger encryption(BigInteger message){
        startEnc = System.nanoTime();
        
        BigInteger tmp1;
        BigInteger tmp2;
        BigInteger cipher;
        
        tmp1 = new BigInteger(t*2, new Random(System.currentTimeMillis()));
        tmp2 = h.modPow(tmp1, n);
        tmp1 = g.modPow(message, n);
        cipher = tmp1.multiply(tmp2);
        cipher = cipher.mod(n);
        
        finishEnc = System.nanoTime();
        timeDGKEnc += finishEnc - startEnc;
        
        return cipher;
    }
    
    //DGK "zero decryption": only checks if the ciphertext is an encryption of zero
    public boolean decryptionZero(BigInteger cipher) throws CryptoException{
        startDec = System.nanoTime();
        
        if (!canDecrypt){
            throw new CryptoException("Cannot dencrypt value because the secret "
                    + "key is not stored in the scheme");
        }
        
        BigInteger tmp1;
        
        tmp1 = cipher.modPow(vpvq, n);
        int res = tmp1.compareTo(BigInteger.ONE);
        
        finishDec = System.nanoTime();
        timeDGKDec += finishDec - startDec;
        
        return (res == 0);
    }
    
    // DGK Decryption.   
    public BigInteger decryption(BigInteger cipher) throws CryptoException{
        startDec = System.nanoTime();
        
        if (!canDecrypt){
            throw new CryptoException("Cannot dencrypt value because the secret "
                    + "key is not stored in the scheme");
        }
        
        BigInteger tmp1, tmp2;
        BigInteger message;
        
        message = cipher.modPow(vpvq, n);
        int uff = u.intValue();
        tmp1 = g.modPow(vpvq, n);
        
        for(int i=0;i<uff;i++){
            tmp2 = tmp1.modPow(BigInteger.valueOf(i), n);
            int res = message.compareTo(tmp2);
            if(res == 0)
                message = BigInteger.valueOf(i);
                  
        }
        
        finishDec = System.nanoTime();
        timeDGKDec += finishDec - startDec;
        
        return message;
    }
}
