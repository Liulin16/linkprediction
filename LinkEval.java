package dtwlastversion;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
/**
 *
 * @author Didem Demirag
 */
public class LinkEval {
    protected static long timeClient = 0, timeServer = 0, timeEu = 0, timeMin = 0;
    protected static long start, finish, startEu, finishEu, startMin, finishMin;
        
    protected static BigInteger p, q, n, g, h, nsquare, x, L, x1, x2;
    private static BigInteger[] publicKey;
    public static Scheme s;
    private static DGK_scheme dgk_s;
    private static BigInteger[] dgk_pk;
   // protected static Paillier paillier;
    
    public LinkEval(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }
    
    public LinkEval() {
        KeyGeneration(512, 128);
    }
    
    
    public void KeyGeneration(int bitLength, int certainty) {
        
        //paillier = new Paillier();
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());
        
        publicKey = new BigInteger[3];
    	publicKey[0] = p.multiply(q);
        n = publicKey[0];
        nsquare = n.multiply(n);
        
    	publicKey[1] = new BigInteger("1226");
    	// BigInteger a = randomBigInteger(BigInteger.ONE, nsquare);
        // publicKey[1] = pow(a, new BigInteger("2").multiply(n)).multiply(new BigInteger("-1"));
        
        x = new BigInteger("929");
        
        // Partial keys
        x2 = new BigInteger("111");
        x1 = x.subtract(x2);
        
        publicKey[2] = publicKey[1].pow(x.intValue());
        
        
        g = publicKey[1];
        h = publicKey[2];
        
        
        // BigInteger mult1 = new BigInteger("-1").modPow((q.subtract(new BigInteger("1")).multiply(p.subtract(new BigInteger("1")))).divide(new BigInteger("2")), nsquare);
        // BigInteger mult2 = new BigInteger("3651").modPow(n.multiply(q.subtract(new BigInteger("1"))).multiply(p.subtract(new BigInteger("1"))), nsquare);
        // System.out.println("Check: " + mult1.multiply(mult2).mod(nsquare));
                
        s = new Scheme(n, g, h, x);
        L = new BigInteger("32");
        
        generateDGKScheme(64, 160, 1024);
    }
    
    public static void generateDGKScheme(int l, int t, int k) {
        DGK_key_generator kg = new DGK_key_generator(k, t, l);
        kg.generateKeys();
        
        dgk_pk = new BigInteger[4];
        dgk_pk[0] = kg.getN();
        dgk_pk[1] = kg.getG();
        dgk_pk[2] = kg.getH();
        dgk_pk[3] = kg.getU();
                
        BigInteger[] dgk_sk = {kg.getP(), kg.getQ(), kg.getVpvq(), kg.getPp_inv(), kg.getQq_inv()};
        dgk_s = new DGK_scheme(dgk_pk, dgk_sk, k, t, l);
    }
    
    
    public static BigInteger[] compare(BigInteger[] enc_a, BigInteger[] enc_b) throws CryptoException {
        start = System.nanoTime();
        
        BigInteger twoPowL = BigInteger.valueOf(2).pow(L.intValue());
        BigInteger[] enc_twoPowL = s.encrypt(twoPowL);
        BigInteger[] enc_z = new BigInteger[2];
        
        enc_z[0] = enc_twoPowL[0].multiply(enc_a[0]).multiply(enc_b[0].modInverse(nsquare)).mod(nsquare);
        enc_z[1] = enc_twoPowL[1].multiply(enc_a[1]).multiply(enc_b[1].modInverse(nsquare)).mod(nsquare);
        
        Random rand = new Random();
        BigInteger r = new BigInteger("" + rand.nextInt(1000));
        BigInteger[] enc_r = s.encrypt(r);
        BigInteger[] enc_d = new BigInteger[2];
        enc_d[0] = enc_z[0].multiply(enc_r[0]).mod(nsquare);
        enc_d[1] = enc_z[1].multiply(enc_r[1]).mod(nsquare);
        
        BigInteger[] d_tilde = s.proxyDecription(enc_d, x2);
        
        finish = System.nanoTime();
        timeClient += finish - start;
        
        start = System.nanoTime();
        
        BigInteger plain_d = s.decrypt2(d_tilde, x1);
        
        BigInteger dMod2PowL = plain_d.mod(twoPowL);
        BigInteger[] enc_dMod2PowL = s.encrypt(dMod2PowL);
        
        finish = System.nanoTime();
        timeServer += finish - start;
        
        start = System.nanoTime();
        
        BigInteger rMod2PowL = r.mod(twoPowL);
        BigInteger[] enc_rMod2PowL = s.encrypt(rMod2PowL);
        
        finish = System.nanoTime();
        timeClient += finish - start;
        
        // System.out.println("Expected lambda:\t" + lambda);
        BigInteger[] enc_lambda = getEncLambda(dMod2PowL, rMod2PowL);
       // System.out.println("Lambda is: " + s.decrypt(enc_lambda));
        // BigInteger[] enc_lambda = s.encrypt(lambda);
        
        start = System.nanoTime();
        BigInteger[] enc_lambda2PowL = new BigInteger[2];
        
        enc_lambda2PowL[0] = enc_lambda[0].modPow(twoPowL, nsquare);
        enc_lambda2PowL[1] = enc_lambda[1].modPow(twoPowL, nsquare);
        
        // * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
        
        BigInteger[] enc_zMod2PowL = new BigInteger[2];
        enc_zMod2PowL[0] = enc_dMod2PowL[0].multiply(enc_rMod2PowL[0].modInverse(nsquare)).multiply(enc_lambda2PowL[0]).mod(nsquare);
        enc_zMod2PowL[1] = enc_dMod2PowL[1].multiply(enc_rMod2PowL[1].modInverse(nsquare)).multiply(enc_lambda2PowL[1]).mod(nsquare);
        
        //System.out.println("enc_zMod2PowL: " + s.decrypt(enc_zMod2PowL));
        /*
        BigInteger[] enc_zLMinus1 = new BigInteger[2];
        enc_zLMinus1[0] = enc_z[0].multiply(enc_zMod2PowL[0].modInverse(nsquare));
        enc_zLMinus1[1] = enc_z[1].multiply(enc_zMod2PowL[1].modInverse(nsquare));
        
        System.out.println("lambda:\t" + s.decrypt(enc_lambda));
        System.out.println("lambda2PowL:\t" + s.decrypt(enc_lambda2PowL));
        System.out.println("a:\t" + s.decrypt(enc_a));
        System.out.println("b:\t" + s.decrypt(enc_b));
        System.out.println("z:\t" + s.decrypt(enc_z));
        System.out.println("zMod2PowL:\t" + s.decrypt(enc_zMod2PowL));
        */
        
        // System.out.println("bit:\t" + BigInteger.ONE.subtract(new BigInteger("" + result.charAt(0))));
        
        BigInteger[] diff = new BigInteger[2];
        diff[0] = enc_z[0].multiply(enc_zMod2PowL[0].modInverse(nsquare)).mod(nsquare);
        diff[1] = enc_z[1].multiply(enc_zMod2PowL[1].modInverse(nsquare)).mod(nsquare);
        
        // enc_a diff
        // b twoPowL
        // http://crypto.stackexchange.com/questions/2076/division-in-paillier-cryptosystem
        
        BigInteger b_hat = twoPowL.modPow(BigInteger.valueOf(-1), n);
        
        diff[0] = diff[0].modPow(b_hat, nsquare);
        diff[1] = diff[1].modPow(b_hat, nsquare);
        
        finish = System.nanoTime();
        timeClient += finish - start;
        
        // return enc(1 - dec(diff))
        /*BigInteger[] enc_one = s.encrypt(BigInteger.ONE);
        diff[0] = enc_one[0].multiply(diff[0].modInverse(nsquare)).mod(nsquare);
        diff[1] = enc_one[1].multiply(diff[1].modInverse(nsquare)).mod(nsquare);*/
        
        return diff;
    }
        
    public static BigInteger[] getEncLambda(BigInteger dMod2PowL, BigInteger rMod2PowL) throws CryptoException {
        
        /*
        System.out.println("dMod2PowL:\t" + dMod2PowL.intValue());
        System.out.println("rMod2PowL:\t" + rMod2PowL.intValue());
        */
        
        start = System.nanoTime();
        String dMod2PowL_bits = Integer.toBinaryString(dMod2PowL.intValue());
        // System.out.println("dMod2PowL_bits: " + dMod2PowL_bits);
        
        ArrayList<BigInteger> enc_d_hat = new ArrayList<BigInteger>();
        
        for (int i = dMod2PowL.bitLength() - 1; i >= 0; i--) {
            BigInteger enc_di_hat = dgk_s.encryption(new BigInteger("" + dMod2PowL_bits.charAt(i)));
            enc_d_hat.add(enc_di_hat);
        }
        
        int index = enc_d_hat.size();
        while (index < L.intValue()) {
            enc_d_hat.add(dgk_s.encryption(BigInteger.ZERO));
            index++;
        }
        
        finish = System.nanoTime();
        timeServer += finish - start;
        
        // * * * * * * *
        
        start = System.nanoTime();
        
        String rMod2PowL_bits = Integer.toBinaryString(rMod2PowL.intValue());
        ArrayList<BigInteger> enc_r_hat = new ArrayList<BigInteger>();
        ArrayList<BigInteger> r_hat = new ArrayList<BigInteger>();
        
        for (int i = rMod2PowL.bitLength() - 1; i >= 0; i--) {
            BigInteger enc_ri_hat = dgk_s.encryption(new BigInteger("" + rMod2PowL_bits.charAt(i)));
            enc_r_hat.add(enc_ri_hat);
            r_hat.add(new BigInteger("" + rMod2PowL_bits.charAt(i)));
        }
        
        index = enc_r_hat.size();
        while (index < L.intValue()) {
            enc_r_hat.add(dgk_s.encryption(BigInteger.ZERO));
            r_hat.add(BigInteger.ZERO);
            index++;
        }
        
        /*
        int[] s_values = new int[2];
        s_values[0] = 1;
        s_values[1] = -1;
        */
        
        int[] s_values = new int[1];
        s_values[0] = 1;
        
        int rand = new Random().nextInt(s_values.length);
        int s_chosen = s_values[rand];
        
        BigInteger enc_s = dgk_s.encryption(BigInteger.valueOf(s_chosen));
        // System.out.println("SSSS:\t" + dgk_s.decryption(enc_s));
        
        ArrayList<BigInteger> enc_c_bits = new ArrayList<BigInteger>();
        ArrayList<BigInteger> sum_wj = new ArrayList<BigInteger>();
        
        for (int i = 0; i < L.intValue(); i++) {
            
            BigInteger enc_sum_wj = dgk_s.encryption(BigInteger.ZERO);
            
            for (int j = i + 1; j < L.intValue(); j++) {
                BigInteger w = xor(enc_d_hat.get(j), enc_r_hat.get(j), r_hat.get(j));
                //System.out.println("w: " + dgk_s.decryption(w));
                enc_sum_wj = (enc_sum_wj.multiply(w)).mod(dgk_pk[0]);
            }
            
            BigInteger p1 = enc_r_hat.get(i).modInverse(dgk_pk[0]);
            p1 = enc_d_hat.get(i).multiply(p1);
            
            // System.out.println("p11:\t" + dgk_s.decryption(p1));
            p1 = p1.multiply(enc_s);
            
            sum_wj.add(enc_sum_wj);
            
            enc_sum_wj = enc_sum_wj.modPow(BigInteger.valueOf(3), dgk_pk[0]);
            
            // System.out.println("p1:\t" + dgk_s.decryption(p1));
            // System.out.println("enc_sum_wj1:\t" + dgk_s.decryption(enc_sum_wj));
            BigInteger c = p1.multiply(enc_sum_wj);
            c = c.mod(dgk_pk[0]);
            
            enc_c_bits.add(c);
        }
        //System.out.println("c bits: " );
        //decryptNPrint(enc_c_bits);
        // Shuffling
        // Collections.shuffle(enc_c_bits);
        
        finish = System.nanoTime();
        timeClient += finish - start;
        
        start = System.nanoTime();
        
        BigInteger a = null;
        for (int i = enc_c_bits.size() - 1; i >= 0; i--) {
            // System.out.println("boolean    " + dgk_s.decryptionZero(enc_c_bits.get(i)));
            // System.out.println("value      " + dgk_s.decryption(enc_c_bits.get(i)));
            
            if (dgk_s.decryptionZero(enc_c_bits.get(i))) {
                a = BigInteger.ZERO;
                break;
            }
            else {
                a = BigInteger.ONE;
            }
        }
       
        BigInteger[] enc_a = s.encrypt(a);
        
        finish = System.nanoTime();
        
        timeServer += finish - start;
        
        start = System.nanoTime();
        BigInteger[] enc_lambda = new BigInteger[2];
        
        // System.out.println("a - s:\t" + s.decrypt(enc_a) + " - " + s_chosen);
        
        BigInteger[] enc_one = s.encrypt(BigInteger.ONE);
        if (s_chosen == 1) {
            enc_lambda[0] = enc_one[0].multiply(enc_a[0].modInverse(nsquare));
            enc_lambda[1] = enc_one[1].multiply(enc_a[1].modInverse(nsquare));
        }
        else {
            enc_lambda[0] = enc_a[0];
            enc_lambda[1] = enc_a[1];
        }
        
        /*
        System.out.print("enc_d_hat:\t");
        decryptNPrint(enc_d_hat);
        System.out.print("enc_r_hat:\t");
        decryptNPrint(enc_r_hat);
        System.out.print("sum_wj:\t\t"); 
        decryptNPrint(sum_wj);
        System.out.print("enc_c_bits:\t");
        decryptNPrint(enc_c_bits);
        */
        
        finish = System.nanoTime();
        timeClient += finish - start;
        
        return enc_lambda;
    } 
    
    public static BigInteger xor(BigInteger enc_dj, BigInteger enc_rj, BigInteger rj) throws CryptoException {
        BigInteger exp = rj.multiply(BigInteger.valueOf(2));
        BigInteger p1 = enc_dj.multiply(enc_rj);
        BigInteger p2 = enc_dj.modInverse(dgk_pk[0]);
        p2 = p2.modPow(exp, dgk_pk[0]);
        BigInteger w = (p1.multiply(p2)).mod(dgk_pk[0]);

        return w;
    }
    
    private static void decryptNPrint(ArrayList<BigInteger> list) throws CryptoException {
        for (int i = list.size() - 1; i >= 0; i--) {
            System.out.print(dgk_s.decryption(list.get(i)) + " ");
        }
        System.out.println();
    }
    
    
    public static String[] getNeighbors(String neighbor, String filename) throws FileNotFoundException, IOException
    {
        String[] neighbors = new String[1];
        String line = null;
        FileReader fileReader = new FileReader(filename);
 
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        int count = 0;
        while((line = bufferedReader.readLine()) != null) {
            neighbors = line.split(",");
            count++;
            if(count == Integer.parseInt(neighbor))
                break;
        }  
        bufferedReader.close();         
        
        return neighbors;
    }
    
    public static ArrayList<String> commonNeighbors(String[] n1, String[] n2)
    {
        ArrayList<String> common = new ArrayList<String>();
        for(int i = 0; i < n1.length; i++)
        {
            for(int j = 0; j < n2.length; j++)
            {
                if(n1[i].equals(n2[j]) )
                {
                    common.add(n1[i]);
                    break;
                }
            }
        }    
            
        return common;
    }
    
    public static ArrayList<String> removeCommonNeighbors(String[] n1, ArrayList<String> common)
    {
        ArrayList<String> newn1 = new ArrayList<String>();
        for(int i = 0; i < n1.length; i++)
        {   
            String a = n1[i];
            if(!(common.contains(a)))
            {

                newn1.add(n1[i]); 
            }
            
        }
            
        return newn1;
    }
    
    public static BigInteger[] functionF(BigInteger[] enc_a, BigInteger[] enc_b) throws CryptoException
    {
        
        BigInteger[] enc_one = s.encrypt(new BigInteger("1"));
   
        BigInteger[] f1 = compare(enc_a,enc_b);
        //System.out.println(s.decrypt(enc_a) + " " + s.decrypt(enc_b) + ", f1: " + s.decrypt(f1));
        
        BigInteger new_enc_b[] =  new BigInteger[2];
        new_enc_b[0] = enc_b[0].multiply(enc_one[0]).mod(nsquare);
        new_enc_b[1] = enc_b[1].multiply(enc_one[1]).mod(nsquare);
        
        BigInteger[] f2 = compare(enc_a,new_enc_b);
      //  System.out.println(s.decrypt(enc_a) + " " + s.decrypt(new_enc_b) + ", f2: " + s.decrypt(f2));
        
        BigInteger[] one_minus_f2 = new BigInteger[2];
        one_minus_f2[0] = enc_one[0].multiply(f2[0].modInverse(nsquare)).mod(nsquare);
        one_minus_f2[1] = enc_one[1].multiply(f2[1].modInverse(nsquare)).mod(nsquare);
       // System.out.println("1 - f2: " + s.decrypt(one_minus_f2));
        
     
        Random rand = new Random();
        BigInteger r1 = new BigInteger("" + 2/*rand.nextInt(10)*/);
        BigInteger r2 = new BigInteger("" + 3/*rand.nextInt(10)*/);
        BigInteger[] enc_r1 = s.encrypt(r1);
        BigInteger[] enc_r2 = s.encrypt(r2);
        
     //   System.out.println("r1: " + r1 + " r2: " + r2);
        
        BigInteger[] enc_f1_r1 = new BigInteger[2];
        enc_f1_r1[0] = f1[0].multiply(enc_r1[0]).mod(nsquare);
        enc_f1_r1[1] = f1[1].multiply(enc_r1[1]).mod(nsquare);
     //   System.out.println("f1+r1: " + s.decrypt(enc_f1_r1));
        
        BigInteger[] enc_one_minus_f2_r2 = new BigInteger[2];
        enc_one_minus_f2_r2[0] = one_minus_f2[0].multiply(enc_r2[0]).mod(nsquare);
        enc_one_minus_f2_r2[1] = one_minus_f2[1].multiply(enc_r2[1]).mod(nsquare);
       // System.out.println("(1-f2)+r2: " + s.decrypt(enc_one_minus_f2_r2));
        
        BigInteger f1_r1 = s.decrypt(enc_f1_r1);
        BigInteger one_minus_f2_r2 = s.decrypt(enc_one_minus_f2_r2);
        
        BigInteger mult = f1_r1.multiply(one_minus_f2_r2);
        BigInteger[] enc_mult = s.encrypt(mult);
      //  System.out.println("mult: " + mult);
        
        BigInteger[] enc_r1r2 = s.encrypt(r1.multiply(r2));
      //  System.out.println("r1r2: " + s.decrypt(enc_r1r2));
        
        BigInteger[] enc_f1r1 = new BigInteger[2];
        enc_f1r1[0] = f1[0].modPow(r2,nsquare);
        enc_f1r1[1] = f1[1].modPow(r2,nsquare);
     //   System.out.println("enc_f1r1: " + s.decrypt(enc_f1r1));
 
        BigInteger[] enc_one_minus_f2r2 = new BigInteger[2];
        enc_one_minus_f2r2[0] = one_minus_f2[0].modPow(r1,nsquare);
        enc_one_minus_f2r2[1] = one_minus_f2[1].modPow(r1,nsquare);
       // System.out.println("enc_one_minus_f2r2: " + s.decrypt(enc_one_minus_f2r2));
        
        BigInteger[] f = new BigInteger[2];
        f[0] = enc_mult[0].multiply(enc_f1r1[0].modInverse(nsquare)).mod(nsquare);
        f[1] = enc_mult[1].multiply(enc_f1r1[1].modInverse(nsquare)).mod(nsquare);
     //   System.out.println("f: " + s.decrypt(f) );
        f[0] = f[0].multiply(enc_one_minus_f2r2[0].modInverse(nsquare)).mod(nsquare);
        f[1] = f[1].multiply(enc_one_minus_f2r2[1].modInverse(nsquare)).mod(nsquare);
      //  System.out.println("f: " + s.decrypt(f) );
        f[0] = f[0].multiply(enc_r1r2[0].modInverse(nsquare)).mod(nsquare);
        f[1] = f[1].multiply(enc_r1r2[1].modInverse(nsquare)).mod(nsquare);
       // System.out.println("f: " + s.decrypt(f) );
        return f;
    }
    
    //NEW
     public static BigInteger[] listSize(ArrayList<BigInteger[]> encn2Gr1, 
            ArrayList<BigInteger[]> encn1Gr2, ArrayList<String> n1NewGr2) throws CryptoException
    {
        
        BigInteger[] size = s.encrypt(new BigInteger("0"));
        for(int k = 1; k <encn2Gr1.size();k++)
        {
        //int k = 3;
            for(int i = 1; i<encn1Gr2.size(); i++)
            {
                BigInteger[] comp = functionF(encn2Gr1.get(k), encn1Gr2.get(i));
                size[0] = size[0].multiply(comp[0]);
                size[1] = size[1].multiply(comp[1]);
                //System.out.println("element: " + n1NewGr2.get(i) + s.decrypt(encn2Gr1.get(k)));
                //System.out.println("comp: " + s.decrypt(comp));
                //System.out.println("addnode: " +  s.decrypt(addnode));

            }
        }
        
        /*for(int i = 0; i<g1n2INTg2n1.size(); i++)
        {
            System.out.println(s.decrypt(g1n2INTg2n1.get(i)));
        }*/
        return size;
    }
    
     public static BigInteger[][][] adjMatrix(ArrayList<BigInteger[]> encn2Gr1, 
            ArrayList<BigInteger[]> encn1Gr2) throws CryptoException
    {
        BigInteger[][][] adj = new BigInteger[encn2Gr1.size()][encn1Gr2.size()][2];
        for(int i = 0; i < encn2Gr1.size(); i++)
        {
            for(int j = 0; j < encn1Gr2.size();j++)
            {
                adj[i][j] = functionF(encn2Gr1.get(i), encn1Gr2.get(j));
            }
        }
        return adj;
    }
     
     public static BigInteger[][][] adjMatrixCommon(ArrayList<BigInteger[]> encn2Gr1, 
            ArrayList<BigInteger[]> encn1Gr2) throws CryptoException
    {
        BigInteger[][][] adj = new BigInteger[encn2Gr1.size()][encn1Gr2.size()][2];
        BigInteger[] enc_one = s.encrypt(new BigInteger("1"));
        for(int i = 0; i < encn2Gr1.size(); i++)
        {
            for(int j = 0; j < encn1Gr2.size();j++)
            {
                BigInteger[] f = functionF(encn2Gr1.get(i), encn1Gr2.get(j));
                BigInteger[] res = new BigInteger[2];
                res[0] = enc_one[0].multiply(f[0].modInverse(nsquare)).mod(nsquare);
                res[1] = enc_one[1].multiply(f[1].modInverse(nsquare)).mod(nsquare);
                adj[i][j] = res;
            }
        }
        return adj;
    }
     
    public static ArrayList<BigInteger[]> intersection(ArrayList<BigInteger[]> encn2Gr1, 
            ArrayList<BigInteger[]> encn1Gr2, ArrayList<String> n1NewGr2) throws CryptoException
    {
        ArrayList<BigInteger[]> g1n2INTg2n1 = new ArrayList<BigInteger[]>();
        for(int k = 1; k <encn2Gr1.size();k++)
        {
        //int k = 3;
            for(int i = 1; i<encn1Gr2.size(); i++)
            {
                BigInteger[] comp = functionF(encn2Gr1.get(k), encn1Gr2.get(i));
                BigInteger[] addnode = new BigInteger[2];
                addnode[0] = comp[0].modPow(new BigInteger(n1NewGr2.get(i)), nsquare);
                addnode[1] = comp[1].modPow(new BigInteger(n1NewGr2.get(i)), nsquare); 
                //System.out.println("element: " + n1NewGr2.get(i) + s.decrypt(encn2Gr1.get(k)));
                //System.out.println("comp: " + s.decrypt(comp));
                //System.out.println("addnode: " +  s.decrypt(addnode));

                g1n2INTg2n1.add(addnode);
            }
        }
        
        /*for(int i = 0; i<g1n2INTg2n1.size(); i++)
        {
            System.out.println(s.decrypt(g1n2INTg2n1.get(i)));
        }*/
        return g1n2INTg2n1;
    }
    
     public static ArrayList<BigInteger[]> intersectionCommon(ArrayList<BigInteger[]> encn2Gr1, 
            ArrayList<BigInteger[]> encn1Gr2, ArrayList<String> n1NewGr2) throws CryptoException
    {
        ArrayList<BigInteger[]> g1n2INTg2n1 = new ArrayList<BigInteger[]>();
        for(int k = 0; k <encn2Gr1.size();k++)
        {
        //int k = 3;
            for(int i = 0; i<encn1Gr2.size(); i++)
            {
                BigInteger[] comp = functionF(encn2Gr1.get(k), encn1Gr2.get(i));
             
                BigInteger[] enc_one = s.encrypt(new BigInteger("1"));
                comp[0] = enc_one[0].multiply(comp[0].modInverse(nsquare)).mod(nsquare);
                comp[1] = enc_one[1].multiply(comp[1].modInverse(nsquare)).mod(nsquare);
          
                
                BigInteger[] addnode = new BigInteger[2];
                addnode[0] = comp[0].modPow(new BigInteger(n1NewGr2.get(i)), nsquare);
                addnode[1] = comp[1].modPow(new BigInteger(n1NewGr2.get(i)), nsquare); 
                //System.out.println("element: " + n1NewGr2.get(i) + s.decrypt(encn2Gr1.get(k)));
                //System.out.println("comp: " + s.decrypt(comp));
                //System.out.println("addnode: " +  s.decrypt(addnode));

                g1n2INTg2n1.add(addnode);
            }
        }
        
        /*for(int i = 0; i<g1n2INTg2n1.size(); i++)
        {
            System.out.println(s.decrypt(g1n2INTg2n1.get(i)));
        }*/
        return g1n2INTg2n1;
    }
     
    
    public static void printArrayList(ArrayList<?> a)
    {
        for(int i = 0; i< a.size();i++)
        {
            System.out.print(a.get(i) + " ");
        }
        System.out.println();     
    }
    
    
    public static void main (String args[]) throws CryptoException, IOException
    {
        long start = 0;
        long finish = 0;
        start = System.nanoTime();  
        new LinkEval();
       /* String g1 = "g1.txt";
        String g2 = "g2.txt";*/
        String neigh1 = "3";
        String neigh2 = "5";
       
        String g1 = "g1-1000-5-10.txt";
        String g2 = "g2-1000-5-10.txt";
        
        String[] n1 = getNeighbors(neigh1, g1);
        String[] n2 = getNeighbors(neigh2, g1);
      
        ArrayList<String> commongr1 = commonNeighbors(n1, n2);
        System.out.print("commongr1: ");

        ArrayList<String> n1NewGr1 = removeCommonNeighbors(n1, commongr1);
        System.out.print("n1NewGr1: ");

        ArrayList<String> n2NewGr1 = removeCommonNeighbors(n2, commongr1);
        System.out.print("n2NewGr1: ");
    
        //G2 preparation
        n1 = getNeighbors(neigh1, g2);  
        n2 = getNeighbors(neigh2, g2);
      
        ArrayList<String> commongr2 = commonNeighbors(n1, n2);
        System.out.print("commongr2: ");

        ArrayList<String> n1NewGr2 = removeCommonNeighbors(n1, commongr2);
        System.out.print("n1NewGr2: ");

        ArrayList<String> n2NewGr2 = removeCommonNeighbors(n2, commongr2);
        System.out.print("n2NewGr2: ");
    
       
        //GRAPH 1
        ArrayList<BigInteger[]> encn1Gr1 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n1NewGr1.size(); i++)
        {
            encn1Gr1.add(s.encrypt(new BigInteger(n1NewGr1.get(i))));
        }
        
        ArrayList<BigInteger[]> encn2Gr1 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n2NewGr1.size(); i++)
        {
            encn2Gr1.add(s.encrypt(new BigInteger(n2NewGr1.get(i))));
        }
    
        
        ArrayList<BigInteger[]> enccommongr1 = new ArrayList<BigInteger[]> ();
        for(int i = 0; i < commongr1.size();i++)
        {
            enccommongr1.add(s.encrypt(new BigInteger(commongr1.get(i))));
        }
        

        
        //GRAPH 2
        ArrayList<BigInteger[]> encn1Gr2 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n1NewGr2.size(); i++)
        {
            encn1Gr2.add(s.encrypt(new BigInteger(n1NewGr2.get(i))));
        }
        
        ArrayList<BigInteger[]> encn2Gr2 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n2NewGr2.size(); i++)
        {
            encn2Gr2.add(s.encrypt(new BigInteger(n2NewGr2.get(i))));
        }
        
        ArrayList<BigInteger[]> enccommongr2 = new ArrayList<BigInteger[]> ();
        for(int i = 0; i < commongr2.size();i++)
        {
            enccommongr2.add(s.encrypt(new BigInteger(commongr2.get(i))));
        }
          
        
        BigInteger[][][] adjn2Gr1n1Gr2 = adjMatrix(encn2Gr1, encn1Gr2);
        System.out.println("adjn2Gr1n1Gr2: ");

        
        BigInteger[][][] adjn2Gr2n1Gr1 = adjMatrix(encn2Gr2, encn1Gr1);
        System.out.println("adjn1Gr2n2Gr1: "); 
        
        BigInteger[][][] adjCommons = adjMatrix(enccommongr1, enccommongr2);
        System.out.println("adjCommons: ");
    
        
        BigInteger[] sizeCommon = s.encrypt(new BigInteger("0"));
        for(int i=0 ; i<adjn2Gr1n1Gr2.length ; i++)
        {
            for(int j=0 ; j<adjn2Gr1n1Gr2[i].length ; j++)
            {
                sizeCommon[0] =adjn2Gr1n1Gr2[i][j][0].multiply(sizeCommon[0]).mod(nsquare);
                sizeCommon[1] =adjn2Gr1n1Gr2[i][j][1].multiply(sizeCommon[1]).mod(nsquare);
                
            }
        }
        
        for(int i=0 ; i<adjn2Gr2n1Gr1.length ; i++)
        {
            for(int j=0 ; j<adjn2Gr2n1Gr1[i].length ; j++)
            {
               sizeCommon[0] =adjn2Gr2n1Gr1[i][j][0].multiply(sizeCommon[0]).mod(nsquare);
               sizeCommon[1] =adjn2Gr2n1Gr1[i][j][1].multiply(sizeCommon[1]).mod(nsquare);
            }
        }
       // System.out.println("adj size: " + s.decrypt(sizeCommon));
        BigInteger[] encCommongr2size = s.encrypt(new BigInteger(""+enccommongr2.size()));
        
        BigInteger[] sizeintCommon = s.encrypt(new BigInteger("0"));
        for(int i=0 ; i<adjCommons.length ; i++)
        {
            for(int j=0 ; j<adjCommons[i].length ; j++)
            {
                sizeintCommon[0] =adjCommons[i][j][0].multiply(sizeintCommon[0]).mod(nsquare);
                sizeintCommon[1] =adjCommons[i][j][1].multiply(sizeintCommon[1]).mod(nsquare);
                
            }
        }
       // System.out.println("sizeintCommon: " + s.decrypt(sizeintCommon));
        BigInteger[] sizeToAdd = new BigInteger[2];
        
        sizeToAdd[0] = encCommongr2size[0].multiply(sizeintCommon[0].modInverse(nsquare)).mod(nsquare);
        sizeToAdd[1] = encCommongr2size[1].multiply(sizeintCommon[1].modInverse(nsquare)).mod(nsquare);
       
       // System.out.println("sizeToAdd: " + s.decrypt(sizeToAdd));
        
        BigInteger[] totalSizeAtG2 = new BigInteger[2];
        totalSizeAtG2[0] = sizeToAdd[0].multiply(sizeCommon[0]).mod(nsquare);
        totalSizeAtG2[1] = sizeToAdd[1].multiply(sizeCommon[1]).mod(nsquare);
        
       // System.out.println("totalSizeAtG2: " + s.decrypt(totalSizeAtG2));
        int commonNeigh = commongr1.size() + s.decrypt(totalSizeAtG2).intValue();
        System.out.println("commonNeigh: " + commonNeigh);
       
      
       // ArrayList<BigInteger[]> combinen1INTn2 = new ArrayList<BigInteger[]>();
   
       BigInteger[] enc_zero = s.encrypt(new BigInteger("0"));
     
        
        
        //FOR JACCARD-union
        System.out.println("Computing Jaccard");
        ArrayList<String>  n1UNIONn2GR1= new ArrayList<String>();
        n1UNIONn2GR1.addAll(n1NewGr1);
        n1UNIONn2GR1.addAll(n2NewGr1);
        System.out.println("Graph1 Union: ");
       // printArrayList(n1UNIONn2GR1);
        ArrayList<String>  n1UNIONn2GR2= new ArrayList<String>();
        n1UNIONn2GR2.addAll(n1NewGr2);
        n1UNIONn2GR2.addAll(n2NewGr2);
        System.out.println("Graph2 Union: ");
       // printArrayList(n1UNIONn2GR2);
        ArrayList<BigInteger[]> encn1UNIONn2GR1 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n1UNIONn2GR1.size(); i++)
        {
            encn1UNIONn2GR1.add(s.encrypt(new BigInteger(n1UNIONn2GR1.get(i))));
        }
   
        ArrayList<BigInteger[]> encn1UNIONn2GR2 = new  ArrayList<BigInteger[]> ();
        for(int i = 0; i < n1UNIONn2GR2.size(); i++)
        {
            encn1UNIONn2GR2.add(s.encrypt(new BigInteger(n1UNIONn2GR2.get(i))));
        }
       
        
        BigInteger[][][] adjUnions = adjMatrix(encn1UNIONn2GR1, encn1UNIONn2GR2);
        System.out.println("adjUnions: ");
      
        
        BigInteger[] sizeUnion = s.encrypt(new BigInteger("0"));
        for(int i=0 ; i<adjUnions.length ; i++)
        {
            for(int j=0 ; j<adjUnions[i].length ; j++)
            {
                sizeUnion[0] =adjUnions[i][j][0].multiply(sizeUnion[0]).mod(nsquare);
                sizeUnion[1] =adjUnions[i][j][1].multiply(sizeUnion[1]).mod(nsquare);
                
            }
        }
       // System.out.println("sizeUnion: " + s.decrypt(sizeUnion));
        BigInteger[] encSizeUnionGr1 = s.encrypt(new BigInteger(""+ n1UNIONn2GR1.size()));
        BigInteger[] encSizeUnionGr2 = s.encrypt(new BigInteger(""+ n1UNIONn2GR2.size()));
        BigInteger[] jaccardUnion = new BigInteger[2];
        jaccardUnion[0] = encSizeUnionGr1[0].multiply(encSizeUnionGr2[0]).mod(nsquare);
        jaccardUnion[1] = encSizeUnionGr1[1].multiply(encSizeUnionGr2[1]).mod(nsquare);
        jaccardUnion[0] = jaccardUnion[0].multiply(sizeUnion[0].modInverse(nsquare)).mod(nsquare);
        jaccardUnion[1] = jaccardUnion[1].multiply(sizeUnion[1].modInverse(nsquare)).mod(nsquare);
        
         System.out.println("jaccardUnion: " + s.decrypt(jaccardUnion));
      
        System.out.println("Intersection size: " + commonNeigh);
        double jaccard =  ((double)(commonNeigh))/ (double)(s.decrypt(jaccardUnion).intValue());
        
        System.out.println("Jaccard coeff: " + jaccard);
        finish = System.nanoTime();
        System.out.println("time: " + (finish - start)/1000000000.0) ;
        
    }
   
    
    
}
