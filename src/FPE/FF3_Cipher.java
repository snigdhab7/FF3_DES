package FPE;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class FF3_Cipher {
   
    public FF3_Cipher(String key, String tweak) {
        this(key, tweak, 10);
    }
    
    public FF3_Cipher(String key, String tweak, int radix) {
        this.radix = radix;
        byte[] keyBytes = hexStringToByteArray(key);
        
        this.minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));

        this.maxLen = (int) (2 * Math.floor(Math.log(Math.pow(2,96))/Math.log(radix)));

        int keyLen = keyBytes.length;
        if ((radix < 2) || (radix > MAX_RADIX)) {
            throw new IllegalArgumentException ("radix must be between 2 and 36, inclusive");
        }

        if ((this.minLen < 2) || (this.maxLen < this.minLen)) {
            throw new IllegalArgumentException ("minLen or maxLen invalid, adjust your radix");
        }

        this.tweakBytes = hexStringToByteArray(tweak);
        try {
            reverseBytes(keyBytes);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
            desCipher = Cipher.getInstance("DES");
            desCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /* convenience method to override tweak */
    public String encrypt(String plaintext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = hexStringToByteArray(tweak);
        return encrypt(plaintext);
    }

    public String encrypt(String plaintext) throws BadPaddingException, IllegalBlockSizeException {
        int n = plaintext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Make sure the given the length of tweak in bits is 64
        if (this.tweakBytes.length != TWEAK_LEN){
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 8 bytes, or 64 bits",
                    this.tweakBytes.length));
        }

        // Check if the plaintext message is formatted in the current radix
        try {
            new BigInteger(plaintext, this.radix);
        } catch (NumberFormatException ex) {
            throw new NumberFormatException(String.format("The plaintext is not supported in the current radix %d", this.radix));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = plaintext.substring(0,u);
        String B = plaintext.substring(u);

        // Split the tweak
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        
        for (byte i = 0; i < NUM_ROUNDS; ++ i) {
            int m;
            BigInteger c;
            byte[] W;

            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = calculateP( i, this.radix, W, B);
            reverseBytes(P);

            // Calculate S by operating on P in place
            byte[] S = this.desCipher.doFinal(P);
            reverseBytes(S);
            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);
         
            // Calculate c
            try {
                c = new BigInteger(reverseString(A), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string A is not within base/radix");
            }

            c = c.add(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            // Convert c to sting using radix and length m
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());

            A = B;
            B = C;
        }
        
        return A+B;
    }

    /* convenience method to override tweak */
    public String decrypt(String ciphertext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = hexStringToByteArray(tweak);
        return decrypt(ciphertext);
    }

    public String decrypt(String ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        int n = ciphertext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Make sure the given the length of tweak in bits is 64
        if (this.tweakBytes.length != TWEAK_LEN){
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 8 bytes, or 64 bits",
                    this.tweakBytes.length));
        }

        // Check if the ciphertext message is formatted in the current radix
        try {
            new BigInteger(ciphertext, this.radix);
        } catch (NumberFormatException ex) {
            throw new NumberFormatException(String.format("The plaintext is not supported in the current radix %d", this.radix));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = ciphertext.substring(0,u);
        String B = ciphertext.substring(u);

        // Split the tweak
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        
        for (byte i = (byte) (NUM_ROUNDS-1); i >= 0; --i) {
            int m;
            BigInteger c;
            byte[] W;

            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = calculateP( i, this.radix, W, A);
            reverseBytes(P);

            // Calculate S by operating on P in place
            byte[] S = this.desCipher.doFinal(P);
            reverseBytes(S);

            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);
            // Calculate c
            try {
                c = new BigInteger(reverseString(B), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string B is not within base/radix");
            }

            c = c.subtract(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            // Convert c to sting using radix and length m
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());

            B = A;
            A = C;
        }
        return A+B;
    }

    protected static byte[] calculateP(int i, int radix, byte[] W, String B) {

        byte[] P = new byte[BLOCK_SIZE];     // P is always 16 bytes, zero initialized

        // Calculate P by XORing W, i into the first 4 bytes of P
        // i only requires 1 byte, rest are 0 padding bytes
        // Anything XOR 0 is itself, so only need to XOR the last byte

        P[0] = W[0];
        P[1] = W[1];
        P[2] = W[2];
        P[3] = (byte) (W[3] ^ i);

        // The remaining 12 bytes of P are copied from reverse(B) with padding

        B = reverseString(B);
        byte[] bBytes = new BigInteger(B, radix).toByteArray();
    
        return P;
    }

    protected static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    protected void reverseBytes(byte[] b) {
        for(int i=0; i<b.length/2; i++){
            byte temp = b[i];
            b[i] = b[b.length -i -1];
            b[b.length -i -1] = temp;
        }
    }

    protected static byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length()/2];
        for(int i=0;i < s.length();i+=2) {
            data[i/2] = (Integer.decode("0x"+s.charAt(i)+s.charAt(i+1))).byteValue();
        }
        return data;
    }

    protected static String byteArrayToHexString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            String aByte = String.format("%02X", b);
            sb.append(aByte);
        }
        return sb.toString();
    }
    protected static String byteArrayToIntString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (byte b : byteArray) {
            // cast signed byte to int and mask for last byte
            String aByte = String.format("%d ", ((int) b) & 0xFF);
            sb.append(aByte);
        }
        sb.append(']');
        return sb.toString();
    }


    public static int DOMAIN_MIN =  1000000; 
    public static int NUM_ROUNDS =   8;
    public static int BLOCK_SIZE =   16;      
    public static int TWEAK_LEN =    8;       
    public static int HALF_TWEAK_LEN = TWEAK_LEN/2;
    public static int MAX_RADIX =    36;      // BigInteger supports radix 2..36
    private final int radix;
    private byte[] tweakBytes;
    private final int minLen;
    private final int maxLen;
    private final Cipher desCipher;
}