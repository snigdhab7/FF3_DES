package FPE;

import java.util.Scanner;

public class FF3 {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			Scanner sc= new Scanner(System.in); 
			String pt,key,tweak;
			key="AABB09182736CCDD";
			tweak="1234567899876543";
			int radix=10;
			FF3_Cipher c=new FF3_Cipher(key,tweak,radix);
			System.out.println("-------------------FF3 using DES--------------------");
			System.out.print("Please enter text to encrypt: ");  
			pt= sc.nextLine();          
			//pt="8123452172926780";  // Uncomment to use default i.e. not take user input
			String ciphertext=c.encrypt(pt);
			System.out.print("After enryption- ciphertext: ");
			System.out.println(ciphertext);
			String plaintext = c.decrypt(ciphertext);
			System.out.print("After decryption- plaintext: ");
			System.out.println(plaintext);
		}catch(Exception e) {
			System.out.println(e);
		}

	}

}
