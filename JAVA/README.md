
# JAVA

** Contents: **

* Day 1: 
	* LFSR
		* [LFSR](#day-1---lfsr)

String & Values
1. [Strings | Hex | Bas64 conversion | byte[] to String | String to byte[] | Correct way to equal strings](#Link)

Day 2: 
Collections and Bitset
3. [Certificate Class | Clone | Array of PublicKeys](#Link)

Crypto
3. [Provider | getProvider()](#Link)
3. [Provider | loadProvider()](#Link)
3. [With bytes | getSecureRandom()](#Link)
3. [With bytes & seed | getSecureRandom()](#Link)
3. [HASH | SHA1 | MESSAGE DIGEST](#Link)
3. [HASH | MD5 | MESSAGE DIGEST](#Link)

Files
3. [Managing File System](#Link)
3. [Create text file](#Link)
3. [Write text file](#Link)
3. [Read text file](#Link)
3. [Write binary file](#Link)
3. [Read binary file](#Link)
3. [Binary files with the legacy Random Access File class](#Link)


Day 3: 
HMAC & PBKDF
3. [HMAC | getHmac()](#Link)
3. [HMAC | getFileHmac()](#Link)
3. [HMAC | getPBKDF()](#Link)
3. [HASH | getHash() | MESSAGE DIGEST](#Link)

OTP
3. [KeyGenerator (based on secretSeed and SHA1PRNG)](#Link)
3. [OTP | encryptFile() | decryptFile()](#Link)
3. [OTP | decryptFile (.otp, .key, .txt) / decryptFile (.otp, .txt, .txt): Getting the key here.](#Link)
3. [HASH | getHash() | MESSAGE DIGEST](#Link)

SYMMETRIC
3. [ECB | Encrypt / Decrypt](#Link)
3. [CBC | Encrypt / Decrypt](#Link)
3. [CTR | Encrypt / Decrypt](#Link)
3. [CTS | Encrypt / Decrypt](#Link)

Day 4: 
ASYMMETRIC
3. [getHexString()](#Link)
3. [getKeyStore()](#Link)
3. [listKeyStore()](#Link)
3. [getPublicKey (publicKey from KeyStore)](#Link)
3. [getPrivateKey (privateKey from KeyStore)](#Link)
3. [getCertificateKey (publicKey from Certificate)](#Link)
3. [randomAESKey / generateKey(128): AES Random Key](#Link)
3. [Asymmetric Cipher: RSA Encrypt (publicKey + AES input (or any input in byte[])) / encrypt()](#Link)
3. [Asymmetric Cipher: RSA Decrypt (privateKey + AES input (or any input in byte[])) / decrypt()](#Link)
3. [Generate a DIGITAL SIGNATURE (RSA) for a file with a private key (from the keystore) / signFile()](#Link)
3. [Validate the DIGITAL SIGNATURE with the public key (from the certificate) / hasValidSignature()](#Link)

## Day 1 - LFSR:

**LFSR Class**
```
package ro.ase.ism.sap.day1;

//implement a LFSR based on the x^31 + x^7 + x^5 + x^3 + x^2 + x + 1
public class LFSR {
	byte[] register = new byte[4];
	
	public void init(byte[] seed) {
		if(seed.length != 4) {
			throw new UnsupportedOperationException("Seed size is wrong");
		}
		else {
			for(int i = 0; i < 4; i++) {
				this.register[i] = seed[i];
			}
		}
	}
	
	//index from 0 to 31
	private byte getBitAtIndex(int index) {
		if(index < 0 || index  > 31) {
			throw new UnsupportedOperationException("Wrong index");
		}
		
		int byteIndex = 3 - (index / 8);
		int bitIndex = index % 8;
		
		byte bitMask = (byte) (1 << bitIndex);
		
		return (byte) ((this.register[byteIndex] & bitMask) >> bitIndex);
	}
	
	//input is 0 or 1
	//index is 0 -> 3
	private byte shiftWithInsertRegisterByte(byte input, int index) {
		byte registerByte = this.register[index];
		
		byte outBit = (byte) (registerByte & 1);
		registerByte = (byte) ((registerByte & 0xFF) >> 1);
		registerByte = (byte) (registerByte | (input << 7));
		
		this.register[index] = registerByte;
		
		return outBit;
	}
	
	private byte doStep() {
		byte xorResult = (byte) (getBitAtIndex(31) ^ getBitAtIndex(7) ^ 
				getBitAtIndex(5) ^ getBitAtIndex(3) ^ 
				getBitAtIndex(2) ^ getBitAtIndex(1) ^
				getBitAtIndex(0));
		
		byte tempBit = shiftWithInsertRegisterByte(xorResult, 0);
		tempBit = shiftWithInsertRegisterByte(tempBit, 1);
		tempBit = shiftWithInsertRegisterByte(tempBit, 2);
		byte resultBit = shiftWithInsertRegisterByte(tempBit, 3);
		
		return resultBit;
	}
	
	public byte getRandomByte() {
		byte result = 0;
		for(int i = 0; i < 8; i++) {
			result = (byte) (result << 1);
			byte randomBit = this.doStep();	//1 or 0
			result = (byte) (result | randomBit);
		}
		return result;
	}
}
```


### MAIN: DAY 1 LFSR
```
package ro.ase.ism.sap.day1;

public class Test {

	public static void main(String[] args) {
		
		byte value = 0b0001_0111;
		
		System.out.println("The value is "  + value);
		
		//shift to left
		value = (byte) (value << 2);
		System.out.println("The value is "  + value);
		
		value = (byte) (value << 1);
		System.out.println("The value is "  + value);
		
		//value is now 1011_1000
		
		//we get 10000000_00000000_..._00111000
		int intValue = (int) value;
		
		//unsigned shift to right
		//temporary we get an int with  00000000_00000000_..._10111000
		value = (byte) ((value & 0xFF) >> 1);
		System.out.println("The value is "  + value);
		
		System.out.println("Demo");
		for(int i = 0; i < 36; i++) {
			System.out.println("The value is "  + (value >> i));	
		}
		
		//how to check and get bit values
		byte keyByte = (byte) 0b1010_0010;
		
		//check if the 4th bit from left to right is 1
		byte _4thBitMask = 0b0001_0000; //1 << 4;
		
		if((keyByte & _4thBitMask) == 0) {
			System.out.println("The 4th bit is zero");
		} else {
			System.out.println("The 4th bit is one");
		}
		
		byte _4thBitValue = (byte) (keyByte & _4thBitMask);
		
		
		//implement a LFSR based on the x^32 + x^7 + x^5 + x^3 + x^2 + x + 1
		LFSR lfsr = new LFSR();
		byte[] seed = {10,20,30,40};
		lfsr.init(seed);
		
		for(int i = 0 ; i < 10; i++) {
			byte randomByte = lfsr.getRandomByte();
			System.out.println("random byte is " + randomByte);
		}
		
	}

}

```


## Day 1 - STRING AND VALUES:

### MAIN: DAY 1 STRING AND VALUES
```
package ro.ase.ism.sap.day1;

import java.util.Base64;

public class Test {
	
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format("%02X", b));
		}
		return result.toString();
	}

	public static void main(String[] args) {

		String filename = "Message.txt";
		String anotherFile = "Message.txt";
		
		//wrong way
		if(filename == anotherFile) {
			System.out.println("They are equal");
		} else {
			System.out.println("They are different");
		}
		
		
		anotherFile = new String("Message.txt");
		if(filename == anotherFile) {
			System.out.println("They are equal");
		} else {
			System.out.println("They are different");
		}
		
		//correct way with equals
		anotherFile = new String("Message.txt");
		if(filename.equals(anotherFile)) {
			System.out.println("They are equal");
		} else {
			System.out.println("They are different");
		}
		
		filename = "Message.enc";
		System.out.println("Filename  = " + filename);
		System.out.println("Other Filename  = " + anotherFile);
		
		int value1 = 23;
		Integer iObject1 = 23; //managed by a Constant Pool of numbers up to 127
		Integer iObject2 = 23;
		
		if(iObject1 == iObject2) {
			System.out.println("The numbers are equal");
		} else {
			System.out.println("The numbers are different");
		}
		
		iObject1 = 230;
		iObject2 = 230;
		
		if(iObject1.equals(iObject2)) {
			System.out.println("The numbers are equal");
		} else {
			System.out.println("The numbers are different");
		}
		
		//converting strings to byte arrays and reverse
		String password = "12345678";
		char c = 'a';		//2 bytes
		byte b = 1;			//1 byte value
		
		byte[] passwordAsByteArray = password.getBytes();
		System.out.println("Password size is " + passwordAsByteArray.length);
		
		
		//only if we know for sure that the values was obtained from a String
		String oldPassword = new String(passwordAsByteArray);
		System.out.println("The password is " + oldPassword);
		
		//printing byte arrays with different encodings
		//hex
		byte[] randomKey = {10,0,1,23,100,120,0,2};
		
		//let's break the value converting it to string
		//don't convert it to string
		password = new String(randomKey);
		
		System.out.println("The pass is " + password);
		byte[] initialKey = password.getBytes();
		for(byte bvalue : initialKey) {
			System.out.println("The byte is " + bvalue);
		}
		
		byte[] newRandomKey = {10,0,2,23,100,120,0,2};
		String newRandomPassword = new String(newRandomKey);
		
		System.out.println("The new pass is " + newRandomPassword);
		
		if(newRandomPassword.equals(password)) {
			System.out.println("They are equal");
		}
		else {
			System.out.println("They are different");
		}
		
		//hexadecimal representation
		System.out.println(String.format("Hex value of 30 is 0x%02x", 30));
		
		System.out.println("Hex value of binary key is " + 
				getHexString(newRandomKey));
		
		//base64 
		String base64Password = Base64.getEncoder().encodeToString(newRandomKey);
		System.out.println("The binary pass as base64 is " + base64Password);
		
		byte[] oldPasswordValue = Base64.getDecoder().decode(base64Password);
		
		System.out.println("Hex value of binary key is " + 
				getHexString(oldPasswordValue));
		
		//define numbers and bytes
		byte byteValue = 23;
		byteValue = 0b00010111;	//still 23
		byteValue = 0b0001_0111;//still 23
		byteValue = 0x17; //still 23
		byteValue = 1 << 4 | 1 << 2 | 1 << 1 | 1; //still 23
		
		System.out.println("Value is " + byteValue);
		
		//shifting values
		byteValue = (byte) (byteValue << 2);
		System.out.println("Value is " + byteValue);
		
		byteValue = (byte) (byteValue << 1);
		System.out.println("Value is " + byteValue); //sign bit is 1
		
		/*
		 * byteValue = (byte) (byteValue >> 1); System.out.println("Value is " +
		 * byteValue);
		 */
		
		int intValue = (int)byteValue;
		System.out.println("Int Value is " + intValue); 
		
		byteValue = (byte) (byteValue >>> 1);  //does not work on byte
		System.out.println("Value is * " + byteValue);
		
		//check the first/sign bit
		boolean isNegative = ((byteValue & (1 << 7)) == 0 ? false : true);
		
		if(isNegative)
			byteValue -= 0b1000_0000;
		
		System.out.println("Value is " + byteValue);
		
		intValue = intValue >>> 1;	//works on int values - unsigned right shift
		System.out.println("Int Value is " + intValue); 
	}

}

```


## Day 2 - COLLECTIONS AND BITSET:

**Certificate CLASS (create a certificate, clone, hashcode it, array of PublicKeys)**
```
package ro.ase.ism.sap.day2;

import java.util.ArrayList;
import java.util.List;

public class Certificate {
	String name;
	String organization;
	String country;
	String signature;
	
	ArrayList<Byte> publicKey = new ArrayList<>(128);
	
	public Certificate(String name, String organization, String country, String signature) {
		super();
		this.name = name;
		this.organization = organization;
		this.country = country;
		this.signature = signature;
	}
	
	@Override
	public String toString() {
		return this.name + " with signature " + this.signature;
	}

	@Override
	public int hashCode() {
		return this.signature.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		
		if(!(obj instanceof Certificate)) {
			return false;
		}
		
		Certificate other = (Certificate) obj;
		
		return this.name.equals(other.name) && 
				this.signature.equals(other.signature);
	}

	@Override
	protected Object clone() throws CloneNotSupportedException {
		Certificate copy = 
				new Certificate(name, organization, country, signature);
		
		//don't do the shallow copy
		//copy.publicKey = this.publicKey;
		
		//do deep-copy
		copy.publicKey = 
				(ArrayList<Byte>) this.publicKey.clone();
		//alternative
		//copy.publicKey = new ArrayList<>(this.publicKey);
		
		return copy;
	}
	
	
	
	
}
```

### MAIN: DAY 2 COLLECTIONS AND BITSET
```
package ro.ase.ism.sap.day2;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Test {
	
	

	public static void main(String[] args) {
		
		BitSet bitSet = new BitSet(32);
		bitSet.set(0); //set to 1 the 1st bit from left to right
		bitSet.set(1, false); //set to 0 the 2nd bit
		
		if(bitSet.get(0)) {
			System.out.println("1st bit is 1");
		}
		else {
			System.out.println("1st bit is 0");
		}
		
		byte seed = (byte) 0b1100_1100;
		for(int i = 0; i < 8; i++) {
			byte mask = (byte) (1 << (7 - i));
			bitSet.set(i, ((seed & mask) != 0));
		}
		
		System.out.println("Bitset:");
		for(int i = 0; i < bitSet.size(); i++) {
			System.out.print(bitSet.get(i) ? 1 : 0);
		}
		
		//3 types of collections
		//List - like a dynamic array
		//Set - like a dynamic array with UNIQUE values
		//Map - like a dictionary with UNIQUE keys
		
		List<Integer> values = new ArrayList<>();
		values.add(23);
		values.add(56);
		values.add(22);
		values.add(56);
		
		System.out.println();
		for(int value : values) {
			System.out.println("List value is " + value);
		}
		
		Set<Integer> uniqueValues = new HashSet<>();
		uniqueValues.add(23);
		uniqueValues.add(56);
		uniqueValues.add(22);
		uniqueValues.add(56);
		
		for(int value : uniqueValues) {
			System.out.println("Unique List value is " + value);
		}
		
		Map<Integer, String> users = new HashMap<>();
		users.put(1, "John");
		users.put(3, "Alice");
		users.put(10, "Bob");
		users.put(1, "Vader");
		
		String username = users.get(10);
		if(username != null) {
			System.out.println("User is " + username);
		}
		else {
			System.out.println("No usee with id 10");
		}
		
		for(Integer key : users.keySet()) {
			System.out.println("User " + users.get(key) + " with id " + key);
		}
		
		//collections and defined models
		Set<Certificate> certificates = new HashSet<>();
		
		certificates.add(
				new Certificate("John", "ISM", "RO", "A312B5AD"));
		certificates.add(
				new Certificate("John", "ISM", "RO", "A312B5AD"));
		
		for(Certificate certificate : certificates) {
			System.out.println(certificate.toString()); 
		}
		
	}

}
```

## Day 2 - CRYPTO:

**Provider | getProvider()**
```

		//test if a provider is available
		
		//String providerName = "SUN";
		String providerName = "BC";
		
		Provider provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
		
```

**Load a provider at runtime - BouncyCastle**

```

		//load a provider at runtime - BouncyCastle
		if(provider == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
```

**getSecureRandom | with bytes**
```
	public static byte[] getSecureRandom(int size) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
```

**getSecureRandom | with bytes & seed**
```
	public static byte[] getSecureRandom(int size, byte[] seed) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		secureRandom.setSeed(seed);
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
```

**HASH | SHA1 | MESSAGE DIGEST**
```
	public static byte[] getMessageDigest(String input) throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		//use Bouncy Castle
		//MessageDigest md = MessageDigest.getInstance("SHA-1","BC");
		
		//compute the hash in one step
		return md.digest(input.getBytes());
		
		//alternative
		//md.update(input.getBytes());
		//return md.digest();
	}
```

**HASH | MD5 | MESSAGE DIGEST**
```
	public static byte[] getMessageDigest(String input) throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		//use Bouncy Castle
		//MessageDigest md = MessageDigest.getInstance("SHA-1","BC");
		
		//compute the hash in one step
		return md.digest(input.getBytes());
		
		//alternative
		//md.update(input.getBytes());
		//return md.digest();
	}
```

### MAIN: DAY 2 CRYPTO
```
package ro.ase.ism.sap.day2;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//test if a provider is available
		
		//String providerName = "SUN";
		String providerName = "BC";
		
		Provider provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
		
		
		//load a provider at runtime - BouncyCastle
		if(provider == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
		
		//test the Secure Random
		byte[] randomBytes = RandomGenerator.getSecureRandom(16);
		System.out.println("Secure random bytes");
		System.out.println(Util.getHexString(randomBytes));
		
		byte[] seed = {0x01, 0x02, 0x03};
		randomBytes = RandomGenerator.getSecureRandom(16, seed);
		System.out.println("Secure random bytes");
		System.out.println(Util.getHexString(randomBytes));
		
		//test hash algorithms
		byte[] hash = Hash.getMessageDigest("Hello! How are you ?");
		System.out.println("SHA1: ");
		System.out.println(Util.getHexString(hash));
		
		byte[] fileHash = Hash.getFileMessageDigest("message.txt", "MD5", "BC");
		System.out.println("File MD5: ");
		System.out.println(Util.getHexString(fileHash));
	}

}
```

## Day 2 - FILES:

**Managing File System** 
```

		//managing the file system
		File location = new File("D:\\2023-2024\\sap-2023");
		if(!location.exists()) {
			throw new UnsupportedOperationException("FOLDER is not there");
		}
		
		File tempFolder = 
				new File(location.getAbsolutePath() + 
						File.separator + 
						"temp");
		
		if(!tempFolder.exists()) {
			tempFolder.mkdir();
		}
			
		File[] files =  location.listFiles();
		for(File file : files) {
			System.out.println(file.getName());
			if(file.isDirectory()) {
				System.out.println(" --- is a folder");
			} else {
				System.out.println(" --- is a file");
			}
		}
```

**Create text file** 
```
	
		File messageTextFile = new File("message.txt");
		if(!messageTextFile.exists()) {
			messageTextFile.createNewFile();
		}
```

**Text File (write)** 
```
	
		//writing into text files
		FileWriter fileWriter = new FileWriter(messageTextFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println("Hello !");
		printWriter.println("This is a secret message.");
		
		printWriter.close();
```

**Text File (read)** 
```
	
		//reading from text files
		FileReader fileReader = new FileReader(messageTextFile);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		
		String line;
		while((line = bufferedReader.readLine()) != null) {
			System.out.println("File line: " + line);
		} 		
		bufferedReader.close();

```

**Binary File (write)** 
```
	//writing into binary files
		File dataFile = new File("mydata.dat");
		if(!dataFile.exists()) {
			dataFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(dataFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		DataOutputStream dos = new DataOutputStream(bos);
		
		dos.writeFloat(23.5f);
		dos.writeInt(23);
		dos.writeBoolean(true);
		dos.writeUTF("Hello");
		byte[] values = {0x0A, 0x0B};
		dos.writeInt(values.length);
		dos.write(values);
		dos.close();

```

**Binary File (read)** 
```
        FileInputStream fis = new FileInputStream(dataFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DataInputStream dis = new DataInputStream(bis);
		
		float floatValue = dis.readFloat();
		int value = dis.readInt();
		boolean logicValue = dis.readBoolean();
		String stringValue = dis.readUTF();
		int byteArraySize = dis.readInt();
		byte[] byteValues = new byte[byteArraySize];
		dis.read(byteValues, 0, byteArraySize);
		
		
		System.out.println("Float value is " + floatValue);
		System.out.println("Int value is " + value);
		System.out.println("String value is " + stringValue);
		
		dis.close();

```

**Binary files with the legacy Random Access File class** 
```
        FileInputStream fis = new FileInputStream(dataFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DataInputStream dis = new DataInputStream(bis);
		
		float floatValue = dis.readFloat();
		int value = dis.readInt();
		boolean logicValue = dis.readBoolean();
		String stringValue = dis.readUTF();
		int byteArraySize = dis.readInt();
		byte[] byteValues = new byte[byteArraySize];
		dis.read(byteValues, 0, byteArraySize);
		
		
		System.out.println("Float value is " + floatValue);
		System.out.println("Int value is " + value);
		System.out.println("String value is " + stringValue);
		
		dis.close();

```

### MAIN: DAY 2 FILES
```
package ro.ase.ism.sap.day2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;

public class Test {

	public static void main(String[] args) throws IOException {
		
		//managing the file system
		File location = new File("D:\\2023-2024\\sap-2023");
		if(!location.exists()) {
			throw new UnsupportedOperationException("FOLDER is not there");
		}
		
		File tempFolder = 
				new File(location.getAbsolutePath() + 
						File.separator + 
						"temp");
		
		if(!tempFolder.exists()) {
			tempFolder.mkdir();
		}
			
		File[] files =  location.listFiles();
		for(File file : files) {
			System.out.println(file.getName());
			if(file.isDirectory()) {
				System.out.println(" --- is a folder");
			} else {
				System.out.println(" --- is a file");
			}
		}
		
		//text files
		File messageTextFile = new File("message.txt");
		if(!messageTextFile.exists()) {
			messageTextFile.createNewFile();
		}
		
		
		//writing into text files
		FileWriter fileWriter = new FileWriter(messageTextFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println("Hello !");
		printWriter.println("This is a secret message.");
		
		printWriter.close();
		
		//reading from text files
		FileReader fileReader = new FileReader(messageTextFile);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		
		String line;
		while((line = bufferedReader.readLine()) != null) {
			System.out.println("File line: " + line);
		} 		
		bufferedReader.close();
		
		
		//binary files
		//writing into binary files
		File dataFile = new File("mydata.dat");
		if(!dataFile.exists()) {
			dataFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(dataFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		DataOutputStream dos = new DataOutputStream(bos);
		
		dos.writeFloat(23.5f);
		dos.writeInt(23);
		dos.writeBoolean(true);
		dos.writeUTF("Hello");
		byte[] values = {0x0A, 0x0B};
		dos.writeInt(values.length);
		dos.write(values);
		dos.close();
		
		//read from a binary file
		FileInputStream fis = new FileInputStream(dataFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DataInputStream dis = new DataInputStream(bis);
		
		float floatValue = dis.readFloat();
		int value = dis.readInt();
		boolean logicValue = dis.readBoolean();
		String stringValue = dis.readUTF();
		int byteArraySize = dis.readInt();
		byte[] byteValues = new byte[byteArraySize];
		dis.read(byteValues, 0, byteArraySize);
		
		
		System.out.println("Float value is " + floatValue);
		System.out.println("Int value is " + value);
		System.out.println("String value is " + stringValue);
		
		dis.close();
		
		//binary files with the legacy Random Access File class

		RandomAccessFile raf = new RandomAccessFile(dataFile, "rw");
		values = new byte[]{0x0a, 0x0b, 0x0c};
		for(byte v: values) {
			raf.writeByte(v);
		}
		
		//move to the beginning og the file
		raf.seek(0);
		byte byteValue = raf.readByte();
		
		System.out.println("First byte " + byteValue);
		
		raf.seek(2);
		byteValue = raf.readByte();
		
		System.out.println("Last byte " + byteValue);
		
		raf.close();
	}

}
```






## Day 3 - HMAC & PBKDF:

> HMAC is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It is commonly used to verify the integrity and authenticity of a message. HMAC involves hashing the message and then combining it with a secret key in a specific way.
> PBKDF is a family of functions designed to derive cryptographic keys from a password. It adds computational cost to the process, making it more resistant to brute-force attacks.


**HMAC - getHmac** 
```
	public static byte[] getHmac(String input, String secret, String algorithm) 
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac hmac = Mac.getInstance(algorithm);
		Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
		hmac.init(hmacKey);
		
		return hmac.doFinal(input.getBytes());
	}

```

**HMAC - getFileHmac** 
```

	public static byte[] getFileHmac(
			String filename, String secret, String algorithm)
					throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		File file = new File(filename);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		Mac hmac = Mac.getInstance(algorithm);
		Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
		hmac.init(hmacKey);
		
		byte[] buffer = new byte[16];
		int noBytes = 0;
		
		while(true) {
			noBytes = bis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			hmac.update(buffer, 0, noBytes);
		}
		
		bis.close();
		
		return hmac.doFinal();
		
	}
```

**PBKDF - getPBKDF** 
```
	public static byte[] getPBKDF(
			String userPassword, 
			String algorithm,
			String salt,
			int noIterations
			) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		SecretKeyFactory pbkdf = 
				SecretKeyFactory.getInstance(algorithm);
		PBEKeySpec pbkdfSpecifications = 
				new PBEKeySpec(
						userPassword.toCharArray(), 
						salt.getBytes(), 
						noIterations,256);
		SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
		return secretKey.getEncoded();
		
	}
```


**HASH** 
```
	public static byte[] getHash(String input, String algorithm) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		return md.digest(input.getBytes());
	}
```

### MAIN: DAY 3 HMAC & PBKDF
```

    package ro.ase.ism.sap.day3;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Test {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		// test hmac
		
		byte[] hmacValue = 
				HMAC.getHmac("This is a secret !", "1234", "HmacSHA256");
		System.out.println("HMAC: ");
		System.out.println(Util.getHexString(hmacValue)); 
		
		
		hmacValue = HMAC.getFileHmac(
				"msg.txt", "12345678", "HmacMD5");
		System.out.println("File HMAC: ");
		System.out.println(Util.getHexString(hmacValue)); 
		
		// test pbkdf
		
		byte[] saltedHash = PBKDF.getPBKDF("12345678", 
				"PBKDF2WithHmacSHA256", "ism", 100);
		System.out.println("Salted hash of 12345678: ");
		System.out.println(Util.getHexString(saltedHash));
		
		//benchmark sha2 vs BKDF2WithHmacSHA256
		
		double tStart = System.currentTimeMillis();
		byte[] hashValue = Hash.getHash("12345678", "SHA-256");
		double tEnd = System.currentTimeMillis();
		
		System.out.println("SHA2 of 12345678 is ");
		System.out.println(Util.getHexString(hashValue));
		System.out.println(String.format(
				"Done in %f millis", tEnd - tStart));
		

		tStart = System.currentTimeMillis();
		saltedHash = PBKDF.getPBKDF("12345678", 
				"PBKDF2WithHmacSHA256", "ism", 15000);
		tEnd = System.currentTimeMillis();
		
		System.out.println("PBKFD SHA2 of 12345678 is ");
		System.out.println(Util.getHexString(saltedHash));
		System.out.println(String.format(
				"Done in %f millis", tEnd - tStart));
		
	}

}

```


## Day 3 - OTP (one time password):

> OTP is a security concept where a unique password is generated for each authentication session, and it is valid for only a short period. 
> This adds an extra layer of security, especially in scenarios like two-factor authentication.

**KeyGenerator (based on secretSeed and SHA1PRNG)** 
```
public class KeyGenerator {
	
	private byte[] seed;
	private String algorithm;
	SecureRandom secureRandom = null;
	
	public KeyGenerator(byte[] seed, String algo) {
		super();
		this.seed = seed;
		this.algorithm = algo;
	}

	public byte[] getRandomBytes(int noBytes) throws NoSuchAlgorithmException {
		if(secureRandom == null) {
			secureRandom = SecureRandom.getInstance(this.algorithm);
			secureRandom.setSeed(this.seed);
		}
		
		byte[] random = new byte[noBytes];
		secureRandom.nextBytes(random);
		return random;	
	}
}
```


**OTP - encryptFile / decryptFile** 
```

	public static void encryptFile(
			String inputFilename, 
			String outputFilename, 
			String keyFilename,
			KeyGenerator keyGenerator) throws IOException, NoSuchAlgorithmException {
		
		//opening the input file
		File input = new File(inputFilename);
		if(!input.exists()) {
			throw new UnsupportedOperationException("File is missing");
		}
		
		FileInputStream fis = new FileInputStream(input);
		
		//open the cipher file
		File cipher = new File(outputFilename);
		if(!cipher.exists()) {
			cipher.createNewFile();
		}
		FileOutputStream fosCipher = new FileOutputStream(cipher);
		
		//open the key file
		File key = new File(keyFilename);
		if(!key.exists()) {
			key.createNewFile();
		}
		FileOutputStream fosKey = new FileOutputStream(key);
		

		byte[] buffer = new byte[16];
		int noBytes = 0;
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] keyStream = keyGenerator.getRandomBytes(noBytes);		
			byte[] cipherStream = encryptDecrypt(
					Arrays.copyOfRange(buffer, 0, noBytes), keyStream);
			
			fosCipher.write(cipherStream);
			fosKey.write(keyStream);
		}
		fosCipher.close();
		fosKey.close();
		fis.close();
	}

    public static byte[] encryptDecrypt(byte[] input, byte[] key) {
		if(input.length != key.length) {
			throw new UnsupportedOperationException("Different key size!");
		}
		byte[] output = new byte[input.length];
		for(int i = 0;i < input.length; i++) {
			output[i] = (byte) (input[i] ^ key[i]);
		}
		return output;
	}

```


**OTP - decryptFile (.otp, .key, .txt) / decryptFile (.otp, .txt, .txt): Getting the key here.** 
```

	public static void decryptFile(
			String cipherFilename, String keyFilename, String outputFilename) throws IOException {
		File cipher = new File(cipherFilename);
		File key = new File(keyFilename);
		if(!cipher.exists() || !key.exists()) {
			throw new UnsupportedOperationException("Missing input files");
		}
		
		File output = new File(outputFilename);
		if(!output.exists()) {
			output.createNewFile();
		}
		
		FileInputStream cipherStream = new FileInputStream(cipher);
		FileInputStream keyStream = new FileInputStream(key);
		FileOutputStream outputStream = new FileOutputStream(output);
		
		byte[] cipherBuffer = new byte[16];
		byte[] keyBuffer = new byte[16];
		
		while(true) {
			int noCipherBytes = cipherStream.read(cipherBuffer);
			int noKeyBytes = keyStream.read(keyBuffer);
			if(noCipherBytes == -1 || noKeyBytes == -1) {
				break;
			}
			if(noCipherBytes < noKeyBytes) {
				noKeyBytes = noCipherBytes;
			} else {
				noCipherBytes = noKeyBytes;
			}
			
			byte[] outputBuffer = encryptDecrypt(
					Arrays.copyOfRange(cipherBuffer, 0, noCipherBytes),
					Arrays.copyOfRange(keyBuffer, 0, noKeyBytes));
			
			outputStream.write(outputBuffer);
		}
		
		outputStream.close();
		keyStream.close();
		cipherStream.close();
		
	}
	
```



### MAIN: DAY 3 OTP
```
package ro.ase.ism.sap.day3;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		
		String secretSeed = "randomKEY1234";
		KeyGenerator keyGenerator = new KeyGenerator(
				secretSeed.getBytes(), "SHA1PRNG");
		
		OTP.encryptFile("msg.txt", "msg.otp", "secretkey.key",keyGenerator);
		OTP.decryptFile("msg.otp", "secretkey.key", "msg2.txt");
		
		
		//you get the key
		OTP.decryptFile("msg.otp", "msg.txt", "key.txt");
		
		System.out.println("Done");
	}

}

```

## Day 3 - SYMMETRIC:

**ECB Encrypt / Decrypt** 
```

	public static void encrypt(
			String filename, String cipherFilename, String password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static void decrypt(
			String filename, String outputFilename, String password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(outputFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		
		cipher.init(Cipher.DECRYPT_MODE, key);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();	
	}
```

**CBC Encrypt / Decrypt** 
```

	public static void encrypt(
			String filename, 
			String cipherFilename, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV is known/generated and placed in the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//IV has the 5th byte from left to right all bits 1
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[4] = (byte) 0xFF;
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		//write the IV in the file
		fos.write(IV);
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static void decrypt(
			String filename, 
			String outputFile, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File outFile = new File(outputFile);
		if(!outFile.exists()) {
			outFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//getting the IV from the file
		byte[] IV = new byte[cipher.getBlockSize()];
		fis.read(IV);
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}

```

**CTR Encrypt / Decrypt** 
```

	public static void encrypt(
			String filename, 
			String cipherFilename, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV is known/generated and placed in the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CTR/NoPadding");
		
		//IV has the 5th byte from left to right all bits 1
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[4] = (byte) 0xFF;
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		//write the IV in the file
		fos.write(IV);
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static void decrypt(
			String filename, 
			String outputFile, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File outFile = new File(outputFile);
		if(!outFile.exists()) {
			outFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CTR/NoPadding");
		
		//getting the IV from the file
		byte[] IV = new byte[cipher.getBlockSize()];
		fis.read(IV);
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}

```

**CTS Encrypt / Decrypt** 
```

	public static void encrypt(
			String filename, 
			String cipherFilename, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV is known/generated and placed in the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CTS/NoPadding");
		
		//IV has is all 1s
		byte[] IV = new byte[cipher.getBlockSize()];
		/*
		 * for(int i = 0; i < IV.length; i++) { IV[i] = (byte) 0xFF; }
		 */
		Arrays.fill(IV, (byte)0xFF);
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static void decrypt(
			String filename, 
			String outputFile, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File outFile = new File(outputFile);
		if(!outFile.exists()) {
			outFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CTS/NoPadding");
		
		//IV has is all 1s
		byte[] IV = new byte[cipher.getBlockSize()];
		Arrays.fill(IV, (byte)0x0F);
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}

```

### MAIN: DAY 3 SYMMETRIC
```
package ro.ase.ism.sap.day3;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Test {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {
		
		
		//test ECB
		
		CipherECB.encrypt("msg.txt", "msg.enc", "password12345678", "AES");
		
		//example with a 256 bit key but with a block size of 128 bits
		//CipherECB.encrypt("msg.txt", "msg.enc", "password12345678password12345678", "AES");
		
		CipherECB.decrypt("msg.enc", "msg2.txt", "password12345678", "AES");
		
		//test CBC
		CipherCBC.encrypt("msg.txt", "msgCBC.enc", "password12345678", "AES");
		CipherCBC.decrypt("msgCBC.enc", "msg3.txt", "password12345678", "AES");
		
		System.out.println("Done.");
		
		//test CTR
		CipherCTR.encrypt("msg.txt", "msgCTR.enc", "password12345678", "AES");
		CipherCTR.decrypt("msgCTR.enc", "msg4.txt", "password12345678", "AES");
	
		//test CTS
		CipherCTS.encrypt("msg.txt", "msgCTS.enc", "password12345678", "AES");
		CipherCTS.decrypt("msgCTS.enc", "msg5.txt", "password12345678", "AES");
		
	}

}
```



## Day 4 - ASYMMETRIC:

**getHexString** 
```
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}
```

**getKeyStore** 

```
	public static KeyStore getKeyStore(
			String keyStoreFile,
			String keyStorePass, 
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		File file = new File(keyStoreFile);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing key store file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		
		KeyStore ks = KeyStore.getInstance(keyStoreType);
		ks.load(fis, keyStorePass.toCharArray());
		
		fis.close();
		return ks;
	}
```

**listKeyStore** 

```
KeyStoreManager.list(ks);

	public static void list(KeyStore ks) throws KeyStoreException {
		System.out.println("Key store content: ");
		Enumeration<String> aliases = ks.aliases();
		
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			System.out.println("Entry: " + alias);
			if(ks.isCertificateEntry(alias)) {
				System.out.println("-- Is a certificate");
			}
			if(ks.isKeyEntry(alias)) {
				System.out.println("-- Is a key pair");
			}
		}
	}
```

**getPublicKey (publicKey from KeyStore)** 

```
	public static PublicKey getPublicKey(String alias, KeyStore ks) throws KeyStoreException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return ks.getCertificate(alias).getPublicKey();
		} else {
			return null;
		}
	}
```

**getPrivateKey (privateKey from KeyStore)** 

```
	public static PrivateKey getPrivateKey(
			String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
		} else {
			return null;
		}
	}
```

**getCertificateKey (publicKey from certificate)** 

```
	public static PublicKey getCertificateKey(String certificateFile) throws CertificateException, IOException {
		File file = new File(certificateFile);
		if(!file.exists()) {
			throw new UnsupportedOperationException("****Missing file****");
		}
		FileInputStream fis = new FileInputStream(file);
		
		CertificateFactory certFactory = 
				CertificateFactory.getInstance("X.509");
		X509Certificate certificate = 
				(X509Certificate) certFactory.generateCertificate(fis);
		fis.close();
		return certificate.getPublicKey();	
	}
```

**randomAESKey / generateKey(128): AES Random Key** 
```
	public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = 
				KeyGenerator.getInstance("AES");
		keyGenerator.init(noBytes);
		return keyGenerator.generateKey().getEncoded();
	}
```

**Asymmetric Cipher: RSA Encrypt (publicKey + AES input (or any input in byte[])) / encrypt()** 

```
	public static byte[] encrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
```


**Asymmetric Cipher: RSA Decrypt (privateKey + AES input (or any input in byte[])) / decrypt()** 

```
	public static byte[] decrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(input);
	}
```


**Generate a DIGITAL SIGNATURE (RSA) for a file with a private key (from the keystore) / signFile()** 

```
	public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fis = new FileInputStream(file);
		
		byte[] fileContent = fis.readAllBytes();
		
		fis.close();
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		
		signature.update(fileContent);
		return signature.sign();		
	}
```

**Validate the DIGITAL SIGNATURE with the public key (from the certificate) / hasValidSignature()** 

```
	public static boolean hasValidSignature(
			String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		
		FileInputStream fis = new FileInputStream(file);	
		byte[] fileContent = fis.readAllBytes();	
		fis.close();
		
		Signature signatureModule = Signature.getInstance("SHA256withRSA");
		signatureModule.initVerify(key);
		
		signatureModule.update(fileContent);
		return signatureModule.verify(signature);
		
	}
```


### MAIN: DAY 4 ASYMMETRIC

```
package ro.ase.ism.sap.day4;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Test {
	
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {

		KeyStore ks = KeyStoreManager.getKeyStore(
				"ismkeystore.ks", "passks", "pkcs12");
		KeyStoreManager.list(ks);
		
		PublicKey pubIsm1 = KeyStoreManager.getPublicKey("ismkey1", ks);
		PrivateKey privIsm1 = KeyStoreManager.getPrivateKey("ismkey1", "passks", ks);
		
		System.out.println("Public key:");
		System.out.println(getHexString(pubIsm1.getEncoded()));
		System.out.println("Private key");
		System.out.println(getHexString(privIsm1.getEncoded()));
		
		PublicKey pubIsm1FromCert = 
				PublicCertificate.getCertificateKey("ISMCertificateX509.cer");
		System.out.println("Public key from certificate: ");
		System.out.println(getHexString(pubIsm1FromCert.getEncoded()));
		
		//encrypt and decrypt with asymmetric ciphers - RSA
		//generate a random AES key and encrypt it with public RSA key
		//decrypt AES key with RSA private key
		
		byte[] randomAESKey = AESCipher.generateKey(128);
		System.out.println("AES Random key: ");
		System.out.println(getHexString(randomAESKey));
		
		byte[] encryptedAESKey = 
				RSACipher.encrypt(pubIsm1FromCert, randomAESKey);
		
		System.out.println("Encrypted AES key with RSA: ");
		System.out.println(getHexString(encryptedAESKey));
		
		byte[] randomAESKeyCopy = 
				RSACipher.decrypt(privIsm1, encryptedAESKey);
		System.out.println("AES Key copy: ");
		System.out.println(getHexString(randomAESKeyCopy));
		
		
		//digital signatures
		//generate a digital signature (RSA) for a file with private key
		//validate the digital signature with public key
		
		byte[] signature = 
				RSACipher.signFile("msg.txt", privIsm1);
		
		System.out.println("Digital signature value: ");
		System.out.println(getHexString(signature));
		
		if(RSACipher.hasValidSignature(
				"msg_copy.txt", pubIsm1FromCert, signature))
		{
			System.out.println("File is the original one");
		} else {
			System.out.println("File has been changed");
		}
		
		
		//using elliptic curves EC
		
	}

}
```