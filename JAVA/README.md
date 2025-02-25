
# JAVA

**Contents:**

* Day 1: 
	* LFSR
		* [LFSR](#day-1---lfsr)
	* String & Values
		* [Strings | Hex | Bas64 conversion | byte[] to String | String to byte[] | Correct way to equal strings](#main-day-1-string-and-values)
* Day 2: 
	* Collections and Bitset
		* [Certificate Class | Clone | Array of PublicKeys](#certificate-class-create-a-certificate-clone-hashcode-it-array-of-publickeys)
	* Crypto
		* [Provider | getProvider()](#provider--getprovider)
		* [Provider | loadProvider()](#load-a-provider-at-runtime---bouncycastle)
		* [With bytes | getSecureRandom()](#getsecurerandom--with-bytes)
		* [With bytes & seed | getSecureRandom()](#getsecurerandom--with-bytes--seed)
		* [HASH | SHA1 | MESSAGE DIGEST](#hash--sha1--message-digest)
		* [HASH | MD5 | MESSAGE DIGEST](#hash--md5--message-digest)
	* Files
		* [Managing File System](#managing-file-system)
		* [Create text file](#create-text-file)
		* [Write text file](#text-file-write)
		* [Read text file](#text-file-read)
		* [Write binary file](#binary-file-write)
		* [Read binary file](#binary-file-read)
		* [Binary files with the legacy Random Access File class](#binary-files-with-the-legacy-random-access-file-class)
* Day 3: 
	* HMAC & PBKDF
		* [HMAC | getHmac()](#hmac---gethmac)
		* [HMAC | getFileHmac()](#hmac---getfilehmac)
		* [HMAC | getPBKDF()](#pbkdf---getpbkdf)
		* [HASH | getHash() | MESSAGE DIGEST](#hash)
	* OTP
		* [KeyGenerator (based on secretSeed and SHA1PRNG)](#keygenerator-based-on-secretseed-and-sha1prng)
		* [OTP | encryptFile() | decryptFile()](#otp---encryptfile--decryptfile)
		* [OTP | decryptFile (.otp, .key, .txt) / decryptFile (.otp, .txt, .txt): Getting the key here.](#otp---decryptfile-otp-key-txt--decryptfile-otp-txt-txt-getting-the-key-here)
	* SYMMETRIC
		* [ECB | Encrypt / Decrypt](#ecb-encrypt--decrypt)
		* [CBC | Encrypt / Decrypt](#cbc-encrypt--decrypt)
		* [CTR | Encrypt / Decrypt](#ctr-encrypt--decrypt)
		* [CTS | Encrypt / Decrypt](#cts-encrypt--decrypt)
* Day 4: 
	* ASYMMETRIC
		* [getHexString()](#gethexstring)
		* [getKeyStore()](#getkeystore)
		* [listKeyStore()](#listkeystore)
		* [getPublicKey (publicKey from KeyStore)](#getpublickey-publickey-from-keystore)
		* [getPrivateKey (privateKey from KeyStore)](#getprivatekey-privatekey-from-keystore)
		* [getCertificateKey (publicKey from Certificate)](#getcertificatekey-publickey-from-certificate)
		* [randomAESKey / generateKey(128): AES Random Key](#randomaeskey--generatekey128-aes-random-key)
		* [Asymmetric Cipher: RSA Encrypt (publicKey + AES input (or any input in byte[])) / encrypt()](#asymmetric-cipher-rsa-encrypt-publickey--aes-input-or-any-input-in-byte--encrypt)
		* [Asymmetric Cipher: RSA Decrypt (privateKey + AES input (or any input in byte[])) / decrypt()](#asymmetric-cipher-rsa-decrypt-privatekey--aes-input-or-any-input-in-byte--decrypt)
		* [Generate a DIGITAL SIGNATURE (RSA) for a file with a private key (from the keystore) / signFile()](#generate-a-digital-signature-rsa-for-a-file-with-a-private-key-from-the-keystore--signfile)
		* [Validate the DIGITAL SIGNATURE with the public key (from the certificate) / hasValidSignature()](#validate-the-digital-signature-with-the-public-key-from-the-certificate--hasvalidsignature)
* [EXTRAS](#Extras)

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

### **Certificate CLASS (create a certificate, clone, hashcode it, array of PublicKeys)**
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

### **Provider | getProvider()**
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

### **Load a provider at runtime - BouncyCastle**

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

### **getSecureRandom | with bytes**
```
	public static byte[] getSecureRandom(int size) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
```

### **getSecureRandom | with bytes & seed**
```
	public static byte[] getSecureRandom(int size, byte[] seed) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		secureRandom.setSeed(seed);
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
```

### **HASH | SHA1 | MESSAGE DIGEST**
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

### **HASH | MD5 | MESSAGE DIGEST**
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

### **Managing File System** 
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

### **Create text file** 
```
	
		File messageTextFile = new File("message.txt");
		if(!messageTextFile.exists()) {
			messageTextFile.createNewFile();
		}
```

### **Text File (write)** 
```
	
		//writing into text files
		FileWriter fileWriter = new FileWriter(messageTextFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println("Hello !");
		printWriter.println("This is a secret message.");
		
		printWriter.close();
```

### **Text File (read)** 
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

### **Binary File (write)** 
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

### **Binary File (read)** 
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

### **Binary files with the legacy Random Access File class** 
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


### **HMAC - getHmac** 
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

### **HMAC - getFileHmac** 
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

### **PBKDF - getPBKDF** 
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


### **HASH** 
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

### **KeyGenerator (based on secretSeed and SHA1PRNG)** 
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


### **OTP - encryptFile / decryptFile** 
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


### **OTP - decryptFile (.otp, .key, .txt) / decryptFile (.otp, .txt, .txt): Getting the key here.** 
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

### **ECB Encrypt / Decrypt** 
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

### **CBC Encrypt / Decrypt** 
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

### **CTR Encrypt / Decrypt** 
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

### **CTS Encrypt / Decrypt** 
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

### **getHexString** 
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

### **getKeyStore** 

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

### **listKeyStore** 

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

### **getPublicKey (publicKey from KeyStore)** 

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

### **getPrivateKey (privateKey from KeyStore)** 

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

### **getCertificateKey (publicKey from certificate)** 

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

### **randomAESKey / generateKey(128): AES Random Key** 
```
	public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = 
				KeyGenerator.getInstance("AES");
		keyGenerator.init(noBytes);
		return keyGenerator.generateKey().getEncoded();
	}
```

### **Asymmetric Cipher: RSA Encrypt (publicKey + AES input (or any input in byte[])) / encrypt()** 

```
	public static byte[] encrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
```


### **Asymmetric Cipher: RSA Decrypt (privateKey + AES input (or any input in byte[])) / decrypt()** 

```
	public static byte[] decrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(input);
	}
```


### **Generate a DIGITAL SIGNATURE (RSA) for a file with a private key (from the keystore) / signFile()** 

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

### **Validate the DIGITAL SIGNATURE with the public key (from the certificate) / hasValidSignature()** 

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


# Extras:

1. Decrypt key.sec file using the public key extracted from provided pubISM.pem file
using OpenSSL in C++
```
#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// Function to decrypt the file using the public key
bool decryptFile(const std::string& inputFile, const std::string& outputFile, RSA* publicKey) {
    // Open the input file for reading
    std::ifstream encryptedFile(inputFile, std::ios::binary);
    if (!encryptedFile.is_open()) {
        std::cerr << "Error: Unable to open the encrypted file." << std::endl;
        return false;
    }

    // Open the output file for writing
    std::ofstream decryptedFile(outputFile, std::ios::binary);
    if (!decryptedFile.is_open()) {
        std::cerr << "Error: Unable to create the decrypted file." << std::endl;
        return false;
    }

    // Get the size of the encrypted file
    encryptedFile.seekg(0, std::ios::end);
    size_t fileSize = encryptedFile.tellg();
    encryptedFile.seekg(0, std::ios::beg);

    // Allocate a buffer to hold the encrypted data
    std::vector<char> encryptedData(fileSize);
    encryptedFile.read(encryptedData.data(), fileSize);

    // Allocate a buffer for the decrypted data
    std::vector<char> decryptedData(RSA_size(publicKey));

    // Decrypt the data using RSA_public_decrypt
    int decryptedSize = RSA_public_decrypt(fileSize, reinterpret_cast<const unsigned char*>(encryptedData.data()),
                                           reinterpret_cast<unsigned char*>(decryptedData.data()), publicKey, RSA_PKCS1_OAEP_PADDING);

    if (decryptedSize == -1) {
        std::cerr << "Error: RSA decryption failed." << std::endl;
        return false;
    }

    // Write the decrypted data to the output file
    decryptedFile.write(decryptedData.data(), decryptedSize);

    // Close the files
    encryptedFile.close();
    decryptedFile.close();

    std::cout << "Decryption successful. Decrypted data written to " << outputFile << std::endl;
    return true;
}

int main() {
    // Replace these paths with your actual file paths
    std::string publicKeyFile = "pubISM.pem";
    std::string encryptedFile = "key.sec";
    std::string outputFile = "decrypted_key.txt";

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read the public key from the PEM file
    FILE* publicKeyFilePtr = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKeyFilePtr) {
        std::cerr << "Error: Unable to open the public key file." << std::endl;
        return 1;
    }

    RSA* publicKey = PEM_read_RSA_PUBKEY(publicKeyFilePtr, nullptr, nullptr, nullptr);
    fclose(publicKeyFilePtr);

    if (!publicKey) {
        std::cerr << "Error: Unable to read the public key from the PEM file." << std::endl;
        return 1;
    }

    // Decrypt the file using the public key
    bool success = decryptFile(encryptedFile, outputFile, publicKey);

    // Free the RSA public key
    RSA_free(publicKey);

    // Clean up OpenSSL
    ERR_free_strings();
    EVP_cleanup();

    return success ? 0 : 1;
}

```

2. Decrypt Msg.enc file using the decrypted key.sec file content as AES key (CBC),
using OpenSSL in C++.
```
#include <iostream>
#include <fstream>
#include <openssl/aes.h>

// Function to decrypt the file using the AES key in CBC mode
bool decryptFile(const std::string& inputFile, const std::string& outputFile, const unsigned char* aesKey) {
    // Open the input file for reading
    std::ifstream encryptedFile(inputFile, std::ios::binary);
    if (!encryptedFile.is_open()) {
        std::cerr << "Error: Unable to open the encrypted file." << std::endl;
        return false;
    }

    // Open the output file for writing
    std::ofstream decryptedFile(outputFile, std::ios::binary);
    if (!decryptedFile.is_open()) {
        std::cerr << "Error: Unable to create the decrypted file." << std::endl;
        return false;
    }

    // Get the size of the encrypted file
    encryptedFile.seekg(0, std::ios::end);
    size_t fileSize = encryptedFile.tellg();
    encryptedFile.seekg(0, std::ios::beg);

    // Allocate a buffer to hold the encrypted data
    std::vector<char> encryptedData(fileSize);
    encryptedFile.read(encryptedData.data(), fileSize);

    // Initialize AES decryption context
    AES_KEY aesKeyStruct;
    if (AES_set_decrypt_key(aesKey, 128, &aesKeyStruct) != 0) {
        std::cerr << "Error: Unable to set AES decryption key." << std::endl;
        return false;
    }

    // Decrypt the data using AES_decrypt in CBC mode
    unsigned char iv[AES_BLOCK_SIZE]; // Initialization Vector (IV)
    memset(iv, 0, sizeof(iv)); // You may need to set a proper IV

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(encryptedData.data()), 
                    reinterpret_cast<unsigned char*>(decryptedFile), 
                    fileSize, &aesKeyStruct, iv, AES_DECRYPT);

    // Close the files
    encryptedFile.close();
    decryptedFile.close();

    std::cout << "Decryption successful. Decrypted data written to " << outputFile << std::endl;
    return true;
}

int main() {
    // Replace these paths with your actual file paths
    std::string encryptedFile = "Msg.enc";
    std::string keyFile = "key.sec";
    std::string outputFile = "decrypted_msg.txt";

    // Read the AES key from the key file
    std::ifstream keyFileStream(keyFile, std::ios::binary);
    if (!keyFileStream.is_open()) {
        std::cerr << "Error: Unable to open the key file." << std::endl;
        return 1;
    }

    // Get the size of the key file
    keyFileStream.seekg(0, std::ios::end);
    size_t keySize = keyFileStream.tellg();
    keyFileStream.seekg(0, std::ios::beg);

    // Allocate a buffer to hold the key
    std::vector<char> aesKey(keySize);
    keyFileStream.read(aesKey.data(), keySize);

    // Decrypt the file using the AES key
    bool success = decryptFile(encryptedFile, outputFile, reinterpret_cast<const unsigned char*>(aesKey.data()));

    // Close the key file
    keyFileStream.close();

    return success ? 0 : 1;
}

```

3. Generate the message digest according to MD5 algorithm for the decrypted
Msg.enc content, using a Java implementation. The first 16 bytes from Msg.enc are
the IV used for MD5 algorithm.

> Well... MD5 doesn't use IV 😂😂😂. But the code must ignore the first 16 bytes bcs are used as IV.

```
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MD5Example {

    public static void main(String[] args) {
        try {
            // Assuming Msg.enc is your encrypted content
            byte[] encryptedContent = // Initialize with your actual encrypted content;

            // Extract the first 16 bytes as IV
            byte[] iv = Arrays.copyOfRange(encryptedContent, 0, 16); // original, from, to

				// Remove the IV from the encryptedContent
				byte[] contentWithoutIV = Arrays.copyOfRange(encryptedContent, 16, encryptedContent.length); // original, from, to


            // Decrypt the content (replace this with your decryption logic)
            byte[] decryptedContent = // Replace with your decryption logic;

            // Generate the message digest using MD5 with IV as input
            byte[] messageDigest = getMessageDigest(decryptedContent, iv);

            // Print or use the message digest as needed
            System.out.println(Arrays.toString(messageDigest));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] getMessageDigest(byte[] input, byte[] iv) throws NoSuchAlgorithmException {
        try {
            // Concatenate IV and input data
            byte[] dataWithIV = new byte[iv.length + input.length];
            System.arraycopy(iv, 0, dataWithIV, 0, iv.length);
            System.arraycopy(input, 0, dataWithIV, iv.length, input.length);

            // Use MD5 algorithm to compute the hash
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(dataWithIV);
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("MD5 algorithm not available", e);
        }
    }
}

```

4. Generate a X509 digital certificate by using the public key stored by pubISM.pem
file (Java implementation).
```
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509CertificateGenerator {

    public static void main(String[] args) {
        try {
            // Load the public key from the PEM file (pubISM.pem)
            // You can replace "pubISM.pem" with the actual path to your PEM file
            FileInputStream fis = new FileInputStream("pubISM.pem");
            byte[] publicKeyBytes = new byte[fis.available()];
            fis.read(publicKeyBytes);
            fis.close();

            // Generate a key pair for the certificate (you can use the existing key pair)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Adjust the key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Create a X.509 certificate
            X509Certificate certificate = generateX509Certificate(keyPair, publicKeyBytes);

            // Print the generated X.509 certificate
            System.out.println("Generated X.509 Certificate:");
            System.out.println(certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate generateX509Certificate(KeyPair keyPair, byte[] publicKeyBytes) throws Exception {
        // Set the certificate subject and issuer information
        X500Name subject = new X500Name("CN=YourCommonName, O=YourOrganization");
        X500Name issuer = subject; // Self-signed certificate

        // Set the validity period of the certificate (e.g., 1 year)
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000); // 1 year

        // Create the X.509 certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                new java.math.BigInteger(64, new java.security.SecureRandom()),
                startDate,
                endDate,
                subject,
                SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKeyBytes))
        );

        // Add extensions (optional)

        // Specify the signature algorithm (SHA256WithRSA, SHA512WithRSA, etc.)
        String signatureAlgorithm = "SHA256WithRSA";

        // Load the private key for signing (you can replace this with your private key logic)
        PrivateKey privateKey = keyPair.getPrivate();

        // Create the content signer
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

        // Build the X.509 certificate holder
        X509CertificateHolder certHolder = certBuilder.build(signer);

        // Convert the X.509 certificate holder to a Java X.509 certificate
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
        certConverter.setProvider("BC"); // Bouncy Castle provider
        return certConverter.getCertificate(certHolder);
    }
}

```


4. Read .pem file private/public keys.
```
public static RSAPublicKey readX509PublicKey(File file) throws Exception {
    String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

    String publicKeyPEM = key
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PUBLIC KEY-----", "");

    byte[] encoded = Base64.decodeBase64(publicKeyPEM);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
}


public RSAPrivateKey readPKCS8PrivateKey(File file) throws Exception {
    String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

    String privateKeyPEM = key
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PRIVATE KEY-----", "");

    byte[] encoded = Base64.decodeBase64(privateKeyPEM);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
}
```



5. Read .pem file private/public keys (buncy castle)
```
public RSAPublicKey readX509PublicKey(File file) throws Exception {
    KeyFactory factory = KeyFactory.getInstance("RSA");

    try (FileReader keyReader = new FileReader(file);
      PemReader pemReader = new PemReader(keyReader)) {

        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        return (RSAPublicKey) factory.generatePublic(pubKeySpec);
    }
}
public RSAPublicKey readX509PublicKeySecondApproach(File file) throws IOException {
    try (FileReader keyReader = new FileReader(file)) {
        PEMParser pemParser = new PEMParser(keyReader);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
        return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
    }
}
public RSAPrivateKey readPKCS8PrivateKey(File file) throws Exception {
    KeyFactory factory = KeyFactory.getInstance("RSA");

    try (FileReader keyReader = new FileReader(file);
      PemReader pemReader = new PemReader(keyReader)) {

        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
    }
}
public RSAPrivateKey readPKCS8PrivateKeySecondApproach(File file) throws IOException {
    try (FileReader keyReader = new FileReader(file)) {

        PEMParser pemParser = new PEMParser(keyReader);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
    }
}
```















22
```

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {
        //47
        String path = "C:\\Users\\Daniela\\IdeaProjects\\testSAP3";


        // In order to use this passphrase as a secret password you will compute its SHA-1 value. That will be your access
        // key. Print it on the screen to check it.


        //managing the file system
        File file = new File("C:\\Users\\Daniela\\IdeaProjects\\testSAP3\\Passphrase.txt");


        //reading from text files
        FileReader fileReader = new FileReader(file);
        BufferedReader bufferedReader = new BufferedReader(fileReader);

        String line = bufferedReader.readLine();

        byte[] sha1 = getMessageDigest(line); // my access key

        System.out.println("sha1: " + getHexString(sha1));

        //The system admin is storing sensitive data in the EncryptedData.data file. Knowing that
        //▪ the file has been encrypted using AES in CBC mode please decrypt it
        //▪ The encryption didn’t use any padding as the file length is ok.
        //▪ The IV value is also known because it is stored at the beginning of the encrypted file.
        //▪ The encryption key is equal with the first 128 bits of the previous SHA1 hash value // 128/8 = 16
        //Let’s suppose that the obtained plaintext is named OriginalData.txt.

        byte[] encryptionKey = new byte[16]; // my access key
        for(int i=0;i<=15;i++){
            encryptionKey[i] = sha1[i];
        }


        System.out.println("encryptionKey: " + getHexString(encryptionKey));
        System.out.println("encryptionKey as string: " + encryptionKey);

        decrypt(path+"\\EncryptedData.data","OriginalData.txt", encryptionKey,"AES");

        //In the end you want to digitally sign (using RSA digital signature) the obtained plaintext OriginalData.txt. Your
        //private key, named sapexamkey, is stored in the Java Key store file, sap_exam_keystore.ks. The key password and
        //the keystore password are stored in the OriginalData.txt file that you decrypted earlier.
        //The obtained digital signature must be stored in the DataSignature.ds file. It will be used by others to check the file.


        KeyStore ks = getKeyStore("sap_exam_keystore.ks", "you_already_made_it", "pkcs12");
        list(ks);

        PublicKey pubIsm1 = getPublicKey("sapexamkey", ks);
        PrivateKey privIsm1 = getPrivateKey("sapexamkey", "you_already_made_it", ks); // For some reason, key pass isn't setting and reverts to default keystore pass. Done it with "C:\Program Files\Java\jdk-21\bin\keytool.exe" -genkeypair -keyalg RSA -alias sapexamkey -keypass grant_access -storepass you_already_made_it -keystore sap_exam_keystore.ks -dname "cn=EneFlavian, ou=ISM, o=IT&C Security Master, c=RO"


        //digital signatures
        //generate a digital signature (RSA) for a file with private key
        //validate the digital signature with public key

        byte[] signature = signFile("OriginalData.txt", privIsm1);

        File dataFile = new File("DataSignature.ds");
        if(!dataFile.exists()) {
            dataFile.createNewFile();
        }

        FileOutputStream fos = new FileOutputStream(dataFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write(signature);
        dos.close();

        System.out.println("Digital signature value: ");
        System.out.println(getHexString(signature));

        if(hasValidSignature("OriginalData.txt", pubIsm1, signature))
        {
            System.out.println("File is the original one");
        } else {
            System.out.println("File has been changed");
        }

        bufferedReader.close();
    }


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
    public static void decrypt(
            String filename,
            String outputFile,
            byte[] password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


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

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");

        //getting the IV from the file
        byte[] IV = new byte[cipher.getBlockSize()];
        fis.read(IV);

        SecretKeySpec key = new SecretKeySpec(password, algorithm);
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


    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }


    public static byte[] getMessageDigest(String input) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input.getBytes());
    }
}
```







23
```

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, KeyStoreException, UnrecoverableKeyException, SignatureException, CertificateException {

        //Use the fingerprints.txt content to identify the file from system32.zip which has been changed.

        //managing the file system
        File location = new File("C:\\Users\\Daniela\\IdeaProjects\\testSAP4\\system32");
        if(!location.exists()) {
            throw new UnsupportedOperationException("FOLDER is not there");
        }

        File fingerprints = new File("C:\\Users\\Daniela\\IdeaProjects\\testSAP4\\sha2Fingerprints.txt");

        String fileName = "";
        byte[] password = new byte[0];
        File[] files =  location.listFiles();
        for(File file : files) {

            // process file
            FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);

            byte[] byteValues = dis.readAllBytes();
            byte[] byteValuesHashes = getMessageDigest(byteValues);

            FileReader fileReader = new FileReader(fingerprints);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line;
            int found = 0;

            while((line = bufferedReader.readLine()) != null) {
                if(line.equals(Base64.getEncoder().encodeToString(byteValuesHashes))){
                    found = 1;
                }
            }
            if(found==0){
                fileName = file.getName();
                password = byteValues;
            }

            bufferedReader.close();
        }

        System.out.println("File that was altered is: " + fileName); // svchost71.exe
        //Using the random password, extracted from the file identified at the previous step, decrypt the
        //“financialdata.enc” file into “financialdata.txt”. The virus has encrypted it using AES in CBC mode, with PKCS5Padding.
        //Reverse engineering the virus you find out that that the IV had 1st byte (from right to left) equal with 23, 2nd byte equal
        //with 20, 3rd byte equal with 2 and 4th byte equal with 3. The rest of them are all 0s.

        decrypt("financialdata.enc","financialdata.txt",password,"AES"); // MC2817569000515924956987R16


        //To confirm your success and get your bounty, write the value of the 1st IBAN into myresponse.txt and digital sign
        //this file with your private key (you need to generate a private – public key using keytool). The signature is an RSA with
        //SHA256 digital signature. Don’t forget to send the “financialdata.txt”, “myresponse.txt” and your signature stored in a
        //file called DataSignature.ds


        //text files
        File myresponse = new File("myresponse.txt");
        if(!myresponse.exists()) {
            myresponse.createNewFile();
        }

        //writing into text files
        FileWriter fileWriter = new FileWriter(myresponse, true);
        PrintWriter printWriter = new PrintWriter(fileWriter);
        printWriter.println("MC2817569000515924956987R16");
        printWriter.close();


        KeyStore ks = getKeyStore( "keystore.ks", "parola", "pkcs12");

        PublicKey publicKey = getPublicKey("key1", ks);
        PrivateKey privateKey = getPrivateKey("key1", "parola", ks);

        //digital signatures
        //generate a digital signature (RSA) for a file with private key
        //validate the digital signature with public key

        byte[] signature = signFile("myresponse.txt", privateKey);

        if(hasValidSignature( "myresponse.txt", publicKey, signature))
        {
            System.out.println("File is the original one");
        } else {
            System.out.println("File has been changed");
        }


        File dataFile = new File("DataSignature.ds ");
        if(!dataFile.exists()) {
            dataFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(dataFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write(signature);
        dos.close();


    }

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

    public static KeyStore getKeyStore(
            String keyStoreFile,
            String keyStorePass,
            String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
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


    public static void decrypt(
            String filename,
            String outputFile,
            byte[] password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


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

        //Reverse engineering the virus you find out that that the IV had 1st byte (from right to left) equal with 23, 2nd byte equal
        //with 20, 3rd byte equal with 2 and 4th byte equal with 3. The rest of them are all 0s.
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[IV.length-1] = 0x17;
        IV[IV.length-2] = 0x14;
        IV[IV.length-3] = 0x03;
        IV[IV.length-4] = 0x02;
        IV[IV.length-4] = 0x03;


        SecretKeySpec key = new SecretKeySpec(password, algorithm);
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

    public static byte[] getMessageDigest(byte[] input) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }

}

```




24
```
public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {

        //A DB admin asks for your help to update the hash value of a user in his/her database.
        //He sent you that user password in an encrypted file (with a .user extension). Search for that file as you
        //know its SHA256 hash value in Base64 format.
        //Print the designated file name at the console.

        //SHA256 hash value in Base64 format
        String shaHashInBase = "M07BQL3cbJ2hiOxE6InVBCDwU8MO30Vq+pYt+TGn/8s=";
        String password = "userfilepass@0]3";
        String fileName = "";
        //The byte with index 12 from left to right has all bits 1. The others are all 0

        //managing the file system
        File location = new File("C:\\Users\\Daniela\\IdeaProjects\\testSAP2\\users");
        if(!location.exists()) {
            throw new UnsupportedOperationException("FOLDER is not there");
        }

        File[] files =  location.listFiles();
        for(File file : files) {
            //read from a binary file
            FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);

            byte[] byteValues = dis.readAllBytes();
            byte[] messageDigest = getMessageDigest(byteValues);

            if(shaHashInBase.equals(Base64.getEncoder().encodeToString(messageDigest))){
                System.out.println(file.getName());
                fileName = file.getName();
            }
        }

        //Once you found the file, decrypt it (AES in CBC mode with a known IV - check the user’s file (the index
        //starts at 0). There is no need for Padding as the file has the required size) using the password sent by
        //your friend (check the users.pdf file).
        //The decrypted content represents the user password as a string with 16 characters.
        //Print the user password at the console.

        String userPass = decrypt("C:\\Users\\Daniela\\IdeaProjects\\testSAP2\\users\\"+fileName,"pass.txt",password,"AES");
        System.out.println(userPass);

        //Add to the user password the "ism2021" salt at the end and hash it with the PBKDF (Password-Based
        //Key Derivation Function) based on HmacSHA1 algorithm with 150 iterations. The output must have
        //20 bytes.
        //Store the result in a binary file (you can choose the filename name). To get the points, the value must
        //be validated by your friend.

        String salt = "ism2021";
        String newPassword = userPass + salt;


        byte[] saltedHash = getPBKDF(newPassword,"PBKDF2WithHmacSHA1", salt, 150);
        System.out.println(getHexString(saltedHash));

        File dataFile = new File("pbkdf.dat");
        if(!dataFile.exists()) {
            dataFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(dataFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write(saltedHash);
        dos.close();


        //To assure your friend that no one is tampering with that value, digitally sign the previous binary file
        //with your private key. Store the signature in another binary file.
        //Using keytool generate a RSA pair. Export the public key in a X509 .cer file. Use the private key to sign
        //the previous file.
        //Send your colleague the binary files with the signature and your public certificate.
        //To get points the digital signature must be validated for the previous file with your public key.


        KeyStore ks = getKeyStore("keystore.ks", "parola", "pkcs12");

        PrivateKey privIsm1 = getPrivateKey("key1", "parola", ks);

        byte[] signature = signFile("pbkdf.dat", privIsm1);


        File signatureFile = new File("signature.dat");
        if(!signatureFile.exists()) {
            signatureFile.createNewFile();
        }
        FileOutputStream fos1 = new FileOutputStream(signatureFile);
        BufferedOutputStream bos1 = new BufferedOutputStream(fos1);
        DataOutputStream dos1 = new DataOutputStream(bos1);

        dos1.write(signature);
        dos1.close();

        PublicKey pubIsm1FromCert = getCertificateKey("EneFlavian.cer");


        if(hasValidSignature("pbkdf.dat", pubIsm1FromCert, signature))
        {
            System.out.println("File is the original one");
        } else {
            System.out.println("File has been changed");
        }
    }

    public static boolean hasValidSignature(String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

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

    public static PrivateKey getPrivateKey( String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if(ks == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if(ks.containsAlias(alias)) {
            return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        } else {
            return null;
        }
    }

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


    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }

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
                        noIterations,160);
        SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
        return secretKey.getEncoded();
    }

    public static String decrypt(
            String filename,
            String outputFile,
            String password,
            String algorithm) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        String userPass = "";
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

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");
        //The byte with index 12 from left to right has all bits 1. The others are all 0
        //getting the IV from the file
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[12]= (byte) 0xFF;
        //fis.read(IV);

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
            userPass = new String(cipherBlock);
        }
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
        return userPass;
    }

    public static byte[] getMessageDigest(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }


}

```