package security;

import jSC.CS;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class Ciphers {
	
	private Cipher encryptor, decryptor;
	private IvParameterSpec ivspec;

	public Ciphers(String algorithm, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException {
		encryptor = Cipher.getInstance(algorithm);
		decryptor = Cipher.getInstance(algorithm);
		ivspec = new IvParameterSpec(iv);
		CS.log("Using init vector: " + DatatypeConverter.printBase64Binary(ivspec.getIV()));
	}
	
	public Ciphers(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
		encryptor = Cipher.getInstance(algorithm);
	}
	
	public Cipher GetEncryptor(Key secret) throws InvalidKeyException, InvalidAlgorithmParameterException {
		CS.log("Using secret: " + DatatypeConverter.printBase64Binary(secret.getEncoded()));
		encryptor.init(Cipher.ENCRYPT_MODE, secret, ivspec);
		return encryptor;
	}
	
	public Cipher GetDecryptor(Key secret) throws InvalidKeyException, InvalidAlgorithmParameterException {
		decryptor.init(Cipher.DECRYPT_MODE, secret, ivspec);
		return decryptor;
	}

}
