package security;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

public final class RSA {
	private static final Logger log = Logger.getLogger(RSA.class.getName());

	public static int PRIME_LENGTH = 1024;

	private BigInteger p, q, n, phi, e, d;
	private SecureRandom sr;

	public RSA() {
		log.info("Initializing java PRNG with a random seed");
		sr = new SecureRandom();
		sr.setSeed(System.currentTimeMillis());

		log.info("Generating 2 prime numbers, of PRIME_LENGHT ("
				+ RSA.PRIME_LENGTH + ") bit");
		p = BigInteger.probablePrime(RSA.PRIME_LENGTH, sr);
		q = BigInteger.probablePrime(RSA.PRIME_LENGTH, sr);

		// n = q times p
		n = q.multiply(p);

		// Calculate Euler's Totient function
		// For 2 prime number this value is equal to phi = (p - 1)(q - 1)
		phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = findExponent(phi);

		// Public key : {e, n}
		// Private key: {d, n}
		d = e.modInverse(phi);
	}

	public RSAKey getPrivateKey() {
		RSAKey privateKey = new RSAKey();
		privateKey.exponent = d;
		privateKey.number = n;
		return privateKey;
	}

	public RSAKey getPublicKey() {
		RSAKey publicKey = new RSAKey();
		publicKey.exponent = e;
		publicKey.number = n;
		return publicKey;
	}

	public BigInteger sign(byte[] message) throws NoSuchAlgorithmException {
		// Sign the hash of the message with my private key
		// We use a 256 bit algorithm, since 256 is less then PRIME_LENGTH so
		// RSA can generate a secure sign of this hash (since RSA can't handle
		// messages longest than the module)
		return encrypt(MessageDigest.getInstance("SHA-256").digest(message),
				getPrivateKey());
	}

	public static boolean verifySign(RSAKey publicKey, BigInteger sign,
			byte[] message) throws NoSuchAlgorithmException {
		// Since RSA is a reversible algorithm, we can decrypt the sign
		// (signed with the other user private key)
		// using the other user public key.
		// After that, we should calculate the hash of the
		// plaintext message and compare this the the decrypted sign
		return new BigInteger(RSA.decrypt(sign, publicKey))
				.equals(new BigInteger(MessageDigest.getInstance("SHA-256")
						.digest(message)));

	}

	public static BigInteger encrypt(byte[] message, RSAKey key) {
		return new BigInteger(message).modPow(key.exponent, key.number);
	}

	public static byte[] decrypt(BigInteger encryptedMessage, RSAKey key) {
		return encryptedMessage.modPow(key.exponent, key.number).toByteArray();
	}

	public byte[] decrypt(BigInteger encryptedMessage) {
		return RSA.decrypt(encryptedMessage, getPrivateKey());
	}

	private BigInteger findExponent(BigInteger phi) {
		log.info("Searching for a valid exponent");
		BigInteger e;
		do {
			// -1, so we are sure that the value is less than phi
			e = new BigInteger(RSA.PRIME_LENGTH - 1, sr);
		} while (!phi.gcd(e).equals(BigInteger.ONE));
		log.info("Exponent found: " + e.toString());
		return e;
	}

}
