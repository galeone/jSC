package security;

import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;

public class RSAKey {
	public BigInteger exponent, number;

	@Override
	public String toString() {
		return DatatypeConverter.printBase64Binary(exponent.toByteArray())
				+ "'"
				+ DatatypeConverter.printBase64Binary(number.toByteArray());
	}

	public static RSAKey parse(String textRepresentation) {
		RSAKey key = new RSAKey();
		if (textRepresentation.contains("'")) {
			String[] values = textRepresentation.split("'");
			key.exponent = new BigInteger(
					DatatypeConverter.parseBase64Binary(values[0]));
			key.number = new BigInteger(
					DatatypeConverter.parseBase64Binary(values[1]));
		}
		return key;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((exponent == null) ? 0 : exponent.hashCode());
		result = prime * result + ((number == null) ? 0 : number.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RSAKey other = (RSAKey) obj;
		if (exponent == null) {
			if (other.exponent != null)
				return false;
		} else if (!exponent.equals(other.exponent))
			return false;
		if (number == null) {
			if (other.number != null)
				return false;
		} else if (!number.equals(other.number))
			return false;
		return true;
	}
}
