package pkr;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class PubKeyRecovery {

  static void log(final Object o) {
    System.out.println("" + o);
  }

  public static void main(String[] args) throws Exception {
    final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
        CURVE_PARAMS.getH());
    final ECKeyPairGenerator generator = new ECKeyPairGenerator();
    final ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, new SecureRandom());
    generator.init(keygenParams);
    final AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
    log("keypair: " + keypair);
    final ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
    final ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
    log("EC Pub: " + pubParams);
    log("EC Pri: " + privParams);
    final BigInteger priBI = privParams.getD();
    final byte[] pubBI = pubParams.getQ().getEncoded(true);

    final String message = "Hello World!";
    final MessageDigest digest = MessageDigest.getInstance("SHA-256");
    final byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
    final ECDSASigner ecdsaSigner = new ECDSASigner();
    ecdsaSigner.init(true, new ECPrivateKeyParameters(priBI, CURVE));
    final BigInteger[] signature = ecdsaSigner.generateSignature(hash);
    log("signature: " + Arrays.toString(signature));
    final BigInteger r = signature[0];
    final BigInteger s = signature[1];

    boolean success = false;
    for (int i = 0; i < 4; i++) {
      final byte[] recoveredPubKey = recoverFrom(CURVE, i, r, s, hash, true);
      if (recoveredPubKey != null && Arrays.equals(recoveredPubKey, pubBI)) {
        success = true;
        log("Success at index " + i);
        break;
      }
    }
    log("Done! " + success);
  }

  static byte[] recoverFrom(final ECDomainParameters CURVE, final int index, final BigInteger sigR, final BigInteger sigS,
      final byte[] hash, final boolean compressed) throws Exception {
    final BigInteger n = CURVE.getN();
    final BigInteger i = BigInteger.valueOf((long) index / 2);
    final BigInteger x = sigR.add(i.multiply(n));
    final BigInteger prime = SecP256K1Curve.q;
    if (x.compareTo(prime) >= 0) {
      return null;
    }
    final ECPoint R = decompressKey(CURVE, x, (index & 1) == 1);
    if (!R.multiply(n).isInfinity()) {
      return null;
    }
    final BigInteger e = new BigInteger(1, hash);
    final BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
    final BigInteger rInv = sigR.modInverse(n);
    final BigInteger srInv = rInv.multiply(sigS).mod(n);
    final BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
    final ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
    return q.getEncoded(compressed);
  }

  private static ECPoint decompressKey(final ECDomainParameters CURVE, final BigInteger xBN, final boolean yBit) {
    final X9IntegerConverter x9 = new X9IntegerConverter();
    final byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
    compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
    return CURVE.getCurve().decodePoint(compEnc);
  }
}
