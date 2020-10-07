package pkr;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
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
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import java.security.spec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class PubKeyRecovery {
  public static final String CURVE_NAME = "secp256k1";

  static void log(final Object o) {
    System.out.println("" + o);
  }

  public static void main(String[] args) throws Exception {
    // 1. Generate the EC Key Pair and related key spec parameters
    final KeyData ecKEyData = generateECDSAKeyPair();
    log(ecKEyData);

    // 2. Generate a signature for a message using ECDSA
    final String message = "Hello TJ! Howzit?";
    final MessageDigest digest = MessageDigest.getInstance("SHA-256");
    final byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
    final ECDSASigner ecdsaSigner = new ECDSASigner();
    ecdsaSigner.init(true, new ECPrivateKeyParameters(ecKEyData.priBI, ecKEyData.ecDomainParameters));
    final BigInteger[] signature = ecdsaSigner.generateSignature(hash);
    log("Signature: " + Arrays.toString(signature));
    final BigInteger r = signature[0];
    final BigInteger s = signature[1];

    // 3. From the signature, recover the public key and make sure it matches the original public key
    boolean success = false;
    for (int i = 0; i < 4; i++) {
      final byte[] recoveredPubKey = recoverFrom(ecKEyData.ecDomainParameters, i, r, s, hash, true);
      if (recoveredPubKey != null && Arrays.equals(recoveredPubKey, ecKEyData.pubBI)) {
        success = true;
        log("Success at index " + i);
        break;
      }
    }
    log("Done! " + success);
  }

  static KeyData generateECDSAKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
    final X9ECParameters x9ECParameters = CustomNamedCurves.getByName(CURVE_NAME);
    final ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(),
        x9ECParameters.getH());
    final ECKeyPairGenerator generator = new ECKeyPairGenerator();
    final ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ecDomainParameters, new SecureRandom());
    generator.init(keygenParams);
    final AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
    final ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();

    final X9ECParameters ecCurve = ECNamedCurveTable.getByName(CURVE_NAME);
    final ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH(), ecCurve.getSeed());
    final ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privParams.getD(), ecParameterSpec);
    final KeyFactory keyFactory = KeyFactory.getInstance("EC");
    final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

    final ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
    final byte[] x = pubParams.getQ().getRawXCoord().getEncoded();
    final byte[] y = pubParams.getQ().getRawYCoord().getEncoded();
    final ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
    final ECParameterSpec spec = new ECNamedCurveSpec(CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH(), ecCurve.getSeed());
    final PublicKey ecPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(point, spec));

    final BigInteger priBI = privParams.getD();
    final byte[] pubBI = pubParams.getQ().getEncoded(true);

    return new KeyData((ECPrivateKey)privateKey, (ECPublicKey)ecPublicKey, ecDomainParameters, priBI, pubBI);
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
    final org.bouncycastle.math.ec.ECPoint R = decompressKey(CURVE, x, (index & 1) == 1);
    if (!R.multiply(n).isInfinity()) {
      return null;
    }
    final BigInteger e = new BigInteger(1, hash);
    final BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
    final BigInteger rInv = sigR.modInverse(n);
    final BigInteger srInv = rInv.multiply(sigS).mod(n);
    final BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
    final org.bouncycastle.math.ec.ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
    return q.getEncoded(compressed);
  }

  private static org.bouncycastle.math.ec.ECPoint decompressKey(final ECDomainParameters CURVE, final BigInteger xBN, final boolean yBit) {
    final X9IntegerConverter x9 = new X9IntegerConverter();
    final byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
    compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
    return CURVE.getCurve().decodePoint(compEnc);
  }
}
