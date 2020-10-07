package pkr;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.bouncycastle.crypto.params.ECDomainParameters;

public final class KeyData {
  public final ECPrivateKey ecPrivateKey;
  public final ECPublicKey ecPublicKey;
  public final ECDomainParameters ecDomainParameters;
  public final BigInteger priBI;
  public final byte[] pubBI;

  public KeyData(
      final ECPrivateKey ecPrivateKey,
      final ECPublicKey ecPublicKey,
      final ECDomainParameters ecDomainParameters,
      final BigInteger priBI,
      final byte[] pubBI) {
    this.ecPrivateKey = ecPrivateKey;
    this.ecPublicKey = ecPublicKey;
    this.ecDomainParameters = ecDomainParameters;
    this.priBI = priBI;
    this.pubBI = pubBI;
  }

  @Override
  public String toString() {
    return "KeyData{" +
        "ecPrivateKey=" + ecPrivateKey +
        ", ecPublicKey=" + ecPublicKey +
        ", ecDomainParameters=" + ecDomainParameters +
        ", priBI=" + priBI +
        ", pubBI=" + Arrays.toString(pubBI) +
        '}';
  }
}
