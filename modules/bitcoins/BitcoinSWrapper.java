import org.bitcoins.core.crypto.ChainCode;
import org.bitcoins.core.crypto.ExtKey;
import org.bitcoins.core.crypto.ExtKey$;
import org.bitcoins.core.crypto.ExtKeyPrivVersion;
import org.bitcoins.core.crypto.ExtPrivateKey;
import org.bitcoins.core.crypto.ExtPrivateKey$;
import org.bitcoins.core.crypto.ExtPublicKey;
import org.bitcoins.core.hd.BIP32Path$;
import org.bitcoins.core.hd.BIP32Path;
import org.bitcoins.core.psbt.PSBT;
import org.bitcoins.core.psbt.PSBT$;
import org.bitcoins.core.psbt.InputPSBTMap;
import org.bitcoins.core.protocol.transaction.Transaction;
import org.bitcoins.core.protocol.transaction.TransactionInput;
import org.bitcoins.core.protocol.transaction.TransactionOutput;
import scala.Option;
import scala.util.Try;
import scodec.bits.ByteVector;
import scodec.bits.ByteVector$;

/**
 * Plain Java entry point for the bitcoin-s fuzzing module. All three methods
 * are real Java statics so C++ JNI can call them without going through Scala's
 * companion-object virtual dispatch, which conflicts with AddressSanitizer's
 * SIGSEGV interception.
 *
 * Calling convention (shared by every JVM module in this project):
 *   ""           -> parse / validation error (counted, not compared)
 *   "skip error" -> tells the C++ driver to skip this test-case
 *   anything else-> normalised output compared across all loaded modules
 */
public class BitcoinSWrapper {

  // Cached singleton — loaded once on first call, reused for every subsequent
  // invocation so we don't pay repeated Class.forName / getField overhead.
  private static ExtKeyPrivVersion LEGACY_MAINNET_PRIV = null;

  // Access the LegacyMainNetPriv case-object via reflection; javac cannot
  // parse Scala's $-delimited class names directly in source code.
  private static ExtKeyPrivVersion legacyMainNetPriv() throws Exception {
    if (LEGACY_MAINNET_PRIV == null) {
      Class<?> cls = Class.forName(
          "org.bitcoins.core.crypto.ExtKeyVersion$LegacyMainNetPriv$");
      LEGACY_MAINNET_PRIV = (ExtKeyPrivVersion) cls.getField("MODULE$").get(null);
    }
    return LEGACY_MAINNET_PRIV;
  }

  /**
   * Derives a BIP-32 master private key from raw seed bytes and returns its
   * Base58Check encoding (the standard "xprv..." string).
   */
  public static String createMasterKey(byte[] seedBytes) {
    try {
      ByteVector bv = ByteVector$.MODULE$.apply(seedBytes);
      ExtKeyPrivVersion version = legacyMainNetPriv();
      // passing Some(seed) triggers HMAC-SHA512("Bitcoin seed", seed) per BIP-32
      scala.Option<ByteVector> seedOpt = scala.Some$.MODULE$.apply(bv);
      // third arg is BIP32Path — use the default (empty path = master key)
      BIP32Path emptyPath = BIP32Path$.MODULE$.empty();
      ExtPrivateKey key =
          (ExtPrivateKey) ExtPrivateKey$.MODULE$.apply(version, seedOpt, emptyPath);
      // toStringSensitive bypasses MaskedToString and returns the real xprv
      return key.toStringSensitive();
    } catch (Exception e) {
      return "";
    }
  }

  /**
   * Parses a Base58Check-encoded extended key (xprv / xpub / tprv / tpub ...)
   * and returns a normalised field string for differential comparison.
   *
   * Output format (matches bitcoinj and libwally-core):
   *   depth=<02x>;fp=<8 hex>;child=<08x>;chaincode=<64 hex>;key=<hex>
   */
  public static String deserializeExtendedKey(byte[] bytes) {
    if (bytes.length == 0) return "INVALID";
    try {
      String base58 = new String(bytes, "UTF-8").trim();
      Try<ExtKey> result = ExtKey$.MODULE$.fromStringT(base58);
      if (!result.isSuccess()) return "INVALID";

      ExtKey key = result.get();

      // depth is UInt8; mask to unsigned to avoid sign-extension
      int depth = key.depth().toInt() & 0xff;
      // fingerprint is a 4-byte ByteVector -> 8 lowercase hex chars
      String fp = key.fingerprint().toHex();
      // childNum is UInt32; toLong gives the unsigned 32-bit value
      long child = key.childNum().toLong();
      // chainCode carries the raw 32 bytes
      String cc = key.chainCode().bytes().toHex();

      String keyHex;
      if (key instanceof ExtPrivateKey) {
        // 32-byte raw scalar, no prefix -> 64 hex chars
        keyHex = ((ExtPrivateKey) key).key().bytes().toHex();
      } else {
        // 33-byte compressed public key (0x02/0x03 + X) -> 66 hex chars
        keyHex = ((ExtPublicKey) key).key().bytes().toHex();
      }

      return String.format(
          "depth=%02x;fp=%s;child=%08x;chaincode=%s;key=%s",
          depth, fp, child, cc, keyHex);

    } catch (Exception e) {
      return "INVALID";
    }
  }

  /**
   * Parses a raw PSBT (v0, BIP-174) from bytes and returns a summary string.
   * Only PSBT v0 (with a global unsigned transaction) is supported; v2 PSBTs
   * that lack a global tx return "" so the driver skips them.
   */
  public static String parsePSBT(byte[] psbtBytes) {
    if (psbtBytes.length == 0) return "";
    try {
      ByteVector bv = ByteVector$.MODULE$.apply(psbtBytes);
      PSBT psbt = PSBT$.MODULE$.fromBytes(bv);

      // .transaction() throws if there is no global unsigned tx (PSBTv2)
      Transaction tx = psbt.transaction();

      StringBuilder sb = new StringBuilder();
      sb.append("lt=").append(tx.lockTime().toLong()).append(";");
      sb.append("in=").append(tx.inputs().size()).append(";");
      sb.append("out=").append(tx.outputs().size()).append(";");

      scala.collection.immutable.Seq<?> inputs = tx.inputs();
      for (int i = 0; i < inputs.size(); i++) {
        TransactionInput txIn = (TransactionInput) inputs.apply(i);
        String prevHash = txIn.previousOutput().txIdBE().hex();
        long vout = txIn.previousOutput().vout().toLong();
        sb.append("in").append(i).append("prev=")
            .append(prevHash).append(":").append(vout).append(";");
        sb.append("in").append(i).append("seq=")
            .append(txIn.sequence().toLong()).append(";");

        // check whether the PSBT input map has a UTXO attached
        InputPSBTMap inp = (InputPSBTMap) psbt.inputMaps().apply(i);
        boolean hasUtxo = inp.nonWitnessOrUnknownUTXOOpt().isDefined()
            || inp.witnessUTXOOpt().isDefined();
        if (hasUtxo) {
          sb.append("in").append(i).append("utxo=1;");
        }
        sb.append("in").append(i).append("sigs=")
            .append(inp.partialSignatures().size()).append(";");
      }

      scala.collection.immutable.Seq<?> outputs = tx.outputs();
      for (int i = 0; i < outputs.size(); i++) {
        TransactionOutput txOut = (TransactionOutput) outputs.apply(i);
        sb.append("out").append(i).append("val=")
            .append(txOut.value().satoshis().toLong()).append(";");
        sb.append("out").append(i).append("script=")
            .append(txOut.scriptPubKey().hex()).append(";");
      }

      return sb.toString();

    } catch (Exception e) {
      return "";
    }
  }
}
