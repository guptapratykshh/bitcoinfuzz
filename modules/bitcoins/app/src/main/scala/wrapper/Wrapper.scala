package wrapper

import org.bitcoins.core.crypto._
import org.bitcoins.core.hd.BIP32Path
import org.bitcoins.core.psbt.PSBT
import scodec.bits.ByteVector

import scala.util.{Failure, Success}

/**
 * JNI entry point for the bitcoin-s module.
 *
 * Calling convention shared by every JVM module in this project:
 *   ""           → parse / validation error (counted, not compared)
 *   "skip error" → tells the C++ driver to skip this test-case (std::nullopt)
 *   anything else→ normalised output compared across all loaded modules
 *
 * Scala `object` auto-generates static Java forwarders so C++ JNI can
 * resolve all methods as statics on "wrapper/Wrapper".
 */
object Wrapper {

  /**
   * Derives a BIP-32 master private key from raw seed bytes and returns its
   * Base58Check encoding (the familiar "xprv…" string).
   *
   * bitcoin-s uses `ExtKeyVersion.LegacyMainNetPriv` (0x0488ADE4) to produce
   * the standard xprv prefix, matching bitcoinj's MainNet serialisation.
   *
   * Note: `ExtPrivateKey.toString` is masked for security. We call
   * `toStringSensitive` instead to get the actual Base58 payload for
   * differential comparison.
   */
  def createMasterKey(seedBytes: Array[Byte]): String = {
    try {
      val seedBV = ByteVector(seedBytes)
      // apply(version, seedOpt, path) — passing Some(seed) triggers the
      // HMAC-SHA512("Bitcoin seed", seed) derivation defined in BIP-32.
      val masterKey =
        ExtPrivateKey(ExtKeyVersion.LegacyMainNetPriv, Some(seedBV))
      // toStringSensitive bypasses MaskedToString and returns the real xprv string
      masterKey.toStringSensitive
    } catch {
      // Catch seeds that produce an invalid scalar (IL >= curve order)
      // or any other bitcoin-s rejection; return "" so it is counted but not
      // compared rather than aborting the whole run.
      case _: Exception => ""
    }
  }

  /**
   * Parses a Base58Check-encoded extended key (xprv / xpub / tprv / tpub …)
   * from the raw bytes of the fuzzer buffer and returns a normalised field
   * string so the driver can diff implementations field-by-field.
   *
   * Output format (matches bitcoinj and libwally-core):
   *   depth=<02x>;fp=<8 hex>;child=<08x>;chaincode=<64 hex>;key=<hex>
   *
   * For private keys "key" is the 32-byte raw scalar (64 hex chars).
   * For public  keys "key" is the 33-byte compressed point (66 hex chars),
   * including the 0x02/0x03 parity byte — consistent with bitcoinj output.
   */
  def deserializeExtendedKey(bytes: Array[Byte]): String = {
    if (bytes.isEmpty) return "INVALID"

    // The fuzzer passes raw bytes; treat them as a UTF-8 Base58Check string
    val base58 = new String(bytes, "UTF-8").trim

    ExtKey.fromStringT(base58) match {

      case Success(key) =>
        val depth = key.depth.toInt & 0xff
        // fingerprint is a 4-byte ByteVector → 8 lowercase hex chars
        val fp    = key.fingerprint.toHex
        // childNum is UInt32; toLong gives the unsigned value
        val child = key.childNum.toLong
        // chainCode.bytes() is the raw 32-byte chain code
        val cc    = key.chainCode.bytes.toHex

        val keyHex = key match {
          case priv: ExtPrivateKey =>
            // ECPrivateKey.bytes is 32 bytes (no prefix) → 64 hex chars
            priv.key.bytes.toHex
          case pub: ExtPublicKey =>
            // ECPublicKey.bytes is 33 bytes compressed (0x02/0x03 + X) → 66 hex chars
            pub.key.bytes.toHex
        }

        f"depth=$depth%02x;fp=$fp;child=$child%08x;chaincode=$cc;key=$keyHex"

      case Failure(_) =>
        "INVALID"
    }
  }

  /**
   * Parses a raw PSBT (v0, BIP-174) from bytes and returns a summary string
   * matching the field format used by libwally-core so the driver can diff
   * results across implementations.
   *
   * Only PSBT v0 (which embeds a global unsigned transaction) is emitted;
   * v2 / BIP-370 PSBTs that lack a global tx are reported as "" so the
   * driver ignores them — same behaviour as the libwally module.
   */
  def parsePSBT(psbtBytes: Array[Byte]): String = {
    if (psbtBytes.isEmpty) return ""

    try {
      val bv   = ByteVector(psbtBytes)
      val psbt = PSBT.fromBytes(bv)

      // `transaction` may throw if there is no global unsigned tx (PSBTv2)
      val tx = psbt.transaction

      val sb = new StringBuilder
      sb.append("lt=").append(tx.lockTime.toLong).append(";")
      sb.append("in=").append(tx.inputs.size).append(";")
      sb.append("out=").append(tx.outputs.size).append(";")

      tx.inputs.zipWithIndex.foreach { case (txIn, i) =>
        // txIdBE is the big-endian (display) form of the txid hash
        val prevHash = txIn.previousOutput.txIdBE.hex
        val vout     = txIn.previousOutput.vout.toLong
        sb.append(s"in${i}prev=$prevHash:$vout;")
        sb.append(s"in${i}seq=${txIn.sequence.toLong};")

        // Flag whether a UTXO is attached to this input in the PSBT map
        val inp     = psbt.inputMaps(i)
        val hasUtxo = inp.nonWitnessOrUnknownUTXOOpt.isDefined ||
                      inp.witnessUTXOOpt.isDefined
        if (hasUtxo) sb.append(s"in${i}utxo=1;")

        sb.append(s"in${i}sigs=${inp.partialSignatures.size};")
      }

      tx.outputs.zipWithIndex.foreach { case (txOut, i) =>
        sb.append(s"out${i}val=${txOut.value.satoshis.toLong};")
        // hex() returns the raw serialised script bytes, consistent with libwally
        sb.append(s"out${i}script=${txOut.scriptPubKey.hex};")
      }

      sb.toString()

    } catch {
      // Any parse failure or missing global tx → skip this input
      case _: Exception => ""
    }
  }
}
