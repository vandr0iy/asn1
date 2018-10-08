package bitHelper;

public final class Bytes {
  static public byte shiftRight(byte x, byte n){ return (byte)((byte)x >> n); }
  static public byte shiftLeft(byte x, byte n){ return (byte)((byte)x << n); }
  static public byte unsignedShiftRight(byte x, byte n){ return (byte)((byte)x >>> n); }
  static public byte and(byte x, byte n){ return (byte)((byte)x & (byte)n); }
  static public byte or(byte x, byte n){ return (byte)((byte)x | (byte)n); }
}
