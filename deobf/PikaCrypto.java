package devs.pikachu.deobf;

/**
 * PikachuObf 2.x の文字列・数値を復号する。同じ XOR なのになんで2つ実装したのかは不明。
 * - {@code Kami(Object)}: 先頭文字がキー。残りは {@code key * (index + 1)} と XOR。
 * - {@code BROZOZOTOWN}: int キー由来の鍵スケジュールで所有クラス名・メソッド名・記述子を XOR。
 * - InvokeDynamicTransformer2 の配列: 例外にペイロード、行番号にキーを持たせ、
 *   クラス名もキーストリームに混ぜる。
 * - {@code Kami(int,int,int)} / {@code Kami(long,long,long)}: 最後の値をビット反転して 3 値を XOR。
 */
public final class PikaCrypto {
    private PikaCrypto() {
    }

    /** StringNumberTransformer.visitString / Kami(Object) の文字列を復号。 */
    public static String decodeKamiString(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return encoded;
        }
        char key = encoded.charAt(0);
        char[] out = new char[encoded.length() - 1];
        for (int i = 0; i < out.length; i++) {
            out[i] = (char) (encoded.charAt(i + 1) ^ (key * (i + 1)));
        }
        return new String(out);
    }

    /**
     * Kami 符号化らしければ true。キーは 8192..65535 なので ASCII 始まりは触らない。
     */
    public static boolean looksKamiEncoded(String s) {
        return s != null && !s.isEmpty() && s.charAt(0) >= 0x2000;
    }

    /**
     * BROZOZOTOWN の引数から所有クラス名・メソッド名・記述子を復号。
     * 鍵スケジュールは Java の int オーバーフローまで再現。
     */
    public static String decodeIndyString(String encoded, int key) {
        if (encoded == null) {
            return null;
        }
        int size = key % 10 + 10;
        if (size <= 0) {
            size = 1;
        }
        char[] charKey = new char[size];
        int k = key;
        for (int i = 0; i < charKey.length; i++) {
            k += k * (k >> 5) + (k << 5) + 114514;
            charKey[i] = (char) (k % 65536);
        }
        char[] out = encoded.toCharArray();
        for (int i = 0; i < out.length; i++) {
            out[i] = (char) (out[i] ^ charKey[i % charKey.length]);
        }
        return new String(out);
    }

    /** InvokeDynamicTransformer2 のキー付き文字列を復号。 */
    public static String decodeSimpleString(String encoded) {
        return decodeKamiString(encoded);
    }

    /**
     * invokedynamic 静的配列の例外ペイロードを復号。
     * {@code exceptionName} は Throwable.getClass().getName() と同じドット区切りの
     * バイナリ名（java.lang.NullPointerException）が必須。
     */
    public static String decodeThrowableString(String encoded, int lineNumber, String exceptionName) {
        if (encoded == null || encoded.isEmpty()) {
            return encoded;
        }
        char[] chars = encoded.toCharArray();
        int previous = 0;
        for (int i = 0; i < chars.length; i++) {
            int enc = chars[i];
            int keyPart = previous
                    ^ lineNumber * (chars.length - i)
                    ^ exceptionName.charAt(i % exceptionName.length());
            int dec = enc ^ (keyPart % 65536);
            chars[i] = (char) dec;
            previous = dec;
        }
        return new String(chars);
    }

    /** Kami(int,int,int). */
    public static int kamiInt(int a, int b, int c, boolean resourcePresent) {
        if (resourcePresent) {
            return ~(a ^ b ^ c);
        }
        return a ^ b ^ ~c;
    }

    /** Kami(long,long,long). */
    public static long kamiLong(long a, long b, long c, boolean resourcePresent) {
        if (resourcePresent) {
            return a ^ b ^ c ^ 0xFFFFFFFFFFFFFFFFL;
        }
        return a ^ b ^ (c ^ 0xFFFFFFFFFFFFFFFFL);
    }
}
