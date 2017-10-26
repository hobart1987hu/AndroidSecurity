package security.score;

/**
 * Created by huzeyin on 2017/8/26.
 */

public class Security {

    static {
        System.loadLibrary("Security");
    }

    /**
     * md5 encrypt
     *
     * @param value the input data
     * @return
     */
    public static native String md5(String value);

    /**
     * check the current app sign is validate
     *
     * @return 0: success ,-1:failure
     */
    public static native int verifySign();

    /**
     * AES encrypt
     *
     * @param value the given value
     * @return the value encrypt by AES
     */
    public static native String AESEncrypt(String value);

    /**
     * AES decrypt
     *
     * @param value the value of need decrypt
     * @return the decrypt value
     */
    public synchronized static native String AESDecrypt(String value);

    /**
     * AES encrypt with key
     *
     * @param key   AES encrypt key
     * @param value the given value
     * @return the value encrypt by AES
     * @throws Exception
     */
    public static native String AESEncryptWithKey(String key, String value);

    /**
     * AES decrypt with key
     *
     * @param key   the ASE decrypt key
     * @param value the value of need decrypt
     * @return the decrypt value
     * @throws Exception
     */
    public static native String AESDecryptWithKey(String key, String value);
}
