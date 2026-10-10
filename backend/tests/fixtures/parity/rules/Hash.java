import java.security.MessageDigest;
import java.sql.Statement;

public class Hash {
    public static byte[] weak(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public static byte[] alsoWeak(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    public static byte[] strong(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public String find(Statement st, String id) throws Exception {
        return st.executeQuery("SELECT name FROM users WHERE id = " + id).getString(1);
    }

    private static int clamp(int v) {
        if (v < 0 || v > 100) {
            return v < 0 ? 0 : 100;
        }
        return v;
    }
}
