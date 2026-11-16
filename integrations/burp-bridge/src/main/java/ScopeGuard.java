import burp.api.montoya.http.message.requests.HttpRequest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/** One signed PM request, not a generic network grant. No target I/O here. */
public final class ScopeGuard {
    public static final String HEADER = "X-Pentest-Master-Scope";
    private final String secret;
    private final ConcurrentHashMap<String,Long> used = new ConcurrentHashMap<>();
    public ScopeGuard(String secret) { this.secret=secret; }
    public static String hash(byte[] input) throws Exception {
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
    }
    private static String hash(String value) throws Exception {
        return hash((value==null?"":value).getBytes(StandardCharsets.UTF_8));
    }
    public boolean allows(HttpRequest request, boolean consume) {
        try {
            String ticket=request.headerValue(HEADER);
            if(ticket==null || ticket.length()>20000)return false;
            String[] pieces=ticket.split("\\.",2);
            if(pieces.length!=2)return false;
            byte[] payload=Base64.getUrlDecoder().decode(pieces[0]);
            Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.US_ASCII),"HmacSHA256"));
            if(!MessageDigest.isEqual(mac.doFinal(payload),Base64.getUrlDecoder().decode(pieces[1])))return false;
            String[] fields=new String(payload,StandardCharsets.UTF_8).split("\n",-1);
            if(fields.length!=11)return false;
            long now=System.currentTimeMillis()/1000, expires=Long.parseLong(fields[10]);
            if(expires<now || expires>now+180 || !fields[9].matches("[0-9a-f]{32}"))return false;
            var service=request.httpService();
            String actual=String.join("\n",request.method(),service.host(),Integer.toString(service.port()),
                service.secure()?"https":"http",request.headerValue("Host"),request.path(),
                hash(request.body().getBytes()),hash(request.headerValue("Authorization")),hash(request.headerValue("Cookie")));
            if(!actual.equals(String.join("\n",java.util.Arrays.copyOf(fields,9))))return false;
            used.entrySet().removeIf(entry->entry.getValue()<now);
            if(used.containsKey(fields[9]))return false;
            return !consume || used.putIfAbsent(fields[9],expires)==null;
        } catch(Exception ex) {return false;}
    }
}
