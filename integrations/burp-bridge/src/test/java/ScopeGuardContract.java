import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.ByteArray;
import java.lang.reflect.Proxy;

/** Contract objects only. No Burp application, target I/O, or Scanner invocation. */
public class ScopeGuardContract {
    public static void main(String[] args) throws Exception {
        String secret=args[0], ticket=args[1];String[] path={"/contract?q=1"};
        HttpService service=(HttpService)Proxy.newProxyInstance(HttpService.class.getClassLoader(),new Class[]{HttpService.class},(p,m,a)->switch(m.getName()) {
            case "host"->"10.0.0.1";case "port"->8080;case "secure"->false;default->null;});
        ByteArray body=(ByteArray)Proxy.newProxyInstance(ByteArray.class.getClassLoader(),new Class[]{ByteArray.class},(p,m,a)->m.getName().equals("getBytes")?"contract-body".getBytes():null);
        HttpRequest request=(HttpRequest)Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),new Class[]{HttpRequest.class},(p,m,a)->switch(m.getName()) {
            case "httpService"->service;case "method"->"POST";case "path"->path[0];case "body"->body;
            case "headerValue"->switch(((String)a[0]).toLowerCase()) {
                case "host"->"app.lab:8080";case "authorization"->"Bearer offline";case "cookie"->"sid=offline";case "x-pentest-master-scope"->ticket;default->null;};default->null;});
        ScopeGuard guard=new ScopeGuard(secret);
        if(!guard.allows(request,false))throw new AssertionError("Valid Python-issued scope ticket rejected");
        path[0]="/outside";
        if(guard.allows(request,false))throw new AssertionError("Mutated path was accepted");
        path[0]="/contract?q=1";
        if(!guard.allows(request,true)||guard.allows(request,true))throw new AssertionError("Nonce is not single use");
        System.out.println("PASS Montoya 2026.7 compile and HMAC/path/single-use contract; NOT a live Burp test");
    }
}
