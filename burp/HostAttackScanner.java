//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class HostAttackScanner {
    public HostAttackScanner() {
    }

    public byte[] requestRaw(IExtensionHelpers helpers, IHttpRequestResponse messagesInfo, String evalHost) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messagesInfo.getRequest());
        List<String> headers = requestInfo.getHeaders();
        int bodyBegin = requestInfo.getBodyOffset();
        byte[] body = (new String(messagesInfo.getRequest())).substring(bodyBegin).getBytes(StandardCharsets.UTF_8);
        System.out.println(headers);
        headers.removeIf(header ->  header.startsWith("Host:"));
        headers.add(1, "Host: " + evalHost);
        return helpers.buildHttpMessage(headers, body);
    }
}
