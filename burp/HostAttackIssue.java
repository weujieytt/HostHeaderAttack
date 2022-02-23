//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp;

import java.net.URL;

public class HostAttackIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public HostAttackIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    public URL getUrl() {
        return this.url;
    }

    public String getIssueName() {
        return this.name;
    }

    public int getIssueType() {
        return 0;
    }

    public String getSeverity() {
        return this.severity;
    }

    public String getConfidence() {
        return "Certain";
    }

    public String getIssueBackground() {
        return null;
    }

    public String getRemediationBackground() {
        return null;
    }

    public String getIssueDetail() {
        return this.detail;
    }

    public String getRemediationDetail() {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages() {
        return this.httpMessages;
    }

    public IHttpService getHttpService() {
        return this.httpService;
    }
}
