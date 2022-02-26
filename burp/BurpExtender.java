//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp;

import burp.utill.RandomString;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private String version = "0.1";

    public BurpExtender() {
    }

    List<int[]> getMatches(byte[] response, byte[] math) {
        List<int[]> matches = new ArrayList();

        for (int start = 0; start < response.length; start += math.length) {
            start = this.helpers.indexOf(response, math, true, start, response.length);
            if (start == -1) {
                break;
            }

            matches.add(new int[]{start, start + math.length});
        }

        return matches;
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callback) {
        this.callbacks = callback;
        this.helpers = this.callbacks.getHelpers();
        this.callbacks.setExtensionName("HostHeaderAttack");
        this.stdout = new PrintWriter(this.callbacks.getStdout(), true);
        this.callbacks.registerScannerCheck(this);
        this.stdout.println("Loaded Successfully HostHeaderAttack!");
        this.stdout.println("GitHub: https://github.com/weujieytt/HostHeaderAttack");
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        String url = this.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        String[] spUrl = url.split("/");
        String endUrl = spUrl[spUrl.length - 1];
        /**
         *
         */
        if (!endUrl.contains(".js") &&
                !endUrl.contains(".css") && !endUrl.contains(".png") && !endUrl.contains(".jpg")
                && !endUrl.contains(".jpeg") && !endUrl.contains(".svg") && !endUrl.contains(".woff") && !endUrl.contains(".gif")) {
            String EVAL_HOST = RandomString.randomHost(7);
            IHttpRequestResponse makeResponse = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), (new HostAttackScanner()).requestRaw(this.helpers, baseRequestResponse, EVAL_HOST));
            if (makeResponse.getResponse() != null) {
                List<int[]> matches = this.getMatches(makeResponse.getResponse(), EVAL_HOST.getBytes(StandardCharsets.UTF_8));
                if (matches.size() > 0) {
                    stdout.println("[+] Vulnerable URL: " + url);
                    List<IScanIssue> issues = new ArrayList(1);
                    List<int[]> sendHostMatches  = this.getMatches(makeResponse.getRequest(), EVAL_HOST.getBytes(StandardCharsets.UTF_8));  // 获取request请求包中插入数据的位置

                    //对reqeust、response中将插入数据进行高亮展示
                    issues.add(new HostAttackIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(makeResponse, sendHostMatches, matches)}, "Host header attack ", "The response contains the eval host: " + this.helpers.bytesToString(EVAL_HOST.getBytes(StandardCharsets.UTF_8)), "Medium"));
                    return issues;
                }
            }
        }

        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0;
    }
}
