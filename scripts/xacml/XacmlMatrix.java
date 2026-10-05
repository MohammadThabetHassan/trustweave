import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.wso2.balana.Balana;
import org.wso2.balana.DOMHelper;
import org.wso2.balana.PDP;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.Policy;
import org.wso2.balana.PolicySet;
import org.wso2.balana.ctx.AbstractRequestCtx;
import org.wso2.balana.ctx.AbstractResult;
import org.wso2.balana.ctx.RequestCtxFactory;
import org.wso2.balana.ctx.ResponseCtx;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.PolicyFinderModule;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;

/**
 * Decides every loaded request against each policy it is given, with Balana. Standard input
 * holds commands, one per line: "REQUESTS path" parses the file's requests, one per line, once;
 * "POLICY path" decides all of them against the policy in that file and prints one line,
 * "DECISIONS " followed by one letter per request in order: P(ermit), D(eny), N(otApplicable)
 * or I(ndeterminate, of any kind). A request the engine cannot read is decided I, as Balana's
 * own response to it would be.
 */
public final class XacmlMatrix {
    private XacmlMatrix() {}

    private static PDP pdpFor(String path) {
        Set<String> locations = new HashSet<>();
        locations.add(new File(path).getAbsolutePath());
        PolicyFinder finder = new PolicyFinder();
        Set<PolicyFinderModule> modules = new HashSet<>();
        modules.add(new FileBasedPolicyFinderModule(locations));
        finder.setModules(modules);
        PDPConfig base = Balana.getInstance().getPdpConfig();
        return new PDP(new PDPConfig(base.getAttributeFinder(), finder, base.getResourceFinder(), false));
    }

    /** Null when Balana's own reader accepts the file as a Policy or PolicySet; else why not. */
    private static String readable(String path) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Element root = factory.newDocumentBuilder().parse(new File(path)).getDocumentElement();
            String name = DOMHelper.getLocalName(root);
            if (name.equals("Policy")) {
                Policy.getInstance(root);
            } else if (name.equals("PolicySet")) {
                PolicySet.getInstance(root, new PolicyFinder());
            } else {
                return "root element " + name;
            }
            return null;
        } catch (Exception error) {
            return String.valueOf(error);
        }
    }

    private static char letter(ResponseCtx response) {
        int decision = response.getResults().iterator().next().getDecision();
        switch (decision) {
            case AbstractResult.DECISION_PERMIT:
                return 'P';
            case AbstractResult.DECISION_DENY:
                return 'D';
            case AbstractResult.DECISION_NOT_APPLICABLE:
                return 'N';
            default:
                return 'I';
        }
    }

    public static void main(String[] args) throws Exception {
        List<AbstractRequestCtx> requests = new ArrayList<>();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(new BufferedOutputStream(System.out), false, "UTF-8");
        String line;
        while ((line = in.readLine()) != null) {
            if (line.startsWith("REQUESTS ")) {
                requests = new ArrayList<>();
                for (String request : Files.readAllLines(new File(line.substring(9)).toPath(), StandardCharsets.UTF_8)) {
                    if (request.isEmpty()) {
                        continue;
                    }
                    try {
                        requests.add(RequestCtxFactory.getFactory().getRequestCtx(request));
                    } catch (Exception unreadable) {
                        requests.add(null);
                    }
                }
                out.println("LOADED " + requests.size());
                out.flush();
            } else if (line.startsWith("POLICY ")) {
                String path = line.substring(7);
                String unloadable = readable(path);
                if (unloadable != null) {
                    // An empty policy finder decides NotApplicable everywhere, which would score a
                    // policy the engine cannot read as a policy that permits nothing.
                    out.println("UNLOADABLE " + unloadable.replace('\n', ' '));
                    out.flush();
                    continue;
                }
                PDP pdp = pdpFor(path);
                StringBuilder decisions = new StringBuilder(requests.size());
                try {
                    for (AbstractRequestCtx request : requests) {
                        decisions.append(request == null ? 'I' : letter(pdp.evaluate(request)));
                    }
                    out.println("DECISIONS " + decisions);
                } catch (RuntimeException error) {
                    // A policy the engine reads but fails while evaluating is not scored at all.
                    out.println("UNEVALUABLE " + String.valueOf(error).replace('\n', ' '));
                }
                out.flush();
            }
        }
        out.flush();
    }
}
