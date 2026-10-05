import java.util.List;

import org.seal.xacml.coverage.DecisionCoverage;
import org.seal.xacml.coverage.MCDC;
import org.seal.xacml.coverage.RuleCoverage;
import org.seal.xacml.coverage.RulePairCoverage;

/**
 * Generates one of XPA's test suites for one policy, calling the generator exactly as XPA's own
 * test panel (org.seal.xacml.gui.TestPanel) does, and prints each request on one line. XPA asks
 * its solver through ./z3/build/z3 in the working directory.
 */
public final class XpaSuites {
    private XpaSuites() {}

    public static void main(String[] args) throws Exception {
        String policy = args[0];
        List<String> requests;
        switch (args[1]) {
            case "RC":
                requests = new RuleCoverage(policy).generateTests();
                break;
            case "DC":
                requests = new DecisionCoverage(policy, true).generateTests();
                break;
            case "NE-DC":
                requests = new DecisionCoverage(policy, false).generateTests();
                break;
            case "MCDC":
                requests = new MCDC(policy, true).generateTests();
                break;
            case "NE-MCDC":
                requests = new MCDC(policy, false).generateTests();
                break;
            case "PC":
                requests = new RulePairCoverage(policy).generateTests(false);
                break;
            case "PD-PC":
                requests = new RulePairCoverage(policy).generateTests(true);
                break;
            default:
                throw new IllegalArgumentException("unknown criterion " + args[1]);
        }
        for (String request : requests) {
            System.out.println("REQUEST " + request.replaceAll("\\s*[\\r\\n]+\\s*", " ").trim());
        }
    }
}
