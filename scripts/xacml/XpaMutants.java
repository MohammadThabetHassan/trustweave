import java.io.File;

import org.seal.xacml.mutation.PolicyMutator;

/**
 * Runs XPA's own mutation operators, PolicyMutator.createAllMutants() as XPA defines it, on one
 * policy. XPA writes each mutant to a "mutants" folder beside the policy; this prints that folder.
 */
public final class XpaMutants {
    private XpaMutants() {}

    public static void main(String[] args) throws Exception {
        File policy = new File(args[0]).getAbsoluteFile();
        PolicyMutator mutator = new PolicyMutator(policy.getPath());
        mutator.createAllMutants();
        System.out.println("MUTANTS " + new File(policy.getParentFile(), "mutants").getPath());
    }
}
