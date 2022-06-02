package aws.sigv4.samples.factory;

import aws.sigv4.samples.AwsSigV4Signer;

public interface SigV4SignerFactory {
    AwsSigV4Signer getAwsSigV4Signer(String partnerIamRole, String region);
}
