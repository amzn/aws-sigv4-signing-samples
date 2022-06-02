package aws.sigv4.samples;

import aws.sigv4.samples.models.AwsSigV4SignerInput;
import aws.sigv4.samples.models.AwsSigV4SignerOutput;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayConfigurationException;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayDependencyException;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayInvalidInputException;
import lombok.NonNull;

/**
 * Interface for signing with AWS SigV4 algorithm.
 */
public interface AwsSigV4Signer {

    /**
     * Sign method. It return request header with the signature and related information.
     */
    AwsSigV4SignerOutput sign(@NonNull AwsSigV4SignerInput input)
            throws PartnerGatewayConfigurationException, PartnerGatewayDependencyException,
            PartnerGatewayInvalidInputException;
}
