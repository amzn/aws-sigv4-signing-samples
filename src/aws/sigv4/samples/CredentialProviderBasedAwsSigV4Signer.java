package aws.sigv4.samples;

import aws.sigv4.samples.factoryHelpers.Aws4SignerFactoryHelper;
import aws.sigv4.samples.models.AwsSigV4SignerInput;
import aws.sigv4.samples.models.AwsSigV4SignerOutput;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayConfigurationException;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayInvalidInputException;
import com.amazonaws.DefaultRequest;
import com.amazonaws.SignableRequest;
import com.amazonaws.auth.AWSCredentialsProvider;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;

/**
 * Class for signing with AWS SigV4 algorithm, using the execution role of this code.
 */
@AllArgsConstructor
@Log4j2
public class CredentialProviderBasedAwsSigV4Signer implements AwsSigV4Signer {
    @NonNull
    private final AWSCredentialsProvider credentialsProvider;

    /**
     * {@inheritDoc}
     */
    public AwsSigV4SignerOutput sign(@NonNull final AwsSigV4SignerInput input)
            throws PartnerGatewayInvalidInputException, PartnerGatewayConfigurationException {

        log.debug("Starting AWS SigV4 signing process.");
        log.debug("Creating request.");
        var request = createRequest(input);

        log.debug("Creating signer instance.");
        var aws4Signer = Aws4SignerFactoryHelper.getSigner(input.getRegionName(), input.getServiceName());

        log.debug("Signing request.");
        aws4Signer.sign(request, credentialsProvider.getCredentials());

        log.debug("Building response.");
        return AwsSigV4SignerOutput.builder().requestHeaderMap(request.getHeaders()).build();
    }

    private SignableRequest<String> createRequest(final AwsSigV4SignerInput input)
            throws PartnerGatewayInvalidInputException {
        URI requestUri;
        try {
            requestUri = new URI(input.getRequestEndpoint());
        } catch (URISyntaxException e) {
            throw new PartnerGatewayInvalidInputException(
                    String.format("Invalid request endpoint passed in Input: %s", input.getRequestEndpoint()),
                    e);
        }

        return createRequest(requestUri, input);
    }

    private DefaultRequest<String> createRequest(final URI requestUri, final AwsSigV4SignerInput input) {
        var request = new DefaultRequest<String>(input.getServiceName());

        request.setEndpoint(requestUri);
        Optional.ofNullable(input.getRequestResourcePath()).ifPresent(request::setResourcePath);
        request.setHttpMethod(input.getRequestMethod());
        request.setContent(new ByteArrayInputStream(input.getRequestPayload().getBytes(StandardCharsets.UTF_8)));
        Optional.ofNullable(input.getRequestHeaderMap()).ifPresent(request::setHeaders);

        return request;
    }
}
