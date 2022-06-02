package aws.sigv4.samples.models;

import aws.sigv4.samples.AwsSigV4Signer;
import com.amazonaws.http.HttpMethodName;
import java.util.Map;
import lombok.*;

/**
 * Input class for {@link AwsSigV4Signer#sign(AwsSigV4SignerInput)}.
 */
@Builder
@Getter
@ToString
@EqualsAndHashCode
public class AwsSigV4SignerInput {

    /**
     * HTTP request payload.
     */
    @NonNull
    private final String requestPayload;

    /**
     * HTTP request endpoint.
     */
    @NonNull
    private final String requestEndpoint;

    /**
     * (optional) Resource path of the request.
     */
    private final String requestResourcePath;

    /**
     * HTTP request method.
     */
    @NonNull
    private final HttpMethodName requestMethod;

    /**
     * AWS service name, to which the request will be sent.
     * Note: Service name for AWS API Gateway is 'execute-api'.
     */
    @NonNull
    private final String serviceName;

    /**
     * Regions in which the AWS service is.
     */
    @NonNull
    private final String regionName;

    /**
     * HTTP request headers. If passed they'll secured with the signature.
     */
    private final Map<String, String> requestHeaderMap;
}
