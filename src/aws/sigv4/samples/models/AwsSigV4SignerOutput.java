package aws.sigv4.samples.models;

import aws.sigv4.samples.AwsSigV4Signer;
import java.util.Map;
import lombok.*;

/**
 * Output class for {@link AwsSigV4Signer#sign(AwsSigV4SignerInput)}.
 */
@Builder
@Getter
@ToString
@EqualsAndHashCode
public class AwsSigV4SignerOutput {

    /**
     * Request headers with signature and related information.
     * Note: If request header were passed in {@link AwsSigV4SignerInput},
     * then these headers will contain all headers passed in input,
     * with additional headers added as part of the signing process.
     */
    @NonNull
    private final Map<String, String> requestHeaderMap;
}
