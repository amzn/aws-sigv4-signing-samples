package aws.sigv4.samples.models;

import lombok.*;

@Builder
@Getter
@ToString
@EqualsAndHashCode
public class IamRoleBasedAwsSigV4SignerConfig {

    @NonNull
    private final String iamRoleAnr;

    @NonNull
    private final String assumeRoleSessionName;
}
