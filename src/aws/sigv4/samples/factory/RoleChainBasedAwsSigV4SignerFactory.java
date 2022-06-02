package aws.sigv4.samples.factory;

import aws.sigv4.samples.AwsSigV4Signer;
import aws.sigv4.samples.CredentialProviderBasedAwsSigV4Signer;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider.Builder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public class RoleChainBasedAwsSigV4SignerFactory implements SigV4SignerFactory {

    @NonNull
    private final String firstLevelChainedIamRoleArn;

    /*
        In credentialProviderCache Key is String which is IamRole Used for STS and Its store corresponding credentials
     */
    @NonNull
    private final Cache<String, AWSSessionCredentialsProvider> credentialProviderCache;

    @NonNull
    private final String defaultAssumeRoleSessionName;

    @NonNull
    private final String partnerAssumeRoleSessionName;

    @Override
    public AwsSigV4Signer getAwsSigV4Signer(String secondLevelChainedIamRoleArn, @NonNull String region) {

        if (secondLevelChainedIamRoleArn == null) {
            if (credentialProviderCache.getIfPresent(firstLevelChainedIamRoleArn) != null) {
                return new CredentialProviderBasedAwsSigV4Signer(
                        credentialProviderCache.getIfPresent(firstLevelChainedIamRoleArn));
            }
            STSAssumeRoleSessionCredentialsProvider firstLevelRoleAssumeRoleSessionCredentialsProvider = new Builder(
                    firstLevelChainedIamRoleArn,
                    defaultAssumeRoleSessionName)
                    .build();
            credentialProviderCache
                    .put(firstLevelChainedIamRoleArn, firstLevelRoleAssumeRoleSessionCredentialsProvider);
            return new CredentialProviderBasedAwsSigV4Signer(firstLevelRoleAssumeRoleSessionCredentialsProvider);
        }
        if (credentialProviderCache.getIfPresent(secondLevelChainedIamRoleArn) != null) {
            return new CredentialProviderBasedAwsSigV4Signer(
                    credentialProviderCache.getIfPresent(secondLevelChainedIamRoleArn));
        }
        STSAssumeRoleSessionCredentialsProvider firstLevelRoleAssumeRoleSessionCredentialsProvider = new Builder(
                firstLevelChainedIamRoleArn,
                defaultAssumeRoleSessionName)
                .build();

        AWSSecurityTokenService awsSecurityTokenService = AWSSecurityTokenServiceClientBuilder
                .standard().withCredentials(firstLevelRoleAssumeRoleSessionCredentialsProvider)
                .withRegion(region).build();

        STSAssumeRoleSessionCredentialsProvider secondLevelRoleAssumeRoleSessionCredentialsProvider = new Builder(
                secondLevelChainedIamRoleArn,
                partnerAssumeRoleSessionName)
                .withStsClient(awsSecurityTokenService)
                .build();
        credentialProviderCache.put(secondLevelChainedIamRoleArn, secondLevelRoleAssumeRoleSessionCredentialsProvider);
        return new CredentialProviderBasedAwsSigV4Signer(secondLevelRoleAssumeRoleSessionCredentialsProvider);
    }
}
