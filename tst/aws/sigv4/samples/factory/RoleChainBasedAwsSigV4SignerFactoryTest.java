package aws.sigv4.samples.factory;

import static org.mockito.Mockito.when;

import com.amazon.lombok.verifiers.Verifier;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.github.benmanes.caffeine.cache.Cache;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("For RoleChainBasedAwsSigV4SignerFactory class")
public class RoleChainBasedAwsSigV4SignerFactoryTest {

    private String defaultAssumeClientRole;
    private String region;
    private String defaultAssumeRoleSessionName;
    private String partnerAssumeRoleSessionName;
    private EasyRandom easyRandom;
    private SigV4SignerFactory awsSigV4SignerFactory;

    @Mock
    private Cache<String, AWSSessionCredentialsProvider> credentialProviderCache;

    @Mock
    private STSAssumeRoleSessionCredentialsProvider credentialsProvider;

    @BeforeEach
    void setUp() {
        easyRandom = new EasyRandom();
        defaultAssumeClientRole = easyRandom.nextObject(String.class);
        region = easyRandom.nextObject(String.class);
        defaultAssumeRoleSessionName = easyRandom.nextObject(String.class);
        partnerAssumeRoleSessionName = easyRandom.nextObject(String.class);
        awsSigV4SignerFactory = new RoleChainBasedAwsSigV4SignerFactory(defaultAssumeClientRole, credentialProviderCache,
                defaultAssumeRoleSessionName, partnerAssumeRoleSessionName);
    }

    @Test
    @DisplayName("arguments of all public methods should be non-null.")
    void nonNullMethodArgsVerification() {
        Verifier.forNonNullMethodArgs().verify(RoleChainBasedAwsSigV4SignerFactory.class);
    }

    @Nested
    @DisplayName("the getAwsSigV4Signer method")
    class GetAwsSigV4Signer {

        @Test
        @DisplayName("should call getAwsSigV4Signer with default role return result.")
        void shouldCallGetAwsSigV4SignerAndReturnResultUsingDefaultRole() {
            awsSigV4SignerFactory.getAwsSigV4Signer(null, region);
        }

        @Test
        @DisplayName("should call getAwsSigV4Signer with provided role return result.")
        void shouldCalGetAwsSigV4SignerAndReturnResultUsingProvidedRole() {
            awsSigV4SignerFactory.getAwsSigV4Signer(easyRandom.nextObject(String.class), region);
        }

        @Test
        @DisplayName("should call getAwsSigV4Signer with provided role and cache hit return result.")
        void shouldCalGetAwsSigV4SignerAndReturnResultUsingProvidedRoleWithCacheHit() {
            String partnerIamRole = easyRandom.nextObject(String.class);
            when(credentialProviderCache.getIfPresent(partnerIamRole)).thenReturn(credentialsProvider);
            awsSigV4SignerFactory.getAwsSigV4Signer(partnerIamRole, region);
        }

        @Test
        @DisplayName("should call getAwsSigV4Signer with default role and cache hit return result.")
        void shouldCalGetAwsSigV4SignerAndReturnResultUsingDefaultRoleWithCacheHit() {
            when(credentialProviderCache.getIfPresent(defaultAssumeClientRole)).thenReturn(credentialsProvider);
            awsSigV4SignerFactory.getAwsSigV4Signer(null, region);
        }
    }
}
