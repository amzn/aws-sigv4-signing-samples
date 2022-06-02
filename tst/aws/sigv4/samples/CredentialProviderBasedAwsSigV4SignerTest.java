package aws.sigv4.samples;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import aws.sigv4.samples.factoryHelpers.Aws4SignerFactoryHelper;
import aws.sigv4.samples.models.AwsSigV4SignerInput;
import com.amazon.financialservices.insurance.partnergateway.commons.exceptions.PartnerGatewayInvalidInputException;
import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.http.HttpMethodName;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("For ExecutionRoleBasedAwsSigV4Signer class,")
@ExtendWith(MockitoExtension.class)
class CredentialProviderBasedAwsSigV4SignerTest {

    private EasyRandom easyRandom;

    @Mock
    private AWS4Signer mockAws4Signer;

    @Mock
    private AWSCredentialsProvider mockAwsCredentialsProvider;

    private MockedStatic<Aws4SignerFactoryHelper> aws4SignerFactoryHelperMockedStatic;

    private CredentialProviderBasedAwsSigV4Signer signer;

    private String testService;

    private String testRegion;

    @BeforeEach
    void beforeEach() {
        easyRandom = new EasyRandom();

        signer = new CredentialProviderBasedAwsSigV4Signer(mockAwsCredentialsProvider);

        testService = easyRandom.nextObject(String.class);
        testRegion = easyRandom.nextObject(String.class);
        aws4SignerFactoryHelperMockedStatic = mockStatic(Aws4SignerFactoryHelper.class);
        aws4SignerFactoryHelperMockedStatic
                .when(() -> Aws4SignerFactoryHelper.getSigner(testRegion, testService))
                .thenReturn(mockAws4Signer);
    }

    @Nested
    @DisplayName("the sign method,")
    class SignMethod {

        private AwsSigV4SignerInput.AwsSigV4SignerInputBuilder inputBuilder;
        private AwsSigV4SignerInput signerInput;

        @BeforeEach
        void beforeEach() {
            inputBuilder = AwsSigV4SignerInput.builder();
        }

        @Nested
        @DisplayName("with invalid URI in requestEndpoint input param,")
        class WithInvalidRequestEndpoint {

            @BeforeEach
            void beforeEach() {
                signerInput = inputBuilder
                        .requestEndpoint("Invalid`URI")
                        .requestResourcePath(easyRandom.nextObject(String.class))
                        .requestPayload(easyRandom.nextObject(String.class))
                        .serviceName(testService)
                        .regionName(testRegion)
                        .requestMethod(easyRandom.nextObject(HttpMethodName.class))
                        .requestHeaderMap(easyRandom.nextObject(Map.class))
                        .build();
            }

            @Test
            @DisplayName("should throw PartnerGatewayInvalidInputException.")
            void shouldThrowException() {
                assertThatThrownBy(() -> signer.sign(signerInput))
                        .isInstanceOf(PartnerGatewayInvalidInputException.class)
                        .hasMessage(String.format("Invalid request endpoint passed in Input: %s",
                                signerInput.getRequestEndpoint()))
                        .hasCauseInstanceOf(URISyntaxException.class);
            }
        }

        @Nested
        @DisplayName("with valid URI in requestEndpoint input param,")
        class WithValidRequestEndpoint {
            @Mock
            private AWSCredentials testCredentials;

            private Map<String, String> testOutputRequestHeaderMap;

            @Captor
            private ArgumentCaptor<DefaultRequest<String>> requestCaptor;

            @Captor
            private ArgumentCaptor<AWSCredentials> credentialsCaptor;

            private Map<String, String> requestHeaderMap;


            @BeforeEach
            void beforeEach() {
                signerInput = inputBuilder
                        .requestEndpoint("ValidURI")
                        .requestResourcePath(easyRandom.nextObject(String.class))
                        .requestPayload(easyRandom.nextObject(String.class))
                        .serviceName(testService)
                        .regionName(testRegion)
                        .requestMethod(easyRandom.nextObject(HttpMethodName.class))
                        .requestHeaderMap(easyRandom.nextObject(Map.class))
                        .build();

                testOutputRequestHeaderMap = easyRandom.nextObject(Map.class);

                when(mockAwsCredentialsProvider.getCredentials()).thenReturn(testCredentials);

                doAnswer((invocation) -> {
                    DefaultRequest<String> request = invocation.getArgument(0);
                    request.setHeaders(testOutputRequestHeaderMap);
                    return request;
                }).when(mockAws4Signer).sign(requestCaptor.capture(), credentialsCaptor.capture());

                requestHeaderMap = signerInput.getRequestHeaderMap();
            }

            @Test
            @DisplayName("should returned request headers with signature.")
            @SneakyThrows
            void shouldReturnResponse() {
                var output = signer.sign(signerInput);
                assertThat(output.getRequestHeaderMap()).isEqualTo(testOutputRequestHeaderMap);
            }

            @Nested
            @DisplayName("with no request headers in input,")
            class WithNoRequestHeaders {
                @BeforeEach
                void beforeEach() {
                    signerInput = inputBuilder
                            .requestEndpoint("ValidURI")
                            .requestPayload(easyRandom.nextObject(String.class))
                            .serviceName(testService)
                            .regionName(testRegion)
                            .requestMethod(easyRandom.nextObject(HttpMethodName.class))
                            .build();

                    requestHeaderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                }

                @Test
                @DisplayName("should returned request headers with signature.")
                @SneakyThrows
                void shouldReturnResponse() {
                    var output = signer.sign(signerInput);
                    assertThat(output.getRequestHeaderMap()).isEqualTo(testOutputRequestHeaderMap);
                }
            }

            @Nested
            @DisplayName("with no request resource path in input,")
            class WithNoRequestResourcePath {
                @BeforeEach
                void beforeEach() {
                    signerInput = inputBuilder
                            .requestEndpoint("ValidURI")
                            .requestPayload(easyRandom.nextObject(String.class))
                            .serviceName(testService)
                            .regionName(testRegion)
                            .requestMethod(easyRandom.nextObject(HttpMethodName.class))
                            .requestHeaderMap(easyRandom.nextObject(Map.class))
                            .build();

                    requestHeaderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                }

                @Test
                @DisplayName("should returned request headers with signature.")
                @SneakyThrows
                void shouldReturnResponse() {
                    var output = signer.sign(signerInput);
                    assertThat(output.getRequestHeaderMap()).isEqualTo(testOutputRequestHeaderMap);
                }
            }

            @AfterEach
            @SneakyThrows
            void afterEach() {
                var request = requestCaptor.getValue();
                assertThat(request.getEndpoint().toString()).isEqualTo(signerInput.getRequestEndpoint());
                assertThat(IOUtils.toString(request.getContent(), StandardCharsets.UTF_8))
                        .isEqualTo(signerInput.getRequestPayload());
                assertThat(request.getHeaders()).isEqualTo(requestHeaderMap);

                var credentials = credentialsCaptor.getValue();
                assertThat(credentials).isEqualTo(testCredentials);
            }
        }
    }

    @AfterEach
    void afterEach() {
        aws4SignerFactoryHelperMockedStatic.close();
    }
}
