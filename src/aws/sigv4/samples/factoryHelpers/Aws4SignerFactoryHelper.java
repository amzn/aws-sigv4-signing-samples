package aws.sigv4.samples.factoryHelpers;

import com.amazonaws.auth.AWS4Signer;
import lombok.NonNull;

public final class Aws4SignerFactoryHelper {

    private Aws4SignerFactoryHelper() {
    }

    public static AWS4Signer getSigner(@NonNull final String regionName, @NonNull final String serviceName) {
        var signer = new AWS4Signer();
        signer.setServiceName(serviceName);
        signer.setRegionName(regionName);
        return signer;
    }
}
