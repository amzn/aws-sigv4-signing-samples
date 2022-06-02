## Aws SigV4 Signing Samples

This package contains sample code demonstrating
[SigV4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) signing using
[AWS Java SDK](https://aws.amazon.com/sdk-for-java/). It contains two main classes in Java package `aws.sigv4.samples`,
namely `CredentialProviderBasedAwsSigV4Signer` and `IamRoleBasedAwsSigV4Signer`.
These classes show different types of signer implementations.
These classed use AWS SDK's `AWS4Signer` class for signing,
and show how a SigV4 signature can be generated and how the signed headers can be extracted.
These signed headers can then be used with any HTTP request lib
(like [URL connection](https://docs.oracle.com/javase/8/docs/api/java/net/HttpURLConnection.html)),
for sending an SigV4 signed HTTP request.

This package also contains some test cases demonstrating the usage of sample signer classes,
but it doesn't contain any build logic. This package is not meant for direct consumption.
The sample code in this package should only be referred to write you own code.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

