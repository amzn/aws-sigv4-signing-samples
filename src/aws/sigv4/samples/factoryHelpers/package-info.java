
/**
 * This package contains factory helper classed to avoid dependency initialisation in other classes. All classed in this
 * package simply call the constructor of their respective class without modifying the input.
 * <p>
 * This package is excluded from test coverage, since we can't mock constructor calls.
 */
package aws.sigv4.samples.factoryHelpers;
