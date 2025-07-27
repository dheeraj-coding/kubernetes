/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package x509

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	asn1util "k8s.io/apimachinery/pkg/apis/asn1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/lazy"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
)

/*
 * By default, the following metric is defined as falling under
 * ALPHA stability level https://github.com/kubernetes/enhancements/blob/master/keps/sig-instrumentation/1209-metrics-stability/kubernetes-control-plane-metrics-stability.md#stability-classes)
 *
 * Promoting the stability level of the metric is a responsibility of the component owner, since it
 * involves explicitly acknowledging support for the metric across multiple releases, in accordance with
 * the metric stability policy.
 */
var clientCertificateExpirationHistogram = metrics.NewHistogram(
	&metrics.HistogramOpts{
		Namespace: "apiserver",
		Subsystem: "client",
		Name:      "certificate_expiration_seconds",
		Help:      "Distribution of the remaining lifetime on the certificate used to authenticate a request.",
		Buckets: []float64{
			0,
			1800,     // 30 minutes
			3600,     // 1 hour
			7200,     // 2 hours
			21600,    // 6 hours
			43200,    // 12 hours
			86400,    // 1 day
			172800,   // 2 days
			345600,   // 4 days
			604800,   // 1 week
			2592000,  // 1 month
			7776000,  // 3 months
			15552000, // 6 months
			31104000, // 1 year
		},
		StabilityLevel: metrics.ALPHA,
	},
)

func init() {
	legacyregistry.MustRegister(clientCertificateExpirationHistogram)
}

// UserConversion defines an interface for extracting user info from a client certificate chain
type UserConversion interface {
	User(chain []*x509.Certificate) (*authenticator.Response, bool, error)
}

// UserConversionFunc is a function that implements the UserConversion interface.
type UserConversionFunc func(chain []*x509.Certificate) (*authenticator.Response, bool, error)

// User implements x509.UserConversion
func (f UserConversionFunc) User(chain []*x509.Certificate) (*authenticator.Response, bool, error) {
	return f(chain)
}

func columnSeparatedHex(d []byte) string {
	h := strings.ToUpper(hex.EncodeToString(d))
	var sb strings.Builder
	for i, r := range h {
		sb.WriteRune(r)
		if i%2 == 1 && i != len(h)-1 {
			sb.WriteRune(':')
		}
	}
	return sb.String()
}

func certificateIdentifier(c *x509.Certificate) string {
	return fmt.Sprintf(
		"SN=%d, SKID=%s, AKID=%s",
		c.SerialNumber,
		columnSeparatedHex(c.SubjectKeyId),
		columnSeparatedHex(c.AuthorityKeyId),
	)
}

// VerifyOptionFunc is function which provides a shallow copy of the VerifyOptions to the authenticator.  This allows
// for cases where the options (particularly the CAs) can change.  If the bool is false, then the returned VerifyOptions
// are ignored and the authenticator will express "no opinion".  This allows a clear signal for cases where a CertPool
// is eventually expected, but not currently present.
type VerifyOptionFunc func() (x509.VerifyOptions, bool)

// Authenticator implements request.Authenticator by extracting user info from verified client certificates
type Authenticator struct {
	verifyOptionsFn VerifyOptionFunc
	user            UserConversion
}

type AuthenticatorWithCEL struct {
	verifyOptionsFn VerifyOptionFunc
	user            UserConversion
	celMapper       authenticationcel.CELMapper
	certConfig      apiserver.X509AuthConfig
}

// New returns a request.Authenticator that verifies client certificates using the provided
// VerifyOptions, and converts valid certificate chains into user.Info using the provided UserConversion
func New(opts x509.VerifyOptions, user UserConversion) *Authenticator {
	return NewDynamic(StaticVerifierFn(opts), user)
}

// NewDynamic returns a request.Authenticator that verifies client certificates using the provided
// VerifyOptionFunc (which may be dynamic), and converts valid certificate chains into user.Info using the provided UserConversion
func NewDynamic(verifyOptionsFn VerifyOptionFunc, user UserConversion) *Authenticator {
	return &Authenticator{verifyOptionsFn, user}
}

func NewDynamicWithCel(certConfig apiserver.X509AuthConfig, verifyOptionsFn VerifyOptionFunc, user UserConversion) (*AuthenticatorWithCEL, error) {
	compiler := authenticationcel.NewDefaultCompiler()
	celMapper, fieldErr := apiservervalidation.CompileAndValidateCertAuthenticator(compiler, certConfig)

	if err := fieldErr.ToAggregate(); err != nil {
		return nil, err
	}
	return &AuthenticatorWithCEL{verifyOptionsFn, user, celMapper, certConfig}, nil
}

type CertRequest struct {
	RemoteAddr string
}

func (a *AuthenticatorWithCEL) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}

	var reqInfoVal *lazy.MapValue
	if a.celMapper.RequestValidationRules != nil {
		klog.InfoS("KEP x509", "remoteaddr", req.RemoteAddr)
		reqInfoVal = newRequestInfoValue(req)

		evalResult, err := a.celMapper.RequestValidationRules.EvalRequest(reqInfoVal)
		if err != nil {
			return nil, false, fmt.Errorf("x509: error evaluating request info validation rules: %w", err)
		}
		if err := checkValidationRulesEvaluation(evalResult, func(a authenticationcel.ExpressionAccessor) (string, error) {
			reqValidationCondition, ok := a.(*authenticationcel.RequestValidationCondition)
			if !ok {
				return "", fmt.Errorf("invalid type conversion, expected UserValidationCondition")
			}
			return reqValidationCondition.Message, nil
		}); err != nil {
			return nil, false, fmt.Errorf("x509: error evaluating request info validation rule: %w", err)
		}
	}

	optsCopy, ok := a.verifyOptionsFn()

	if !ok {
		return nil, false, nil
	}
	if optsCopy.Intermediates == nil && len(req.TLS.PeerCertificates) > 1 {
		optsCopy.Intermediates = x509.NewCertPool()
		for _, intermediate := range req.TLS.PeerCertificates[1:] {
			optsCopy.Intermediates.AddCert(intermediate)
		}
	}

	chains, err := req.TLS.PeerCertificates[0].Verify(optsCopy)
	if err != nil {
		return nil, false, fmt.Errorf(
			"verifyiing certificate %s failed: %w",
			certificateIdentifier(req.TLS.PeerCertificates[0]),
			err,
		)
	}

	var errlist []error
	for _, chain := range chains {
		user, ok, err := a.user.User(chain)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}

		if ok {
			return user, ok, err
		}
	}
	return nil, false, utilerrors.NewAggregate(errlist)

}

func newRequestInfoValue(request *http.Request) *lazy.MapValue {
	lazyMap := lazy.NewMapValue(types.NewObjectType("kubernetes.Request"))
	field := func(name string, get func() any) {
		lazyMap.Append(name, func(_ *lazy.MapValue) ref.Val {
			value := get()
			return nativeToValueWithUnescape(value)
		})
	}

	req := CertRequest{
		RemoteAddr: strings.Split(request.RemoteAddr, ":")[0],
	}
	field("remoteaddr", func() any { return req.RemoteAddr })
	return lazyMap
}

func newUserInfoValue(info user.Info) *lazy.MapValue {
	lazyMap := lazy.NewMapValue(types.NewObjectType("kubernetes.UserInfo"))
	field := func(name string, get func() any) {
		lazyMap.Append(name, func(_ *lazy.MapValue) ref.Val {
			value := get()
			return nativeToValueWithUnescape(value)
		})
	}
	field("username", func() any { return info.GetName() })
	field("uid", func() any { return info.GetUID() })
	field("groups", func() any { return info.GetGroups() })
	field("extra", func() any { return info.GetExtra() })
	return lazyMap
}

func nativeToValueWithUnescape(value any) ref.Val {
	return unescapeWrapper(types.DefaultTypeAdapter.NativeToValue(value))
}

type unescapeMapper struct {
	traits.Mapper
}

func (m *unescapeMapper) Find(key ref.Val) (ref.Val, bool) {
	name, ok := unescapedName(key)
	if ok {
		key = name
	}
	value, ok := m.Mapper.Find(key)
	return unescapeWrapper(value), ok
}

type unescapeLister struct {
	traits.Lister
}

func (l *unescapeLister) Get(index ref.Val) ref.Val {
	return unescapeWrapper(l.Lister.Get(index))
}

// unescapeWrapper handles __dot__ based field access for native types that are converted into CEL values.
// This means we need to handle map lookups for our native types (the claims JSON and the user info data).
// User info is straightforward since it just has a single map field that needs the __dot__ support.  The
// claims JSON is more complicated because maps can appear in deeply nested fields.  This means that we need
// to account for both nested JSON objects and nested JSON arrays in all contexts where we return a CEL value.
// It is safe to pass any CEL value to this function, including nil (i.e. the caller can skip error checking).
func unescapeWrapper(value ref.Val) ref.Val {
	switch v := value.(type) {
	case traits.Mapper:
		return &unescapeMapper{Mapper: v} // handle nested JSON objects
	case traits.Lister:
		return &unescapeLister{Lister: v} // handle nested JSON arrays
	default:
		return value
	}
}

func unescapedName(key ref.Val) (types.String, bool) {
	n, ok := key.(types.String)
	if !ok {
		return "", false
	}
	ns := string(n)
	name, ok := cel.Unescape(ns)
	if !ok || name == ns {
		return "", false
	}
	return types.String(name), true
}

// messageFunc is a function that returns a message for a validation rule.
type messageFunc func(authenticationcel.ExpressionAccessor) (string, error)

func checkValidationRulesEvaluation(results []authenticationcel.EvaluationResult, messageFn messageFunc) error {
	for _, result := range results {
		if result.EvalResult.Type() != celgo.BoolType {
			return fmt.Errorf("validation expression must return a boolean")
		}
		if !result.EvalResult.Value().(bool) {
			expression := result.ExpressionAccessor.GetExpression()

			message, err := messageFn(result.ExpressionAccessor)
			if err != nil {
				return err
			}

			return fmt.Errorf("validation expression '%s' failed: %s", expression, message)
		}
	}

	return nil
}

// AuthenticateRequest authenticates the request using presented client certificates
func (a *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}

	// Use intermediates, if provided
	optsCopy, ok := a.verifyOptionsFn()
	// if there are intentionally no verify options, then we cannot authenticate this request
	if !ok {
		return nil, false, nil
	}
	if optsCopy.Intermediates == nil && len(req.TLS.PeerCertificates) > 1 {
		optsCopy.Intermediates = x509.NewCertPool()
		for _, intermediate := range req.TLS.PeerCertificates[1:] {
			optsCopy.Intermediates.AddCert(intermediate)
		}
	}

	/*
			kubernetes mutual (2-way) x509 between client and apiserver:

				1. apiserver sending its apiserver certificate along with its publickey to client
				2. client verifies the apiserver certificate sent against its cluster certificate authority data
				3. client sending its client certificate along with its public key to the apiserver
				>4. apiserver verifies the client certificate sent against its cluster certificate authority data

		    	description:
					here, with this function,
					client certificate and pub key sent during the handshake process
					are verified by apiserver against its cluster certificate authority data

				normal args related to this stage:
					--client-ca-file string   If set, any request presenting a client certificate signed by
						one of the authorities in the client-ca-file is authenticated with an identity
						corresponding to the CommonName of the client certificate.

					(retrievable from "kube-apiserver --help" command)
					(suggested by @deads2k)

				see also:
					- for the step 1, see: staging/src/k8s.io/apiserver/pkg/server/options/serving.go
					- for the step 2, see: staging/src/k8s.io/client-go/transport/transport.go
					- for the step 3, see: staging/src/k8s.io/client-go/transport/transport.go
	*/

	remaining := req.TLS.PeerCertificates[0].NotAfter.Sub(time.Now())
	clientCertificateExpirationHistogram.WithContext(req.Context()).Observe(remaining.Seconds())
	chains, err := req.TLS.PeerCertificates[0].Verify(optsCopy)
	if err != nil {
		return nil, false, fmt.Errorf(
			"verifying certificate %s failed: %w",
			certificateIdentifier(req.TLS.PeerCertificates[0]),
			err,
		)
	}

	var errlist []error
	for _, chain := range chains {
		user, ok, err := a.user.User(chain)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}

		if ok {
			return user, ok, err
		}
	}
	return nil, false, utilerrors.NewAggregate(errlist)
}

// Verifier implements request.Authenticator by verifying a client cert on the request, then delegating to the wrapped auth
type Verifier struct {
	verifyOptionsFn VerifyOptionFunc
	auth            authenticator.Request

	// allowedCommonNames contains the common names which a verified certificate is allowed to have.
	// If empty, all verified certificates are allowed.
	allowedCommonNames StringSliceProvider
}

// NewVerifier create a request.Authenticator by verifying a client cert on the request, then delegating to the wrapped auth
func NewVerifier(opts x509.VerifyOptions, auth authenticator.Request, allowedCommonNames sets.String) authenticator.Request {
	return NewDynamicCAVerifier(StaticVerifierFn(opts), auth, StaticStringSlice(allowedCommonNames.List()))
}

// NewDynamicCAVerifier create a request.Authenticator by verifying a client cert on the request, then delegating to the wrapped auth
func NewDynamicCAVerifier(verifyOptionsFn VerifyOptionFunc, auth authenticator.Request, allowedCommonNames StringSliceProvider) authenticator.Request {
	return &Verifier{verifyOptionsFn, auth, allowedCommonNames}
}

// AuthenticateRequest verifies the presented client certificate, then delegates to the wrapped auth
func (a *Verifier) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}

	// Use intermediates, if provided
	optsCopy, ok := a.verifyOptionsFn()
	// if there are intentionally no verify options, then we cannot authenticate this request
	if !ok {
		return nil, false, nil
	}
	if optsCopy.Intermediates == nil && len(req.TLS.PeerCertificates) > 1 {
		optsCopy.Intermediates = x509.NewCertPool()
		for _, intermediate := range req.TLS.PeerCertificates[1:] {
			optsCopy.Intermediates.AddCert(intermediate)
		}
	}

	if _, err := req.TLS.PeerCertificates[0].Verify(optsCopy); err != nil {
		return nil, false, err
	}
	if err := a.verifySubject(req.TLS.PeerCertificates[0].Subject); err != nil {
		return nil, false, err
	}
	return a.auth.AuthenticateRequest(req)
}

func (a *Verifier) verifySubject(subject pkix.Name) error {
	// No CN restrictions
	if len(a.allowedCommonNames.Value()) == 0 {
		return nil
	}
	// Enforce CN restrictions
	for _, allowedCommonName := range a.allowedCommonNames.Value() {
		if allowedCommonName == subject.CommonName {
			return nil
		}
	}
	return fmt.Errorf("x509: subject with cn=%s is not in the allowed list", subject.CommonName)
}

// DefaultVerifyOptions returns VerifyOptions that use the system root certificates, current time,
// and requires certificates to be valid for client auth (x509.ExtKeyUsageClientAuth)
func DefaultVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// CommonNameUserConversion builds user info from a certificate chain using the subject's CommonName
var CommonNameUserConversion = UserConversionFunc(func(chain []*x509.Certificate) (*authenticator.Response, bool, error) {
	if len(chain[0].Subject.CommonName) == 0 {
		return nil, false, nil
	}

	fp := sha256.Sum256(chain[0].Raw)
	id := "X509SHA256=" + hex.EncodeToString(fp[:])

	uid, err := parseUIDFromCert(chain[0])
	if err != nil {
		return nil, false, err
	}
	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   chain[0].Subject.CommonName,
			UID:    uid,
			Groups: chain[0].Subject.Organization,
			Extra: map[string][]string{
				user.CredentialIDKey: {id},
			},
		},
	}, true, nil
})

var uidOID = asn1util.X509UID()

func parseUIDFromCert(cert *x509.Certificate) (string, error) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.AllowParsingUserUIDFromCertAuth) {
		return "", nil
	}

	uids := []string{}
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(uidOID) {
			continue
		}
		uid, ok := name.Value.(string)
		if !ok {
			return "", fmt.Errorf("unable to parse UID into a string")
		}
		uids = append(uids, uid)
	}
	if len(uids) == 0 {
		return "", nil
	}
	if len(uids) != 1 {
		return "", fmt.Errorf("expected 1 UID, but found multiple: %v", uids)
	}
	if uids[0] == "" {
		return "", errors.New("UID cannot be an empty string")
	}
	return uids[0], nil
}
