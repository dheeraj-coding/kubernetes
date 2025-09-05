package requestvalidation

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/lazy"
	"k8s.io/klog/v2"
)

type AuthRequest struct {
	RemoteIP              string
	RemotePort            string
	Header                RequestHeader
	CertificateIssuerName string
}

type RequestHeader struct {
	Host          string
	UserAgent     string
	Authorization RequestAuthorization
}

type RequestAuthorization struct {
	Scheme string
}

type RequestValidator struct {
	celMapper     authenticationcel.CELMapper
	Authenticator authenticator.Request
}

func New(reqValidationRules []apiserver.RequestValidationRule, auth authenticator.Request) (*RequestValidator, error) {
	compiler := authenticationcel.NewDefaultCompiler()
	celMapper, fieldErr := apiservervalidation.CompileAndValidateRequestValidationRules(compiler, reqValidationRules)

	if err := fieldErr.ToAggregate(); err != nil {
		return nil, err
	}
	return &RequestValidator{celMapper: celMapper, Authenticator: auth}, nil
}

func (a *RequestValidator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	r, ok, err := a.Authenticator.AuthenticateRequest(req)
	if err != nil || !ok {
		return nil, ok, err
	}
	if a.celMapper.RequestValidationRules == nil {
		return nil, false, nil
	}

	var reqInfoVal *lazy.MapValue
	klog.InfoS("KEP request", "remoteaddr", req.RemoteAddr)
	reqInfoVal = newRequestInfoValue(req)

	evalResult, err := a.celMapper.RequestValidationRules.EvalRequest(reqInfoVal)
	if err != nil {
		return nil, false, fmt.Errorf("request: error evaluating request info validation rules: %w", err)
	}
	if err := checkValidationRulesEvaluation(evalResult, func(a authenticationcel.ExpressionAccessor) (string, error) {
		reqValidationCondition, ok := a.(*authenticationcel.RequestValidationCondition)
		if !ok {
			return "", fmt.Errorf("invalid type conversion, expected RequestValidationCondition")
		}
		return reqValidationCondition.Message, nil
	}); err != nil {
		return nil, false, fmt.Errorf("request: error evaluating request info validation rule: %w", err)
	}

	return r, true, nil

}

func newRequestInfoValue(request *http.Request) *lazy.MapValue {
	lazyMap := lazy.NewMapValue(types.NewObjectType("kubernetes.Request"))

	// Create the `Header` nested map
	headerMap := lazy.NewMapValue(types.NewObjectType("kubernetes.Header"))
	headerMap.Append("Host", func(_ *lazy.MapValue) ref.Val {
		return nativeToValueWithUnescape(request.Header.Get("Host"))
	})
	headerMap.Append("UserAgent", func(_ *lazy.MapValue) ref.Val {
		return nativeToValueWithUnescape(request.Header.Get("User-Agent"))
	})

	// Create the `Authorization` nested map
	authMap := lazy.NewMapValue(types.NewObjectType("kubernetes.Authorization"))
	authMap.Append("Scheme", func(_ *lazy.MapValue) ref.Val {
		authHeader := request.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			return nativeToValueWithUnescape(parts[0])
		}
		return nativeToValueWithUnescape("")
	})
	headerMap.Append("Authorization", func(_ *lazy.MapValue) ref.Val {
		return authMap
	})

	// Append top-level fields to the main map
	lazyMap.Append("RemoteIP", func(_ *lazy.MapValue) ref.Val {
		remoteIP, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			return types.NewErr("failed to parse RemoteAddr: %w", err)
		}
		return nativeToValueWithUnescape(remoteIP)
	})
	lazyMap.Append("RemotePort", func(_ *lazy.MapValue) ref.Val {
		_, remotePort, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			return types.NewErr("failed to parse RemoteAddr: %w", err)
		}
		return nativeToValueWithUnescape(remotePort)
	})
	lazyMap.Append("Header", func(_ *lazy.MapValue) ref.Val {
		return headerMap
	})
	lazyMap.Append("CertificateIssuerName", func(_ *lazy.MapValue) ref.Val {
		var certIssuerName string
		if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
			// Get the last certificate, which is the root CA if provided.
			rootCA := request.TLS.PeerCertificates[len(request.TLS.PeerCertificates)-1]
			// The issuer is self-signed for a root CA.
			if rootCA.Issuer.String() == rootCA.Subject.String() {
				certIssuerName = rootCA.Issuer.CommonName
			}
		}
		return nativeToValueWithUnescape(certIssuerName)
	})

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
