package exception

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	debug            bool = true
	StackTraceHeight int  = 20
)

const (
	exceptionStacktraceHeight int = 3 // skip `Err...`, `New` and `withStackTrace` functions
)

type Exception struct {
	message       string
	details       []string
	wrappedErrors []error
	stackTrace    string
}

// New creates a New exception with the given message.
func New(message string, errs ...error) Exception {
	e := Exception{message: message}
	for _, err := range errs {
		e = e.Wrap(err)
	}
	return e.withStackTrace()
}

func (e Exception) Is(err error) bool {
	if ex, ok := err.(Exception); !ok || err == nil {
		return false
	} else if e.message == ex.message {
		return true
	}
	return false
}

func (e Exception) Unwrap() []error {
	return e.wrappedErrors
}

func (e Exception) Message() string {
	err := e.message

	if len(e.details) > 0 {
		err = fmt.Sprintf("%s (%s)", err, strings.Join(e.details, ", "))
	}

	if len(e.wrappedErrors) > 0 {
		errs := make([]string, 0, len(e.wrappedErrors))
		for _, err := range e.wrappedErrors {
			if ex, ok := err.(Exception); ok {
				errs = append(errs, ex.Message())
			} else {
				errs = append(errs, err.Error())
			}
		}
		err = fmt.Sprintf("%s [%s]", err, strings.Join(errs, " | "))
	}

	return err
}

func (e Exception) withStackTrace() Exception {
	if debug && e.stackTrace == "" {
		stackTrace := ""
		for i := exceptionStacktraceHeight; i < exceptionStacktraceHeight+StackTraceHeight; i++ {
			if pc, file, line, ok := runtime.Caller(i); ok {
				stackTrace += fmt.Sprintf("%s:%d\n", file, line)

				if f := runtime.FuncForPC(pc); f != nil {
					stackTrace += fmt.Sprintf("\t%s\n", f.Name())
				}
			} else {
				break
			}
		}
		e.stackTrace = fmt.Sprintf("%s\n%s", e.stackTrace, stackTrace)
	}
	return e
}
func (e Exception) stackTraceString() (msg string) {
	if debug && e.stackTrace != "" {
		msg = fmt.Sprintf("%s\n%s", msg, e.stackTrace)
	}

	for _, err := range e.wrappedErrors {
		if ex, ok := err.(Exception); ok {
			msg = fmt.Sprintf("%s\n%s", msg, ex.stackTraceString())
		}
	}
	return msg
}

func (e Exception) Error() (msg string) {
	msg = e.Message()

	if debug && e.stackTrace != "" {
		msg = fmt.Sprintf("%s\n%s", msg, e.stackTraceString())
	}

	return msg
}

func (e Exception) WithDetail(detail string) Exception {
	if e.details == nil {
		e.details = make([]string, 0, 1)
	}
	e.details = append(e.details, detail)
	return e
}

func (e Exception) WithDetailf(detail string, args ...any) Exception {
	if e.details == nil {
		e.details = make([]string, 0, 1)
	}
	e.details = append(e.details, fmt.Sprintf(detail, args...))
	return e
}

// Wrap wraps the given error with the exception.
//
// If the given error is nil, the exception is returned as is.
//
// If the given error is being wrapped by the same exception type, the given error is returned with any additional context this exception has.
//
// If the exception already has wrapped errors, the given error is appended to the list.
//
// If the error to be wrapped has a stack trace, is it copied to the returned exception unless a stacktrace already exists.
func (e Exception) Wrap(err error) Exception {
	if err == nil {
		return e
	} else if ex, ok := err.(Exception); !ok {
		// if the error is not an exception, just add it to this one as a wrapped exception
	} else if e.Is(ex) {
		// if the wrapped error is the same type as this one, merge them
		ex.details = append(ex.details, e.details...)
		ex.wrappedErrors = append(ex.wrappedErrors, e.wrappedErrors...)
		return ex
	} else if ex.stackTrace != "" && e.stackTrace == "" {
		// if the wrapped error has a stack trace and this one does not, copy it
		e.stackTrace = ex.stackTrace
	}

	if e.wrappedErrors == nil {
		e.wrappedErrors = []error{err}
	} else {
		e.wrappedErrors = append(e.wrappedErrors, err)
	}
	return e
}

func ErrSavingMessage(err ...error) Exception {
	return New("error saving message", err...)
}

func ErrDKGIncorrectStep(err ...error) Exception {
	return New("incorrect DKG step reached", err...)
}

func ErrDuplicate(err ...error) Exception {
	return New("duplicate value", err...)
}

func ErrDuplicateRoundUUID(err ...error) Exception {
	return New("supplied UUID has already been used for a DKG round", err...)
}

func ErrDuplicateSignature(err ...error) Exception {
	return New("duplicate signature", err...)
}

func ErrFetchingPeers(err ...error) Exception {
	return New("failed to fetch expected peers from originating peer", err...)
}

func ErrFindingIP(err ...error) Exception {
	return New("error finding IP address", err...)
}

func ErrInitKoanf(err ...error) Exception {
	return New("error initializing koanf", err...)
}

func ErrInvalidCoefficient(err ...error) Exception {
	return New("invalid coefficient supplied", err...)
}

func ErrInvalidConfig(err ...error) Exception {
	return New("invalid config file", err...)
}

func ErrInvalidLogger(err ...error) Exception {
	return New("invalid logger supplied", err...)
}

func ErrInvalidMessage(err ...error) Exception {
	return New("invalid message", err...)
}

func ErrInvalidParameters(err ...error) Exception {
	return New("invalid parameters supplied", err...)
}

func ErrInvalidPublicKey(err ...error) Exception {
	return New("invalid public key supplied", err...)
}

func ErrInvalidPublicKeyBytes(err ...error) Exception {
	return New("invalid public key bytes", err...)
}

func ErrInvalidSecretKey(err ...error) Exception {
	return New("invalid secret key supplied", err...)
}

func ErrInvalidSignature(err ...error) Exception {
	return New("invalid signature", err...)
}

func ErrInvalidThreshold(err ...error) Exception {
	return New("invalid threshold supplied", err...)
}

func ErrInvalidUUID(err ...error) Exception {
	return New("UUID supplied is invalid", err...)
}

func ErrKoanfMerge(err ...error) Exception {
	return New("error merging koanf maps", err...)
}

func ErrLoadingKey(err ...error) Exception {
	return New("error loading node key", err...)
}

func ErrNilParameters(err ...error) Exception {
	return New("parameters cannot be nil", err...)
}

func ErrNilRoundUUID(err ...error) Exception {
	return New("UUID supplied for this DKG round cannot be nil", err...)
}

func ErrNoActiveRound(err ...error) Exception {
	return New("there is no active DKG round", err...)
}

func ErrNoPublicKey(err ...error) Exception {
	return New("keyring does not have a public key", err...)
}

func ErrNoSecretKey(err ...error) Exception {
	return New("keyring does not have a secret key", err...)
}

func ErrNoShare(err ...error) Exception {
	return New("no share found for peer", err...)
}

func ErrNoSignature(err ...error) Exception {
	return New("no signature found", err...)
}

func ErrNotEnoughSignatures(err ...error) Exception {
	return New("not enough signatures to create a threshold signature", err...)
}

func ErrOldDKGRound(err ...error) Exception {
	return New("lamport time in parameters cannot be before or equal to current time", err...)
}

func ErrParsingConfigFile(err ...error) Exception {
	return New("error parsing config file", err...)
}

func ErrParsingKey(err ...error) Exception {
	return New("error parsing public key bytes", err...)
}

func ErrPeerError(err ...error) Exception {
	return New("error from peer", err...)
}

func ErrPublicKeyGeneration(err ...error) Exception {
	return New("error generating public key", err...)
}

func ErrRoundUUID(err ...error) Exception {
	return New("incorrect UUID calculated for this DKG round", err...)
}

func ErrSavingKey(err ...error) Exception {
	return New("error saving source node key", err...)
}

func ErrSeedTooShort(err ...error) Exception {
	return New("seed is too short", err...)
}

func ErrSerfTag(err ...error) Exception {
	return New("error setting serf tag", err...)
}

func ErrSerfUnknownEvent(err ...error) Exception {
	return New("unknown serf event", err...)
}

func ErrSerfQuery(err ...error) Exception {
	return New("error handling serf query", err...)
}

func ErrSigning(err ...error) Exception {
	return New("error creating a signature", err...)
}

func ErrThresholdSigning(err ...error) Exception {
	return New("error creating a threshold signature", err...)
}

func ErrTypeAssertion(err ...error) Exception {
	return New("type assertion failed", err...)
}

func ErrUnimplementedMethod(err ...error) Exception {
	return New("method is not implemented", err...)
}

func ErrUnknownConfigFile(err ...error) Exception {
	return New("error parsing unknown config file", err...)
}

func ErrUnknownMember(err ...error) Exception {
	return New("query originated from unknown source", err...)
}

func ErrUnknownPeer(err ...error) Exception {
	return New("unknown peer specified", err...)
}
