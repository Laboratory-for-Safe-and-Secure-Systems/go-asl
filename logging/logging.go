package logging

import (
	"fmt"
	"log"
	"reflect"
)

// Logger is a generic logging interface.
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger writes to the standard logger.
type DefaultLogger struct {
	DebugEnabled bool
}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	if l.DebugEnabled {
		log.Printf(format, args...)
	}
}

func (l *DefaultLogger) Debug(args ...interface{}) {
	if l.DebugEnabled {
		log.Println(args...)
	}
}

func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *DefaultLogger) Info(args ...interface{}) {
	log.Println(args...)
}

func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *DefaultLogger) Error(args ...interface{}) {
	log.Println(args...)
}

// NewLogger wraps an arbitrary logger (or nil) into one that implements lib.Logger.
// Even if the provided logger’s methods have signatures like Debug(string, ...any)
// (as in *slog.Logger), the returned Logger will always have the signature we require.
func NewLogger(logger interface{}) Logger {
	if logger == nil {
		return &DefaultLogger{}
	}
	return &genericLogger{underlying: reflect.ValueOf(logger)}
}

// genericLogger is a reflection-based adapter that implements Logger.
type genericLogger struct {
	underlying reflect.Value
}

// Debug adapts calls to the underlying logger’s Debug method.
// If the underlying Debug has the signature Debug(string, ...any),
// then the adapter will use the first argument as the message if it is a string,
// or else combine all the args with fmt.Sprint.
func (g *genericLogger) Debug(args ...interface{}) {
	m := g.underlying.MethodByName("Debug")
	if !m.IsValid() {
		// Underlying logger has no Debug; do nothing.
		return
	}
	mt := m.Type()
	// If the method expects at least one parameter, assume the first is a message.
	if mt.NumIn() > 0 {
		var msg string
		var extra []interface{}
		if len(args) > 0 {
			// If the first argument is already a string, use it directly.
			if s, ok := args[0].(string); ok {
				msg = s
				extra = args[1:]
			} else {
				// Otherwise, combine all args.
				msg = fmt.Sprint(args...)
			}
		}
		callArgs := []reflect.Value{reflect.ValueOf(msg)}
		// If the underlying method is variadic, pass any extra args.
		if mt.IsVariadic() && len(extra) > 0 {
			for _, v := range extra {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}

// Debugf adapts calls to Debugf(format string, ...interface{}).
// If the underlying logger lacks Debugf, it falls back to Debug.
func (g *genericLogger) Debugf(format string, args ...interface{}) {
	m := g.underlying.MethodByName("Debugf")
	if !m.IsValid() {
		// Fallback: use Debug with Sprintf-ed message.
		g.Debug(fmt.Sprintf(format, args...))
		return
	}
	mt := m.Type()
	if mt.NumIn() > 0 {
		callArgs := []reflect.Value{reflect.ValueOf(format)}
		if mt.IsVariadic() && len(args) > 0 {
			for _, v := range args {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}

// Info adapts calls to Info.
func (g *genericLogger) Info(args ...interface{}) {
	m := g.underlying.MethodByName("Info")
	if !m.IsValid() {
		return
	}
	mt := m.Type()
	if mt.NumIn() > 0 {
		var msg string
		var extra []interface{}
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				msg = s
				extra = args[1:]
			} else {
				msg = fmt.Sprint(args...)
			}
		}
		callArgs := []reflect.Value{reflect.ValueOf(msg)}
		if mt.IsVariadic() && len(extra) > 0 {
			for _, v := range extra {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}

// Infof adapts calls to Infof.
func (g *genericLogger) Infof(format string, args ...interface{}) {
	m := g.underlying.MethodByName("Infof")
	if !m.IsValid() {
		g.Info(fmt.Sprintf(format, args...))
		return
	}
	mt := m.Type()
	if mt.NumIn() > 0 {
		callArgs := []reflect.Value{reflect.ValueOf(format)}
		if mt.IsVariadic() && len(args) > 0 {
			for _, v := range args {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}

// Error adapts calls to Error.
func (g *genericLogger) Error(args ...interface{}) {
	m := g.underlying.MethodByName("Error")
	if !m.IsValid() {
		return
	}
	mt := m.Type()
	if mt.NumIn() > 0 {
		var msg string
		var extra []interface{}
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				msg = s
				extra = args[1:]
			} else {
				msg = fmt.Sprint(args...)
			}
		}
		callArgs := []reflect.Value{reflect.ValueOf(msg)}
		if mt.IsVariadic() && len(extra) > 0 {
			for _, v := range extra {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}

// Errorf adapts calls to Errorf.
func (g *genericLogger) Errorf(format string, args ...interface{}) {
	m := g.underlying.MethodByName("Errorf")
	if !m.IsValid() {
		g.Error(fmt.Sprintf(format, args...))
		return
	}
	mt := m.Type()
	if mt.NumIn() > 0 {
		callArgs := []reflect.Value{reflect.ValueOf(format)}
		if mt.IsVariadic() && len(args) > 0 {
			for _, v := range args {
				callArgs = append(callArgs, reflect.ValueOf(v))
			}
		}
		m.Call(callArgs)
	} else {
		m.Call(nil)
	}
}
