package assert

import (
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
)

const (
	Panic PanicMode = iota
	Exit
	SIGTERM
)

type AssertionPanic string
type PanicMode int

func log(err error, arg ...interface{}) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASSERTION: error %+v\n", err)

	}
	fmt.Fprintf(os.Stderr, "ASSERT: %+v\n", arg)
	fmt.Fprintln(os.Stderr, string(debug.Stack()))
}

func handlePanic(mode PanicMode) {
	switch mode {
	case Panic:
		panic(AssertionPanic("ASSERTION FAILED"))
	case Exit:
		os.Exit(1)
	case SIGTERM:
		err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PANIC: %s\n", err)
			os.Exit(1)
		}

		panic(AssertionPanic("SYSCALL PANIC"))
	}
}

func ErrNotNil(err error, mode PanicMode, arg ...interface{}) {
	if err != nil {

		log(err, arg...)
		handlePanic(mode)
	}
}

func NotNil(intf interface{}, mode PanicMode, arg ...interface{}) {
	if intf == nil {
		log(nil, arg...)
		handlePanic(mode)
	}
}

func StrNotEmpty(str string, mode PanicMode, arg ...interface{}) {
	if str == "" {
		log(nil, arg...)
		handlePanic(mode)
	}
}

func Must[T any](v T, err error) T {
	ErrNotNil(err, Panic)
	return v
}
