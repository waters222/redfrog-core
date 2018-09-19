package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
)

var logger *zap.Logger
var loggerSugar *zap.SugaredLogger
var bIsProductionMode bool

func InitLogger(logLevel string, bIsProductionMode bool) *zap.Logger {
	var levelEnabler zap.LevelEnablerFunc
	switch logLevel {
	case "debug":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.DebugLevel })
	case "info":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.InfoLevel })
	case "warn":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.WarnLevel })
	case "error":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.ErrorLevel })
	case "fatal":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.FatalLevel })
	case "panic":
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.PanicLevel })
	default:
		levelEnabler = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.InfoLevel })
	}

	consoleOut := zapcore.Lock(os.Stdout)
	var consoleEncoder zapcore.Encoder
	if bIsProductionMode {
		consoleEncoder = zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	} else {
		consoleEncoder = zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	}
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleOut, levelEnabler),
	)
	logger = zap.New(core)
	loggerSugar = logger.Sugar()
	return logger
}

func GetLogger() *zap.Logger {
	pc := make([]uintptr, 1) // at least 1 entry needed
	runtime.Callers(2, pc)
	//f := runtime.FuncForPC(pc[0])

	if bIsProductionMode {
		return logger
		//return logger.With(zap.String("caller", f.Name()))
	} else {
		return logger
		//file, line := f.FileLine(pc[0])
		//return logger.With(zap.String("caller", f.Name()),
		//	zap.String("file", file),
		//	zap.Int("line", line))
	}
}

func GetLoggerSugar() *zap.SugaredLogger {
	pc := make([]uintptr, 1) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	if bIsProductionMode {
		return loggerSugar.With(zap.String("caller", f.Name()))
	} else {
		file, line := f.FileLine(pc[0])
		return loggerSugar.With(zap.String("caller", f.Name()),
			zap.String("file", file),
			zap.Int("line", line))
	}
}
