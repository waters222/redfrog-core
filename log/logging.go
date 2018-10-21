package log

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func InitLogger(logFile string, logLevel string, bJson bool) *zap.Logger {

	var cfg zap.Config
	cfg = zap.NewProductionConfig()
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if ! bJson {
		cfg.Encoding = "console"
	}

	switch logLevel {
		case "debug":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		case "info":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		case "warn":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
		case "error":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
		case "fatal":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
		case "panic":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.PanicLevel)
		default:
			cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	if len(logFile) == 0{
		cfg.OutputPaths = []string{"stdout"}
	}else{
		cfg.OutputPaths = []string{"stdout", logFile}
	}

	var err error
	if logger, err = cfg.Build(); err != nil{
		fmt.Println(fmt.Sprintf("Init zap logger failed: %s", err.Error()))
		return nil
	}

	return logger
}

func GetLogger() *zap.Logger {
	return logger
}
