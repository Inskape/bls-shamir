package global

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	Name         string = "inskape"
	Version      string = "0.0.1"
	LogLevelFlag string = "level"
	DataDirFlag  string = "data"
)

var (
	ZapLevels = []zapcore.Level{
		zap.DebugLevel,
		zap.InfoLevel,
		zap.WarnLevel,
		zap.ErrorLevel,
		zap.DPanicLevel,
		zap.PanicLevel,
		zap.FatalLevel,
	}
)
