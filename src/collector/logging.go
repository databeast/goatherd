package collector

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger
var console bool

func init() {
	baselogger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	logger = baselogger.Sugar()
}

//TODO: Enable redirected transmission of logs to the central mapper when in distributed mode

func logCollectorDebug(msg string) {
	if console {
		defer logger.Sync()
	}
	logger.Info(msg)
}

func logCollectorInfo(msg string) {
	if console {
		defer logger.Sync()
	}
	logger.Info(msg)
}

func logCollectorError(msg string) {
	if console {
		defer logger.Sync()
	}
	logger.Error(msg)
}
