package collectors

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	baselogger, _ := zap.NewProduction()
	logger = baselogger.Sugar()
}

//TODO: Enable redirected transmission of logs to the central mapper when in distributed mode

func logCollectorDebug(msg string) {
	defer logger.Sync() // flushes buffer, if any
	logger.Info(msg)
}

func logCollectorInfo(msg string) {
	defer logger.Sync() // flushes buffer, if any
	logger.Info(msg)
}

func logCollectorError(msg string) {
	defer logger.Sync() // flushes buffer, if any
	logger.Error(msg)
}