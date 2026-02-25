package app

import "github.com/sirupsen/logrus"

func NewLogger(cfg Config) *logrus.Logger {
	log := logrus.New()

	if cfg.Debug {
		log.SetLevel(logrus.TraceLevel)
	} else {
		log.SetLevel(logrus.ErrorLevel)
	}
	log.SetFormatter(&logrus.TextFormatter{})

	return log
}
