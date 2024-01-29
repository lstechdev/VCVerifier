package common

import (
	"github.com/fiware/VCVerifier/logging"
	"github.com/procyon-projects/chrono"
	"time"
)

func Schedule(task chrono.Task) {
	_, err := chrono.NewDefaultTaskScheduler().ScheduleAtFixedRate(task, time.Duration(30)*time.Second)
	if err != nil {
		logging.Log().Errorf("failed scheduling task: %v", err)
	}
}
