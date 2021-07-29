package util

import (
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

func LogSystemUsage(every time.Duration) {
	bToMb := func(b uint64) uint64 {
		return b / 1024 / 1024
	}
	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			msg := fmt.Sprintf("Alloc = %v MB", bToMb(m.Alloc))
			//msg += fmt.Sprintf("\tTotalAlloc = %v MB", bToMb(m.TotalAlloc))
			msg += fmt.Sprintf(" Sys = %v MB", bToMb(m.Sys))
			msg += fmt.Sprintf(" NumGC = %v", m.NumGC)
			msg += fmt.Sprintf(" NumGR = %v", runtime.NumGoroutine())
			log.Info(msg)
			time.Sleep(every)
		}
	}()
}
