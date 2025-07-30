package setup

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type ServiceMap map[string]bool

type ExprWindows struct {
	serviceManager *mgr.Mgr // Windows service manager
	servicesCache  ServiceMap
}

func NewExprWindows() (*ExprWindows, error) {
	mgr, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	return &ExprWindows{
		serviceManager: mgr,
		servicesCache:  make(ServiceMap),
	}, nil
}

func (e *ExprWindows) ServiceEnabled(serviceName string) (bool, error) {
	if enabled, ok := e.servicesCache[serviceName]; ok {
		return enabled, nil
	}
	svc, err := e.serviceManager.OpenService(serviceName)
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) && errno == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			e.servicesCache[serviceName] = false // Cache the non-existence
			return false, nil
		}
		return false, fmt.Errorf("while opening service: %w", err)
	}
	svcConfig, err := svc.Config()
	if err != nil {
		return false, fmt.Errorf("while getting service config: %w", err)
	}
	if svcConfig.StartType == windows.SERVICE_AUTO_START {
		e.servicesCache[serviceName] = true
		return true, svc.Close()
	}
	e.servicesCache[serviceName] = false
	return false, svc.Close()
}
