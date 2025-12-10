package v1

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (c *Controller) shouldAutoRegister(token string, r *http.Request) (bool, error) {
	if !*c.AutoRegisterCfg.Enable {
		return false, nil
	}

	// Get client IP from context (resolved by ClientIPMiddleware)
	clientIPStr := router.GetClientIP(r)
	clientIP, err := netip.ParseAddr(clientIPStr)

	// Can probaby happen if using unix socket ?
	if err != nil {
		log.Warnf("Failed to parse client IP for watcher self registration: %s", clientIPStr)
		return false, nil
	}

	if token == "" || c.AutoRegisterCfg == nil {
		return false, nil
	}

	// Check the token
	if token != c.AutoRegisterCfg.Token {
		return false, errors.New("invalid token for auto registration")
	}

	// Check the source IP
	for _, ipRange := range c.AutoRegisterCfg.AllowedRangesParsed {
		// Convert net.IPNet to netip.Prefix for comparison
		prefix, err := netip.ParsePrefix(ipRange.String())
		if err != nil {
			continue
		}
		if prefix.Contains(clientIP) {
			return true, nil
		}
	}

	return false, errors.New("IP not in allowed range for auto registration")
}

func (c *Controller) CreateMachine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var input models.WatcherRegistrationRequest

	if err := router.BindJSON(r, &input); err != nil {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	if err := input.Validate(strfmt.Default); err != nil {
		router.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{"message": err.Error()})
		return
	}

	// Get client IP from context (resolved by ClientIPMiddleware)
	// c.TrustedIPs is the ACL allowlist, not proxy networks
	clientIP := router.GetClientIP(r)
	autoRegister, err := c.shouldAutoRegister(input.RegistrationToken, r)
	if err != nil {
		log.WithFields(log.Fields{"ip": clientIP, "machine_id": *input.MachineID}).Errorf("Auto-register failed: %s", err)
		router.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": err.Error()})

		return
	}

	if _, err := c.DBClient.CreateMachine(ctx, input.MachineID, input.Password, clientIP, autoRegister, false, types.PasswordAuthType); err != nil {
		c.HandleDBErrors(w, err)
		return
	}

	if autoRegister {
		log.WithFields(log.Fields{"ip": clientIP, "machine_id": *input.MachineID}).Info("Auto-registered machine")
		w.WriteHeader(http.StatusAccepted)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (c *Controller) DeleteMachine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	machineID, err := getMachineIDFromContext(r)

	if err != nil {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	if machineID == "" {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "machineID not found in claims"})
		return
	}

	if err := c.DBClient.DeleteWatcher(ctx, machineID); err != nil {
		c.HandleDBErrors(w, err)
		return
	}

	// Get client IP from context (resolved by ClientIPMiddleware)
	// c.TrustedIPs is the ACL allowlist, not proxy networks
	clientIP := router.GetClientIP(r)
	log.WithFields(log.Fields{"ip": clientIP, "machine_id": machineID}).Info("Deleted machine")

	w.WriteHeader(http.StatusNoContent)
}
