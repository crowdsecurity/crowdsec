package v1

import "net/http"

func (c *Controller) HeartBeat(w http.ResponseWriter, r *http.Request) {
	machineID, _ := getMachineIDFromContext(r)

	ctx := r.Context()

	if err := c.DBClient.UpdateMachineLastHeartBeat(ctx, machineID); err != nil {
		c.HandleDBErrors(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
