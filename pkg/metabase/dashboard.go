package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dghubble/sling"
	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
)

type Dashboard struct {
	ID          int          `json:"-"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Folder      string       `json:"-"`
	Client      *sling.Sling `json:"-"`
	Cards       []*Card      `json:"-"`
	Data        map[string]interface{}
}

func (d *Dashboard) AddDashboard() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	resp, err := d.Client.New().Post(routes[dashboardEndpoint]).BodyJSON(d).Receive(&respJSON, &respJSON)
	if err != nil {
		return respJSON, resp, err
	}
	if val, ok := respJSON["id"]; ok {
		d.ID = int(val.(float64))
	}
	return respJSON, resp, nil
}

func (d *Dashboard) Backup() error {
	var respJSON map[string]interface{}
	_, err := d.Client.New().Get(fmt.Sprintf(routes[dashboardByIDEndpoint], d.ID)).Receive(&respJSON, &respJSON)
	if err != nil {
		return err
	}

	t, err := json.Marshal(respJSON)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(d.Folder, "dashboard.json"), t, os.ModePerm); err != nil {
		return err
	}

	if val, ok := respJSON["ordered_cards"]; ok {
		log.Infof("backup %d cards", len(val.([]interface{})))
		for _, card := range val.([]interface{}) {
			c := &Card{
				Folder: d.Folder,
			}
			if err := c.Backup(card); err != nil {
				return err
			}
		}
	} else {
		log.Errorf("no cards for '%s'", d.Name)
	}

	return nil
}

func (d *Dashboard) Update() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	type CardModel struct {
		CardID                int                    `json:"card_id"`
		ID                    int                    `json:"id"`
		SizeX                 int                    `json:"sizeX"`
		SizeY                 int                    `json:"sizeY"`
		Col                   int                    `json:"col"`
		Row                   int                    `json:"row"`
		ParameterMappings     []interface{}          `json:"parameter_mappings"`
		VisualizationSettings map[string]interface{} `json:"visualization_settings"`
		Series                []interface{}          `json:"series"`
	}

	body := make(map[string][]*CardModel)

	for _, card := range d.Cards {
		model := CardModel{}
		tmp, err := json.Marshal(card.Info)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(tmp, &model); err != nil {
			continue
		}
		body["cards"] = append(body["cards"], &model)
	}
	log.Infof("PUT %s", fmt.Sprintf(routes[addCardToDashboard], d.ID))
	t, _ := json.Marshal(body)
	log.Infof("%s", string(t))
	resp, err := d.Client.New().Put(fmt.Sprintf(routes[addCardToDashboard], d.ID)).BodyJSON(body).Receive(&respJSON, &respJSON)
	if err != nil {
		return respJSON, resp, errors.Wrap(err, "dashboard update:")
	}
	delete(d.Data, "id")

	if _, ok := d.Data["ordered_cards"]; ok {
		delete(d.Data, "ordered_cards")
	}
	d.Data["ordered_cards"] = make([]*CardInfo, 0)
	for _, card := range d.Cards {
		if _, _, err := card.GetCard(); err != nil {
			return nil, nil, err
		}
		card.Info.IsAdded = true
		card.Info.IsDirty = true
		card.Info.JustAdded = false
		card.Info.Data["model"] = "card"
		card.Info.DashboardID = d.ID
		d.Data["ordered_cards"] = append(d.Data["ordered_cards"].([]*CardInfo), card.Info)
	}
	log.Infof("PUT %s", fmt.Sprintf(routes[dashboardByIDEndpoint], d.ID))
	t, _ = json.Marshal(d.Data)
	log.Infof("%s", string(t))
	resp, err = d.Client.New().Put(fmt.Sprintf(routes[dashboardByIDEndpoint], d.ID)).BodyJSON(d.Data).Receive(&respJSON, &respJSON)
	if err != nil {
		return respJSON, resp, errors.Wrap(err, "dashboard update:")
	}

	return respJSON, resp, nil
}
