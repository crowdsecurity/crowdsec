package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type Dashboard struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Folder      string  `json:"-"`
	Client      *HTTP   `json:"-"`
	Cards       []*Card `json:"-"`
	Data        map[string]interface{}
	Model       *GetDashboardModel
}

type GetDashboardModel struct {
	Description          string         `json:"description"`
	Archived             bool           `json:"archived"`
	CollectionPosition   interface{}    `json:"collection_position"`
	OrderedCards         []*OrderedCard `json:"ordered_cards"`
	ParamValues          interface{}    `json:"param_values"`
	CanWrite             bool           `json:"can_write"`
	EnableEmbedding      bool           `json:"enable_embedding"`
	CollectionID         interface{}    `json:"collection_id"`
	ShowInGettingStarted bool           `json:"show_in_getting_started"`
	Name                 string         `json:"name"`
	Caveats              interface{}    `json:"caveats"`
	CreatorID            int            `json:"creator_id"`
	UpdatedAt            string         `json:"updated_at"`
	MadePublicByID       interface{}    `json:"made_public_by_id"`
	EmbeddingParams      interface{}    `json:"embedding_params"`
	ID                   int            `json:"id"`
	Position             interface{}    `json:"position"`
	ParamFields          interface{}    `json:"param_fields"`
	Parameters           []interface{}  `json:"parameters"`
	CreatedAt            string         `json:"created_at"`
	PublicUUID           interface{}    `json:"public_uuid"`
	PointsOfInterest     interface{}    `json:"points_of_interest"`
}

type UpdateDashboardModel struct {
	Description          string         `json:"description"`
	Archived             bool           `json:"archived"`
	CollectionPosition   interface{}    `json:"collection_position"`
	OrderedCards         []*OrderedCard `json:"ordered_cards"`
	ParamValues          interface{}    `json:"param_values"`
	CanWrite             bool           `json:"can_write"`
	EnableEmbedding      bool           `json:"enable_embedding"`
	CollectionID         interface{}    `json:"collection_id"`
	ShowInGettingStarted bool           `json:"show_in_getting_started"`
	Name                 string         `json:"name"`
	Caveats              interface{}    `json:"caveats"`
	CreatorID            int            `json:"creator_id"`
	UpdatedAt            string         `json:"updated_at"`
	MadePublicByID       interface{}    `json:"made_public_by_id"`
	EmbeddingParams      interface{}    `json:"embedding_params"`
	Position             interface{}    `json:"position"`
	ParamFields          interface{}    `json:"param_fields"`
	Parameters           []interface{}  `json:"parameters"`
	CreatedAt            string         `json:"created_at"`
	PublicUUID           interface{}    `json:"public_uuid"`
	PointsOfInterest     interface{}    `json:"points_of_interest"`
}

func (d *Dashboard) Add() error {
	success, errorMsg, err := d.Client.Do("POST", routes[dashboardEndpoint], d)
	if err != nil {
		return err
	}

	if errorMsg != nil {
		return fmt.Errorf("add dashboard: %+v", errorMsg)
	}

	body, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("add dashboard bad response type: %+v", success)
	}
	if _, ok := body["id"]; !ok {
		return fmt.Errorf("no dashboard id in response: %v", body)
	}

	if val, ok := body["id"].(float64); ok {
		d.ID = int(val)
		return nil
	}
	return fmt.Errorf("bad id type: %v", body["id"])
}

func (d *Dashboard) Backup() error {
	success, errorMsg, err := d.Client.Do("GET", fmt.Sprintf(routes[dashboardByIDEndpoint], d.ID), nil)
	if err != nil {
		return err
	}
	if errorMsg != nil {
		return fmt.Errorf("backup dashboard: %+v", errorMsg)
	}

	dash, err := json.Marshal(success)
	if err != nil {
		return errors.Wrap(err, "dashboard backup:")
	}
	dashboard := GetDashboardModel{}
	if err := json.Unmarshal(dash, &dashboard); err != nil {
		return errors.Wrap(err, "dashboard backup:")
	}

	data, err := json.Marshal(dashboard)
	if err != nil {
		return errors.Wrap(err, "dashboard backup:")
	}

	if err := ioutil.WriteFile(filepath.Join(d.Folder, "dashboard.json"), data, os.ModePerm); err != nil {
		return errors.Wrap(err, "dashboard backup:")
	}

	for _, card := range dashboard.OrderedCards {
		if err := card.Backup(d.Folder); err != nil {
			return errors.Wrap(err, "card backup:")
		}
	}

	return nil
}

/*

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
	log.Infof("PUT %s", fmt.Sprintf(routes[addCardToDashboardEndpoint], d.ID))
	t, _ := json.Marshal(body)
	log.Infof("%s", string(t))
	resp, err := d.Client.New().Put(fmt.Sprintf(routes[addCardToDashboardEndpoint], d.ID)).BodyJSON(body).Receive(&respJSON, &respJSON)
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
*/
