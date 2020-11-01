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
	ID           int     `json:"id"`
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Folder       string  `json:"-"`
	Client       *HTTP   `json:"-"`
	Cards        []*Card `json:"-"`
	Data         map[string]interface{}
	Model        *GetDashboardModel
	SendModel    *UpdateDashboardModel
	FrontInfo    []*AddFrontInfoModel `json:"card"`
	OrderedCards []*OrderedCard
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

func (d *Dashboard) UpdateFrontInfo() error {
	data := make(map[string][]*AddFrontInfoModel)
	data["cards"] = d.FrontInfo

	_, errorMsg, err := d.Client.Do("PUT", fmt.Sprintf(routes[addCardToDashboardEndpoint], d.ID), data)
	if err != nil {
		return err
	}
	if errorMsg != nil {
		return err
	}

	return nil
}

func (d *Dashboard) UpdateDashboard(user *User) error {
	d.SendModel.CanWrite = true
	for _, card := range d.SendModel.OrderedCards {
		card.Card.Creator = user
		card.DashboardID = d.ID
	}

	_, errorMsg, err := d.Client.Do("PUT", fmt.Sprintf(routes[dashboardByIDEndpoint], d.ID), d.SendModel)
	if err != nil {
		return err
	}
	if errorMsg != nil {
		return err
	}

	return nil
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
