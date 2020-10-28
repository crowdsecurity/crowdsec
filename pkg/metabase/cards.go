package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

type Card struct {
	/*
		Name                  string                 `json:"name"`
		DatasetQuery          *DatasetQuery          `json:"dataset_query`
		Display               string                 `json:"display"`
		Description           string                 `json:"description"`
		VisualizationSettings map[string]interface{} `json:"visualization_settings"`
		CollectionID          int                    `json:"collection_id"`
	*/
	ID          int
	DashboardID int
	DatabaseID  int
	Name        string `json:"name"`
	Path        string
	Folder      string
	Client      *sling.Sling
	Info        *CardInfo
}

type CardInfo struct {
	CardID                int                    `json:"card_id"`
	ID                    int                    `json:"id"`
	DashboardID           int                    `json:"dashboard_id"`
	SizeX                 int                    `json:"sizeX"`
	SizeY                 int                    `json:"sizeY"`
	Col                   int                    `json:"col"`
	Row                   int                    `json:"row"`
	ParameterMappings     []interface{}          `json:"parameter_mappings"`
	CreatedAt             string                 `json:"created_at"`
	VisualizationSettings map[string]interface{} `json:"visualization_settings"`
	Series                []interface{}          `json:"series"`
	Creator               *Creator               `json:"creator"`
	Data                  map[string]interface{} `json:"card"`
	IsAdded               bool                   `json:"isAdded"`
	IsDirty               bool                   `json:"isDirty"`
	JustAdded             bool                   `json:"justAdded"`
}

type Creator struct {
	CommonName  string `json:"common_name"`
	DateJoined  string `json:"date_joined"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	ID          int    `json:"id"`
	IsQBNEWB    bool   `json:"is_qbnewb"`
	IsSuperUser bool   `json:"is_superuser"`
	LastLogin   string `json:"last_login"`
	LastName    string `json:"last_name"`
}

type DatasetQuery struct {
	Database   int                    `json:"database"`
	Query      map[string]interface{} `json:"query"`
	Type       string                 `json:"type"`
	Parameters []interface{}          `json:"parameters"`
}

func (c *Card) Backup(data interface{}) error {
	c.Info = &CardInfo{}
	dataByte, err := json.Marshal(data)
	if err != nil {
		return err
	}

	//data.(map[string]interface{})["card"]
	if err := json.Unmarshal([]byte(dataByte), c.Info); err != nil {
		return err
	}

	cardFilename := fmt.Sprintf("%s_%d.json", c.Info.Data["name"], c.Info.CardID)
	c.Path = filepath.Join(c.Folder, cardFilename)
	f, err := os.Create(c.Path)

	if err != nil {
		return err
	}

	defer f.Close()

	dataStr, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = f.WriteString(string(dataStr))
	if err != nil {
		return err
	}

	log.Infof("card '%s' exported", c.Path)

	return nil
}

func (c *Card) AddCard() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	var err error
	id := struct {
		ID float64 `json:"id"`
	}{}

	delete(c.Info.Data, "archived")
	delete(c.Info.Data, "cache_ttl")
	delete(c.Info.Data, "collection_position")
	delete(c.Info.Data, "created_at")
	delete(c.Info.Data, "creator_id")
	delete(c.Info.Data, "database_id")
	delete(c.Info.Data, "embedding_params")
	delete(c.Info.Data, "enable_embedding")
	delete(c.Info.Data, "id")
	delete(c.Info.Data, "made_public_by_id")
	delete(c.Info.Data, "public_uuid")
	delete(c.Info.Data, "query_average_duration")
	delete(c.Info.Data, "query_type")
	delete(c.Info.Data, "updated_at")
	delete(c.Info.Data, "table_id")

	if respJSON, _, err = c.DataSet(); err != nil {
		return nil, nil, err
	}
	data, ok := respJSON["data"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("unable to get checksum for metadata: %+v", respJSON)
	}
	resultMetadata, ok := data["results_metadata"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("unable to get checksum for metadata: %+v", respJSON)
	}
	checksum, ok := resultMetadata["checksum"]
	if !ok {
		return nil, nil, fmt.Errorf("unable to get checksum for metadata: %+v", resultMetadata)
	}

	c.Info.Data["metadata_checksum"] = checksum
	resp, err := c.Client.New().Post(routes[cardsEndpoint]).BodyJSON(c.Info.Data).Receive(&id, &respJSON)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	c.Info.CardID = int(id.ID)

	var parameters []interface{}
	resp, err = c.Client.New().Post(fmt.Sprintf(routes[queryEndpoint], c.Info.CardID)).BodyJSON(parameters).Receive(&respJSON, &respJSON)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	return respJSON, resp, nil
}

func (c *Card) DataSet() (map[string]interface{}, *http.Response, error) {
	query := &DatasetQuery{}
	dataByte, err := json.Marshal(c.Info.Data["dataset_query"])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal([]byte(dataByte), query); err != nil {
		return nil, nil, err
	}
	var respJSON map[string]interface{}
	resp, err := c.Client.New().Post(routes[datasetEndpoint]).BodyJSON(query).Receive(&respJSON, &respJSON)
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil
}

func (c *Card) AddCardToDashboard() (interface{}, *http.Response, error) {
	var respJSON interface{}

	route := fmt.Sprintf(routes[addCardToDashboard], c.DashboardID)

	c.Info.Data = nil

	body := struct {
		CardID int `json:"cardId"`
	}{
		c.Info.CardID,
	}
	log.Infof("POST %s", route)
	resp, err := c.Client.New().Post(route).BodyJSON(body).Receive(&respJSON, &respJSON)
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil
}

func NewCard(file string, ID int, httpClient *sling.Sling, user *Creator) (*Card, error) {
	card := &Card{
		DashboardID: ID,
		Client:      httpClient,
		Info: &CardInfo{
			Creator: user,
		},
	}
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return card, err
	}
	if err := json.Unmarshal(f, card.Info); err != nil {
		return card, err
	}
	return card, nil
}

func (c *Card) GetCard() (interface{}, *http.Response, error) {
	var respJSON interface{}
	log.Infof("POST %s", fmt.Sprintf(routes[cardByIDEndpoint], c.Info.CardID))
	resp, err := c.Client.New().Get(fmt.Sprintf(routes[cardByIDEndpoint], c.Info.CardID)).Receive(&c.Info.Data, &respJSON)
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil
}
