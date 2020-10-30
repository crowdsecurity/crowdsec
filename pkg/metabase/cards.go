package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type DatasetQuery struct {
	Type  string `json:"type"`
	Query struct {
		SourceTable int             `json:"source-table"`
		Aggregation [][]string      `json:"aggregation"`
		Breakout    [][]interface{} `json:"breakout"`
		OrderBy     [][]interface{} `json:"order-by"`
	} `json:"query"`
	Database   int           `json:"database"`
	Parameters []interface{} `json:"parameters"`
}

type Card struct {
	DatasetQuery                 *DatasetQuery
	AddModel                     *AddCardModel
	GetModel                     *GetCardModel
	AddFrontInfoModel            *AddFrontInfoModel
	AddFrontInfoToDashboardModel *AddFrontInfoToDashboardModel
	OrderedCard                  *OrderedCard `json:"ordered_cards"`
	Client                       *HTTP        `json:"-"`
}

// to export/import (without result metadata)
type AddCardModel struct {
	ID                    interface{}   `json:"id"`
	Name                  string        `json:"name"`
	DatasetQuery          *DatasetQuery `json:"dataset_query"`
	Display               string        `json:"display"`
	Description           interface{}   `json:"description"`
	VisualizationSettings interface{}   `json:"visualization_settings"`
	CollectionID          interface{}   `json:"collection_id"`
	ResultMetadata        []interface{} `json:"result_metadata"`
	MetadataChecksum      string        `json:"metadata_checksum"`
}

type GetCardModel struct {
	Description           interface{}   `json:"description"`
	Archived              bool          `json:"archived"`
	CollectionPosition    interface{}   `json:"collection_position"`
	TableID               int           `json:"table_id"`
	ResultMetadata        interface{}   `json:"result_metadata"`
	Creator               *User         `json:"creator"`
	CanWrite              bool          `json:"can_write"`
	DatabaseID            int           `json:"database_id"`
	EnableEmbedding       bool          `json:"enable_embedding"`
	CollectionID          interface{}   `json:"collection_id"`
	QueryType             string        `json:"query_type"`
	Name                  string        `json:"name"`
	DashboardCount        int           `json:"dashboard_count"`
	CreatorID             int           `json:"creator_id"`
	UpdatedAt             string        `json:"updated_at"`
	MadePublicByID        interface{}   `json:"made_public_by_id"`
	EmbeddingParams       interface{}   `json:"embedding_params"`
	CacheTTL              interface{}   `json:"cache_ttl"`
	DatasetQuery          *DatasetQuery `json:"dataset_query"`
	ID                    int           `json:"id"`
	Display               string        `json:"display"`
	VisualizationSettings struct {
	} `json:"visualization_settings"`
	Collection interface{} `json:"collection"`
	CreatedAt  string      `json:"created_at"`
	PublicUUID interface{} `json:"public_uuid"`
	Favorite   bool        `json:"favorite, omitempty"`
	Model      string      `json:"model", omitempty"`
}

// to import/export
type AddFrontInfoModel struct {
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

//to import export
type AddFrontInfoToDashboardModel struct {
	ID                    float64                `json:"id"`
	CardID                int                    `json:"card_id"`
	Series                []interface{}          `json:"series"`
	Col                   int                    `json:"col"`
	Row                   int                    `json:"row"`
	SizeX                 int                    `json:"sizeX"`
	SizeY                 int                    `json:"sizeY"`
	ParameterMappings     []interface{}          `json:"parameter_mappings"`
	VisualizationSettings map[string]interface{} `json:"visualization_settings"`
}

//to import export
type OrderedCard struct {
	ID                    float64                `json:"id"`
	DashboardID           int                    `json:"dashboard_id"`
	CardID                int                    `json:"card_id"`
	Card                  *GetCardModel          `json:"card"`
	Series                []interface{}          `json:"series"`
	Col                   int                    `json:"col"`
	Row                   int                    `json:"row"`
	SizeX                 int                    `json:"sizeX"`
	SizeY                 int                    `json:"sizeY"`
	ParameterMappings     []interface{}          `json:"parameter_mappings"`
	VisualizationSettings map[string]interface{} `json:"visualization_settings"`
	IsAdded               bool                   `json:"isAdded"`
	JustAdded             bool                   `json:"justAdded"`
	IsDirty               bool                   `json:"isDirty"`
}

func (c *OrderedCard) Backup(folder string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("unable to backup card '%s': %s", c.Card.Name, err)
	}
	if err := ioutil.WriteFile(filepath.Join(folder, fmt.Sprintf("%s.json", c.Card.Name)), data, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func NewCardFromFile(file string, dashboardID int, client *HTTP, creator *User) (*Card, error) {
	card := &OrderedCard{}
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(f, &card); err != nil {
		return nil, err
	}

	ret := &Card{
		DatasetQuery: card.Card.DatasetQuery,
	}

	cardM, err := json.Marshal(card)
	if err != nil {
		return nil, errors.Wrapf(err, "new card from file (%s):", file)
	}
	// to export/import (without result metadata)
	/*type AddCardModel struct {
		ID                    interface{}   `json:"id"`
		Name                  string        `json:"name"`
		DatasetQuery          *DatasetQuery `json:"dataset_query"`
		Display               string        `json:"display"`
		Description           interface{}   `json:"description"`
		VisualizationSettings interface{}   `json:"visualization_settings"`
		CollectionID          interface{}   `json:"collection_id"`
		ResultMetadata        interface{}   `json:"result_metadata"`
		MetadataChecksum      string        `json:"metadata_checksum"`
	}*/

	ret.AddModel = &AddCardModel{
		Name:                  card.Card.Name,
		DatasetQuery:          card.Card.DatasetQuery,
		Display:               card.Card.Display,
		Description:           card.Card.Description,
		VisualizationSettings: card.VisualizationSettings,
	}

	if err := json.Unmarshal(cardM, &ret.GetModel); err != nil {
		return nil, errors.Wrapf(err, "new card from file (%s):", file)
	}

	if err := json.Unmarshal(cardM, &ret.AddFrontInfoModel); err != nil {
		return nil, errors.Wrapf(err, "new card from file (%s):", file)
	}

	if err := json.Unmarshal(cardM, &ret.AddFrontInfoToDashboardModel); err != nil {
		return nil, errors.Wrapf(err, "new card from file (%s):", file)
	}
	card.DashboardID = dashboardID
	ret.OrderedCard = card
	ret.Client = client
	ret.GetModel.Creator = creator
	return ret, nil
}

func (c *Card) Dataset() error {
	success, errormsg, err := c.Client.Do("POST", routes[datasetEndpoint], c.DatasetQuery)
	if errormsg != nil {
		return fmt.Errorf("dataset: %+v", errormsg)
	}
	log.Infof("POST /%s => %+v | %+v", routes[datasetEndpoint], success, errormsg)
	if err != nil {
		return fmt.Errorf("dataset err: %s", err)
	}
	data, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("dataset: response bad type: %+v", success)
	}
	marshal, err := json.Marshal(data["data"])
	if err != nil {
		return errors.Wrap(err, "dataset:")
	}

	resp := struct {
		Result map[string]interface{} `json:"results_metadata"`
	}{}

	if err := json.Unmarshal(marshal, &resp); err != nil {
		return errors.Wrap(err, "dataset:")
	}

	resultMeta := make([]interface{}, 0)

	if _, ok := resp.Result["columns"]; !ok {
		return fmt.Errorf("dataset: no columns: %+v", resp.Result)
	}

	columns, ok := resp.Result["columns"].([]interface{})
	if !ok {
		return fmt.Errorf("dataset: bad columns type: %+v", resp.Result)
	}

	for _, column := range columns {
		resultMeta = append(resultMeta, column)
	}

	c.AddModel.ResultMetadata = resultMeta

	if _, ok := resp.Result["checksum"]; !ok {
		return fmt.Errorf("dataset: no checksum : %+v", resp.Result)
	}

	c.AddModel.MetadataChecksum, ok = resp.Result["checksum"].(string)
	if !ok {
		return fmt.Errorf("dataset: checksum bad type : %+v", resp.Result["checksum"])
	}

	return nil
}

func (c *Card) Add() error {
	success, errormsg, err := c.Client.Do("POST", routes[cardsEndpoint], c.AddModel)
	if err != nil {
		return errors.Wrap(err, "add card:")
	}
	if errormsg != nil {
		return fmt.Errorf("add card: %+v", errormsg)
	}

	marshal, err := json.Marshal(success)
	if err != nil {
		return errors.Wrap(err, "add card:")
	}

	if err := json.Unmarshal(marshal, &c.GetModel); err != nil {
		return errors.Wrap(err, "add card:")
	}

	c.AddFrontInfoModel.CardID = c.GetModel.ID
	c.AddFrontInfoToDashboardModel.CardID = c.GetModel.ID
	c.OrderedCard.CardID = c.GetModel.ID
	return nil
}

func (c *Card) Query() error {
	success, errormsg, err := c.Client.Do("POST", routes[queryEndpoint], map[string]interface{}{
		"parameters": c.DatasetQuery.Parameters,
	})

	if errormsg != nil {
		return fmt.Errorf("query: %+v", errormsg)
	}
	data, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("dataset: response bad type: %+v", success)
	}
	marshal, err := json.Marshal(data["data"])
	if err != nil {
		return errors.Wrap(err, "dataset:")
	}

	resp := struct {
		Result map[string]interface{} `json:"results_metadata"`
	}{}

	if err := json.Unmarshal(marshal, &resp); err != nil {
		return errors.Wrap(err, "dataset:")
	}

	resultMeta := make([]interface{}, 0)

	if _, ok := resp.Result["columns"]; !ok {
		return fmt.Errorf("dataset: no columns: %+v", resp.Result)
	}

	columns, ok := resp.Result["columns"].([]interface{})
	if !ok {
		return fmt.Errorf("dataset: bad columns type: %+v", resp.Result)
	}

	for _, column := range columns {
		resultMeta = append(resultMeta, column)
	}

	c.AddModel.ResultMetadata = resultMeta

	if _, ok := resp.Result["checksum"]; !ok {
		return fmt.Errorf("dataset: no checksum : %+v", resp.Result)
	}

	c.AddModel.MetadataChecksum, ok = resp.Result["checksum"].(string)
	if !ok {
		return fmt.Errorf("dataset: checksum bad type : %+v", resp.Result["checksum"])
	}
	return nil
}

func (c *Card) AddToDashboard() error {
	route := fmt.Sprintf(routes[addCardToDashboardEndpoint], c.OrderedCard.DashboardID)

	_, errormsg, err := c.Client.Do("POST", route, map[string]int{"card_id": c.OrderedCard.CardID})
	if err != nil {
		return err
	}

	if errormsg != nil {
		return fmt.Errorf("add to dashboard: %+v", errormsg)
	}

	return nil
}

/*
type Card struct {
		Name                  string                 `json:"name"`
		DatasetQuery          *DatasetQuery          `json:"dataset_query`
		Display               string                 `json:"display"`
		Description           string                 `json:"description"`
		VisualizationSettings map[string]interface{} `json:"visualization_settings"`
		CollectionID          int                    `json:"collection_id"`
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
*/
