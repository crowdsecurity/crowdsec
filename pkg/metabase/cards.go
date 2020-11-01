package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
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
	//ID                    float64                `json:"id"`
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

type OrderedCardToSend struct {
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
	ret.OrderedCard.Card.Creator = creator
	ret.OrderedCard.Card.Model = "card"
	ret.Client = client
	ret.GetModel.Creator = creator
	return ret, nil
}

func (c *Card) Dataset() error {
	success, errormsg, err := c.Client.Do("POST", routes[datasetEndpoint], c.DatasetQuery)
	if errormsg != nil {
		return fmt.Errorf("dataset: %+v", errormsg)
	}

	if err != nil {
		return fmt.Errorf("dataset err: %s", err)
	}

	response := struct {
		Data map[string]interface{} `json:"data"`
	}{}
	marshal, err := json.Marshal(success)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(marshal, &response); err != nil {
		return err
	}

	marshal, err = json.Marshal(response.Data)
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

	c.AddFrontInfoModel.ID = c.GetModel.ID
	c.AddFrontInfoToDashboardModel.CardID = c.GetModel.ID
	c.OrderedCard.CardID = c.GetModel.ID
	return nil
}

func (c *Card) Query() error {
	if c.DatasetQuery.Parameters == nil {
		c.DatasetQuery.Parameters = make([]interface{}, 0)
	}
	success, errormsg, err := c.Client.Do("POST", fmt.Sprintf(routes[queryEndpoint], c.GetModel.ID), map[string]interface{}{
		"parameters": c.DatasetQuery.Parameters,
	})
	if err != nil {
		return fmt.Errorf("query: http: %s", err)
	}

	if errormsg != nil {
		return fmt.Errorf("query: http: %+v", errormsg)
	}

	response := struct {
		Data map[string]interface{} `json:"data"`
	}{}
	marshal, err := json.Marshal(success)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(marshal, &response); err != nil {
		return err
	}

	marshal, err = json.Marshal(response.Data)
	if err != nil {
		return errors.Wrap(err, "query")
	}

	resp := struct {
		Result map[string]interface{} `json:"results_metadata"`
	}{}

	if err := json.Unmarshal(marshal, &resp); err != nil {
		return errors.Wrap(err, "query")
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

	_, errormsg, err := c.Client.Do("POST", route, map[string]int{"cardId": c.OrderedCard.CardID})
	if err != nil {
		return err
	}

	if errormsg != nil {
		return fmt.Errorf("add to dashboard: %+v", errormsg)
	}

	return nil
}
