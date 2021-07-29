package gsheetw

import (
	"io/ioutil"
	"net/http"

	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/errs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/Iwark/spreadsheet.v2"
)

type Wrapper struct {
	client  *http.Client
	service *spreadsheet.Service
}

func (w *Wrapper) GetService() *spreadsheet.Service {
	return w.service
}

func (w *Wrapper) GetWorksheetValues(spreadsheetID string, worksheetName string) ([]map[string]string, error) {
	if spreadsheetID == "" || worksheetName == "" {
		return nil, errs.ErrInvalidArg
	}
	ss, err := w.service.FetchSpreadsheet(spreadsheetID)
	if err != nil {
		return nil, err
	}
	sheet, err := ss.SheetByTitle(worksheetName)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	maxRows, maxCols := len(sheet.Rows), len(sheet.Columns)
	for col := 0; col < maxCols; col++ {
		key := sheet.Columns[col][0].Value
		keys = append(keys, key)
	}
	rawValues := []map[string]string{}
	for row := 1; row < maxRows; row++ {
		raw := map[string]string{}
		for col := 0; col < maxCols; col++ {
			cell := sheet.Rows[row][col]
			raw[keys[col]] = cell.Value
		}
		rawValues = append(rawValues, raw)
	}
	return rawValues, nil
}

func (w *Wrapper) CleanUpdate(spreadsheetID string, worksheetName string, values [][]string) error {
	if spreadsheetID == "" || worksheetName == "" {
		return errs.ErrInvalidArg
	}
	ss, err := w.service.FetchSpreadsheet(spreadsheetID)
	if err != nil {
		return err
	}
	sheet, err := ss.SheetByTitle(worksheetName)
	if err != nil {
		return err
	}
	// reset the values
	rows, cols := len(sheet.Rows), len(sheet.Columns)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			sheet.Update(i, j, "")
		}
	}
	for i, rows := range values {
		for j, value := range rows {
			sheet.Update(i, j, value)
		}
	}
	err = sheet.Synchronize()
	return err
}

func NewWrapper(jsonCredFilePath string) (*Wrapper, error) {
	if jsonCredFilePath == "" {
		return nil, errs.ErrInvalidArg
	}
	credJSON, err := ioutil.ReadFile(jsonCredFilePath)
	if err != nil {
		return nil, err
	}
	jwtConfig, err := google.JWTConfigFromJSON(credJSON, spreadsheet.Scope)
	if err != nil {
		return nil, err
	}
	client := jwtConfig.Client(oauth2.NoContext)
	service := spreadsheet.NewServiceWithClient(client)
	wrapper := &Wrapper{
		client:  client,
		service: service,
	}
	return wrapper, nil
}
