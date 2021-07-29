package tfinv

import (
	"encoding/json"
	"strings"

	log "github.com/sirupsen/logrus"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/gsheetw"
)

func (w *wrapper) FetchData() ([]byte, error) {
	tfs, err := w.GetTechFamilies()
	if err != nil {
		log.Errorf("while building cost family center map - %v", err)
		return nil, err
	}
	mapping := map[string]TechFamily{}
	for _, tf := range tfs {
		_, found := mapping[tf.Name]
		if found { // don't overwrite
			log.Infof("duplicate cfc - %v %v", tf.Entity, tf.Name)
			continue
		}
		mapping[tf.Name] = tf
	}

	jsons, err := json.Marshal(mapping)
	return jsons, err
}

func (w *wrapper) GetTechFamilies() ([]TechFamily, error) {
	log.Info("fetching tech family mappings")
	rawValues, err := w.gsheetw.GetWorksheetValues(w.config.SpreadsheetID, w.config.MappingWorksheetName)
	if err != nil {
		log.Errorf("while fetching tfs from mapping sheet - %v", err)
		return nil, err
	}
	tfs := []TechFamily{}
	for _, raw := range rawValues {
		tf := TechFamily{
			Name:              processRawValue(raw["tech_family"]),
			Entity:            processRawValue(raw["business_entity"]),
			Handlers:          processHandlers(raw["tf_leads_handle"]),
			CostFamilyCenters: processRawCsv(raw["cost_family_or_center"]),
		}
		tfs = append(tfs, tf)
	}
	log.Info("done fetching tech family mappings")
	return tfs, nil
}

func (i *wrapper) GetTechFamiliesMapping() (map[string]TechFamily, error) {
	tfs, err := i.GetTechFamilies()
	if err != nil {
		log.Errorf("while building cost family center map - %v", err)
		return nil, err
	}
	mapping := map[string]TechFamily{}
	for _, tf := range tfs {
		_, found := mapping[tf.Name]
		if found { // don't overwrite
			log.Infof("duplicate cfc - %v %v", tf.Entity, tf.Name)
			continue
		}
		mapping[tf.Name] = tf
	}
	return mapping, nil
}

func processRawCsv(raw string) []string {
	ret := []string{}
	raw = processRawValue(raw)
	if raw == "na" {
		return ret
	}
	values := strings.Split(raw, ",")
	for _, v := range values {
		p := processRawValue(v)
		if p == "na" {
			continue
		}
		ret = append(ret, p)
	}
	return ret
}

func processRawValue(raw string) string {
	raw = strings.Trim(strings.TrimSpace(raw), ",")
	if raw == "" {
		return "na"
	}
	return raw
}

func processHandlers(raw string) []string {
	handlers := strings.Split(strings.ReplaceAll(strings.TrimSpace(raw), "@", ""), "\n")

	return handlers
}

func NewWrapper(config Config) (*wrapper, error) {
	gsheetw, err := gsheetw.NewWrapper(config.CredentialsFilePath)
	if err != nil {
		return nil, err
	}
	return &wrapper{
		config:  config,
		gsheetw: gsheetw,
	}, nil
}
