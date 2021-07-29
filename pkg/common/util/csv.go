package util

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/dnlo/struct2csv"
)

func CSVRowToMap(headers []string, row []string) map[string]string {
	m := map[string]string{}
	for i := range headers {
		m[headers[i]] = row[i]
	}
	return m
}

func CSVToMap(reader io.Reader) ([]map[string]string, error) {
	r := csv.NewReader(reader)
	rows := []map[string]string{}
	headers, err := r.Read()
	if err != nil {
		return nil, err
	}
	for {
		row, err := r.Read()
		if err == io.EOF {
			return rows, nil
		} else if err != nil {
			return nil, err
		}
		rows = append(rows, CSVRowToMap(headers, row))
	}
}

func WriteToCSV(path string, data []interface{}) (*string, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("error while creating csv export file %v ", err)
	}
	defer f.Close()
	w := struct2csv.NewWriter(f)
	w.SetUseTags(true)
	defer w.Flush()

	err = w.WriteColNames(data[0])
	if err != nil {
		return nil, fmt.Errorf("error while writing csv headers %v ", err)
	}
	for _, rec := range data {
		err = w.WriteStruct(rec)
		if err != nil {
			return nil, fmt.Errorf("error while writing csv row %v ", err)
		}
	}
	return &path, nil
}
