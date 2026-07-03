package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

func SaveResults(target string, data map[string]interface{}) error {
	filename := fmt.Sprintf("%s_report.json", target)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return err
	}

	return nil
}
