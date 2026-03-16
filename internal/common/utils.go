package common

import "encoding/json"

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func MapToStruct(m map[string]interface{}, v interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
