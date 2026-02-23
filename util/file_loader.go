package util

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type YamlLoader struct {
	content map[string]interface{}
	path    string
}

func LoadYamlFromPath(path string) *YamlLoader {
	var m map[string]interface{}
	data, err := os.ReadFile(path)
	err = yaml.Unmarshal(data, &m)
	if err != nil {
		fmt.Println("Failed to load file:", err)
		panic(err)
	}

	return &YamlLoader{
		content: m,
		path:    path,
	}
}

func (y *YamlLoader) Save() bool {
	_, err := yaml.Marshal(y.content)
	if err != nil {
		return false
	} else {
		return true
	}
}

func (y *YamlLoader) GetContent() *map[string]interface{} {
	return &y.content
}

func (y *YamlLoader) GetPath() *string {
	return &y.path
}

// 获取嵌套键的值
func (y *YamlLoader) get(key ...string) (interface{}, bool) {
	var current interface{} = y.content
	for _, k := range key {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func (y *YamlLoader) GetStringOrElse(elseValue string, key ...string) string {
	val, ok := y.get(key...)
	if !ok {
		return elseValue
	}
	switch v := val.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (y *YamlLoader) GetString(key ...string) string {
	val, ok := y.get(key...)
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (y *YamlLoader) GetBool(elseValue bool, key ...string) bool {
	val, ok := y.get(key...)
	if !ok {
		return elseValue
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case int, int64, float64:
		return fmt.Sprintf("%v", v) == "1"
	default:
		return elseValue
	}
}

func (y *YamlLoader) GetFloat64(elseValue float64, key ...string) float64 {
	val, ok := y.get(key...)
	if !ok {
		return elseValue
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		var f float64
		_, err := fmt.Sscanf(v, "%f", &f)
		if err == nil {
			return f
		} else {
			return elseValue
		}
	}
	return elseValue
}
