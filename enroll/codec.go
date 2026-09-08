package enroll

import "encoding/json"

func marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
