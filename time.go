package main

import "time"

type Time struct {
	time.Time
}

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`""`), nil
	}
	return []byte(`"` + t.UTC().Format(time.RFC3339Nano) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == `""` || string(data) == `null` {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(`"`+time.RFC3339Nano+`"`, string(data))
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}
