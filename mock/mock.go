package mock

import "time"

type Claim struct {
	ID   int
	Name string
	Type string
}

func (c Claim) GetID() int {
	return c.ID
}

func (c Claim) GetName() string {
	return c.Name
}

func (c Claim) GetType() string {
	return c.Type
}

func ExpiresAt(d time.Duration) time.Time {
	t, _ := time.Parse(time.RFC3339, "2020-00-00T00:30:00Z")
	return t
}
