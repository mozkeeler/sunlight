package sunlight

import "time"

func TimeToJSONString(t time.Time) string {
	const layout = "Jan 2 2006"
	return t.Format(layout)
}
