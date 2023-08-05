package uadguard

type ErrorRsp struct {
	Message string `json:"message"`
}

type FilteringStatusRsp struct {
	Rules []string `json:"user_rules"`
}
