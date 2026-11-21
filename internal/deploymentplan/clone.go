package deploymentplan

import "encoding/json"

func (p *Plan) DeepCopy() *Plan {
	if p == nil {
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var out Plan
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	out.Requester = p.Requester
	out.IdempotencyKey = p.IdempotencyKey
	return &out
}

func (c *Companion) DeepCopy() *Companion {
	if c == nil {
		return nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var out Companion
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}
