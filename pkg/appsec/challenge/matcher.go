package challenge

type ChallengeMatcher struct {
	allowed    bool
	conditions []bool
}

func (cm *ChallengeMatcher) AddConditions(conditions ...bool) {
	cm.conditions = append(cm.conditions, conditions...)
}

func (cm *ChallengeMatcher) Allow() bool {
	allowed := true
	for _, condition := range cm.conditions {
		if !condition {
			allowed = false
			break
		}
	}
	cm.allowed = allowed
	return cm.allowed
}

func (cm *ChallengeMatcher) Deny(reason string) bool {
	if cm.allowed {
		return false
	}
	return true
}

func NewChallengeMatcher(conditions ...bool) *ChallengeMatcher {
	return &ChallengeMatcher{
		conditions: conditions,
	}
}
