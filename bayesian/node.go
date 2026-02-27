package bayesian

import (
	"math/rand"
)

// RecordList represents a list of records for Bayesian logic
type RecordList []map[string]any

func getRelativeFrequencies(data RecordList, attributeName string) map[string]float64 {
	frequencies := make(map[string]int)
	totalCount := len(data)

	for _, record := range data {
		if val, ok := record[attributeName].(string); ok {
			frequencies[val]++
		}
	}

	result := make(map[string]float64)
	for key, value := range frequencies {
		result[key] = float64(value) / float64(totalCount)
	}
	return result
}

// NodeDefinition defines the structure of a bayesian node
type NodeDefinition struct {
	Name                     string   `json:"name"`
	ParentNames              []string `json:"parentNames"`
	PossibleValues           []string `json:"possibleValues"`
	ConditionalProbabilities any      `json:"conditionalProbabilities"` // usually map[string]any
}

// Node is an implementation of a single node in a bayesian network
type Node struct {
	Definition NodeDefinition
}

func NewNode(def NodeDefinition) *Node {
	return &Node{Definition: def}
}

func (n *Node) getProbabilitiesGivenKnownValues(parentValues map[string]string) map[string]float64 {
	probabilities := n.Definition.ConditionalProbabilities

	for _, parentName := range n.Definition.ParentNames {
		parentValue := parentValues[parentName]
		m, ok := probabilities.(map[string]any)
		if !ok {
			break
		}

		if deeper, hasDeeper := m["deeper"].(map[string]any); hasDeeper {
			if val, exists := deeper[parentValue]; exists {
				probabilities = val
			} else if skip, hasSkip := m["skip"]; hasSkip {
				probabilities = skip
			} else {
				break
			}
		} else if skip, hasSkip := m["skip"]; hasSkip {
			probabilities = skip
		} else {
			break
		}
	}

	// We expect the final probabilities to be map[string]float64 or similar
	result := make(map[string]float64)
	if m, ok := probabilities.(map[string]any); ok {
		for k, v := range m {
			if f, ok := v.(float64); ok {
				result[k] = f
			}
		}
	}
	return result
}

func (n *Node) sampleRandomValueFromPossibilities(possibleValues []string, totalProbability float64, probabilities map[string]float64) string {
	if len(possibleValues) == 0 {
		return ""
	}
	chosenValue := possibleValues[0]
	anchor := rand.Float64() * totalProbability
	cumulativeProbability := 0.0

	for _, possibleValue := range possibleValues {
		cumulativeProbability += probabilities[possibleValue]
		if cumulativeProbability > anchor {
			chosenValue = possibleValue
			break
		}
	}

	return chosenValue
}

func (n *Node) Sample(parentValues map[string]string) string {
	if parentValues == nil {
		parentValues = make(map[string]string)
	}
	probabilities := n.getProbabilitiesGivenKnownValues(parentValues)
	var possibleValues []string
	for k := range probabilities {
		possibleValues = append(possibleValues, k)
	}

	return n.sampleRandomValueFromPossibilities(possibleValues, 1.0, probabilities)
}

func (n *Node) SampleAccordingToRestrictions(parentValues map[string]string, valuePossibilities []string, bannedValues []string) string {
	probabilities := n.getProbabilitiesGivenKnownValues(parentValues)
	totalProbability := 0.0
	var validValues []string

	var valuesInDistribution []string
	for k := range probabilities {
		valuesInDistribution = append(valuesInDistribution, k)
	}

	possibleValues := valuePossibilities
	if len(possibleValues) == 0 {
		possibleValues = valuesInDistribution
	}

	for _, value := range possibleValues {
		if !slicesContains(bannedValues, value) && slicesContains(valuesInDistribution, value) {
			validValues = append(validValues, value)
			totalProbability += probabilities[value]
		}
	}

	if len(validValues) == 0 {
		return ""
	}

	return n.sampleRandomValueFromPossibilities(validValues, totalProbability, probabilities)
}

func slicesContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
