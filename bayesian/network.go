package bayesian

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
)

// Network is an implementation of a bayesian network capable of randomly sampling from the distribution
// represented by the network.
type Network struct {
	NodesInSamplingOrder []*Node
	NodesByName          map[string]*Node
}

// NewNetwork creates a new BayesianNetwork from a zip file definition.
func NewNetwork(path string) *Network {
	network := &Network{
		NodesByName: make(map[string]*Node),
	}

	r, err := zip.OpenReader(path)
	if err != nil {
		fmt.Printf("Error opening zip file %s: %v\n", path, err)
		return network
	}
	defer r.Close()

	if len(r.File) == 0 {
		return network
	}

	f, err := r.File[0].Open()
	if err != nil {
		fmt.Printf("Error opening file in zip: %v\n", err)
		return network
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Error reading file in zip: %v\n", err)
		return network
	}

	var networkDef struct {
		Nodes []NodeDefinition `json:"nodes"`
	}
	err = json.Unmarshal(content, &networkDef)
	if err != nil {
		fmt.Printf("Error unmarshaling network JSON: %v\n", err)
		return network
	}

	for _, nDef := range networkDef.Nodes {
		node := NewNode(nDef)
		network.NodesInSamplingOrder = append(network.NodesInSamplingOrder, node)
		network.NodesByName[nDef.Name] = node
	}

	return network
}

// GenerateSample randomly samples from the distribution represented by the bayesian network.
func (bn *Network) GenerateSample(inputValues map[string]string) map[string]string {
	sample := make(map[string]string)
	for k, v := range inputValues {
		sample[k] = v
	}

	for _, node := range bn.NodesInSamplingOrder {
		if _, ok := sample[node.Definition.Name]; !ok {
			sample[node.Definition.Name] = node.Sample(sample)
		}
	}
	return sample
}

// GenerateConsistentSampleWhenPossible randomly samples values from the distribution represented by the bayesian network,
// making sure the sample is consistent with the provided restrictions on value possibilities.
func (bn *Network) GenerateConsistentSampleWhenPossible(valuePossibilities map[string][]string) map[string]string {
	return bn.recursivelyGenerateConsistentSampleWhenPossible(make(map[string]string), valuePossibilities, 0)
}

func (bn *Network) recursivelyGenerateConsistentSampleWhenPossible(
	sampleSoFar map[string]string,
	valuePossibilities map[string][]string,
	depth int,
) map[string]string {
	if depth >= len(bn.NodesInSamplingOrder) {
		return sampleSoFar
	}

	bannedValues := make([]string, 0)
	node := bn.NodesInSamplingOrder[depth]
	var sampleValue string

	for {
		sampleValue = node.SampleAccordingToRestrictions(sampleSoFar, valuePossibilities[node.Definition.Name], bannedValues)
		if sampleValue == "" {
			break
		}

		sampleSoFar[node.Definition.Name] = sampleValue

		if depth+1 < len(bn.NodesInSamplingOrder) {
			sample := bn.recursivelyGenerateConsistentSampleWhenPossible(sampleSoFar, valuePossibilities, depth+1)
			if len(sample) > 0 {
				return sample
			}
		} else {
			return sampleSoFar
		}

		bannedValues = append(bannedValues, sampleValue)
	}

	return make(map[string]string)
}
