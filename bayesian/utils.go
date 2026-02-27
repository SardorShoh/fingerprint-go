package bayesian

import (
	"fmt"
	"slices"
)

// ArrayIntersection performs a set "intersection" on the given arrays.
func ArrayIntersection[T comparable](a, b []T) []T {
	var result []T
	for _, x := range a {
		if slices.Contains(b, x) {
			result = append(result, x)
		}
	}
	return result
}

// ArrayUnion performs a set "union" operation on two arrays.
func ArrayUnion[T comparable](a, b []T) []T {
	result := make([]T, len(a))
	copy(result, a)
	for _, x := range b {
		if !slices.Contains(a, x) {
			result = append(result, x)
		}
	}
	return result
}

// ArrayZip combines two arrays into a single array using the combiner function f.
func ArrayZip[T any](a, b [][]T, f func([]T, []T) []T) [][]T {
	result := make([][]T, len(a))
	for i := range a {
		result[i] = f(a[i], b[i])
	}
	return result
}

// Undeeper removes the "deeper/skip" structures from the conditional probability table.
func Undeeper(obj any) any {
	m, ok := obj.(map[string]any)
	if !ok {
		return obj
	}

	result := make(map[string]any)
	for key, val := range m {
		if key == "skip" {
			continue
		}
		if key == "deeper" {
			deeperMap, isMap := Undeeper(val).(map[string]any)
			if isMap {
				for k, v := range deeperMap {
					result[k] = v
				}
			}
			continue
		}
		result[key] = Undeeper(val)
	}
	return result
}

func filterByLastLevelKeys(tree any, validKeys []string) [][]string {
	var foundPaths [][]string

	var dfs func(t any, acc []string)
	dfs = func(t any, acc []string) {
		m, ok := t.(map[string]any)
		if !ok || m == nil {
			return
		}

		for key, val := range m {
			valMap, isMap := val.(map[string]any)
			if !isMap || valMap == nil {
				if slices.Contains(validKeys, key) {
					if len(foundPaths) == 0 {
						for _, x := range acc {
							foundPaths = append(foundPaths, []string{x})
						}
					} else {
						var mappedAcc [][]string
						for _, x := range acc {
							mappedAcc = append(mappedAcc, []string{x})
						}

						// arrayZip functionality
						var newFoundPaths [][]string
						for i := 0; i < len(foundPaths) && i < len(mappedAcc); i++ {
							union := append([]string{}, foundPaths[i]...)
							for _, v := range mappedAcc[i] {
								if !slices.Contains(union, v) {
									union = append(union, v)
								}
							}
							newFoundPaths = append(newFoundPaths, union)
						}
						foundPaths = newFoundPaths
					}
				}
				continue
			} else {
				dfs(val, append(acc, key))
			}
		}
	}

	dfs(tree, []string{})
	return foundPaths
}

// GetConstraintClosure returns an extended set of constraints induced by the original constraints and network structure.
func GetConstraintClosure(network *Network, possibleValues map[string][]string) (map[string][]string, error) {
	sets := make([]map[string][]string, 0)
	foundMatchingValues := false

	for key, values := range possibleValues {
		if len(values) == 0 {
			return nil, fmt.Errorf("The current constraints are too restrictive. No possible values can be found for the given constraints.")
		}

		node, ok := network.NodesByName[key]
		if !ok {
			continue // skip if node not found
		}

		tree := Undeeper(node.Definition.ConditionalProbabilities)
		zippedValues := filterByLastLevelKeys(tree, values)

		if len(zippedValues) > 0 {
			foundMatchingValues = true
		}

		set := make(map[string][]string)
		for i, x := range zippedValues {
			if i < len(node.Definition.ParentNames) {
				set[node.Definition.ParentNames[i]] = x
			}
		}
		set[key] = values
		sets = append(sets, set)
	}

	if !foundMatchingValues {
		return make(map[string][]string), nil
	}

	result := make(map[string][]string)
	for _, set := range sets {
		for key, vals := range set {
			if existingVals, found := result[key]; found {
				result[key] = ArrayIntersection(existingVals, vals)
			} else {
				result[key] = vals
			}

			if len(result[key]) == 0 {
				return nil, fmt.Errorf("The current constraints are too restrictive. No possible values can be found for the given constraints.")
			}
		}
	}

	return result, nil
}
