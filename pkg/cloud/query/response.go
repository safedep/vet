package query

type QueryRow map[string]interface{}
type QueryResponse []QueryRow

func (q *QueryResponse) Count() int {
	if q == nil {
		return 0
	}

	return len(*q)
}

func (q *QueryResponse) GetRow(index int) *QueryRow {
	if q.Count() <= index {
		return nil
	}

	return &(*q)[index]
}

func (q *QueryResponse) ForEachRow(fn func(*QueryRow)) {
	if q == nil {
		return
	}

	for _, row := range *q {
		fn(&row)
	}
}

func (q *QueryRow) ForEachField(fn func(string, interface{})) {
	if q == nil {
		return
	}

	for key, val := range *q {
		fn(key, val)
	}
}

func (q *QueryRow) GetField(key string) interface{} {
	if q == nil {
		return nil
	}

	return (*q)[key]
}
