// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/codesourcefile"
	"github.com/safedep/vet/ent/depsusageevidence"
	"github.com/safedep/vet/ent/predicate"
)

// DepsUsageEvidenceQuery is the builder for querying DepsUsageEvidence entities.
type DepsUsageEvidenceQuery struct {
	config
	ctx        *QueryContext
	order      []depsusageevidence.OrderOption
	inters     []Interceptor
	predicates []predicate.DepsUsageEvidence
	withUsedIn *CodeSourceFileQuery
	withFKs    bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DepsUsageEvidenceQuery builder.
func (dueq *DepsUsageEvidenceQuery) Where(ps ...predicate.DepsUsageEvidence) *DepsUsageEvidenceQuery {
	dueq.predicates = append(dueq.predicates, ps...)
	return dueq
}

// Limit the number of records to be returned by this query.
func (dueq *DepsUsageEvidenceQuery) Limit(limit int) *DepsUsageEvidenceQuery {
	dueq.ctx.Limit = &limit
	return dueq
}

// Offset to start from.
func (dueq *DepsUsageEvidenceQuery) Offset(offset int) *DepsUsageEvidenceQuery {
	dueq.ctx.Offset = &offset
	return dueq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dueq *DepsUsageEvidenceQuery) Unique(unique bool) *DepsUsageEvidenceQuery {
	dueq.ctx.Unique = &unique
	return dueq
}

// Order specifies how the records should be ordered.
func (dueq *DepsUsageEvidenceQuery) Order(o ...depsusageevidence.OrderOption) *DepsUsageEvidenceQuery {
	dueq.order = append(dueq.order, o...)
	return dueq
}

// QueryUsedIn chains the current query on the "used_in" edge.
func (dueq *DepsUsageEvidenceQuery) QueryUsedIn() *CodeSourceFileQuery {
	query := (&CodeSourceFileClient{config: dueq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dueq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dueq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(depsusageevidence.Table, depsusageevidence.FieldID, selector),
			sqlgraph.To(codesourcefile.Table, codesourcefile.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, depsusageevidence.UsedInTable, depsusageevidence.UsedInColumn),
		)
		fromU = sqlgraph.SetNeighbors(dueq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first DepsUsageEvidence entity from the query.
// Returns a *NotFoundError when no DepsUsageEvidence was found.
func (dueq *DepsUsageEvidenceQuery) First(ctx context.Context) (*DepsUsageEvidence, error) {
	nodes, err := dueq.Limit(1).All(setContextOp(ctx, dueq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{depsusageevidence.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) FirstX(ctx context.Context) *DepsUsageEvidence {
	node, err := dueq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DepsUsageEvidence ID from the query.
// Returns a *NotFoundError when no DepsUsageEvidence ID was found.
func (dueq *DepsUsageEvidenceQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dueq.Limit(1).IDs(setContextOp(ctx, dueq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{depsusageevidence.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) FirstIDX(ctx context.Context) int {
	id, err := dueq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DepsUsageEvidence entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DepsUsageEvidence entity is found.
// Returns a *NotFoundError when no DepsUsageEvidence entities are found.
func (dueq *DepsUsageEvidenceQuery) Only(ctx context.Context) (*DepsUsageEvidence, error) {
	nodes, err := dueq.Limit(2).All(setContextOp(ctx, dueq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{depsusageevidence.Label}
	default:
		return nil, &NotSingularError{depsusageevidence.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) OnlyX(ctx context.Context) *DepsUsageEvidence {
	node, err := dueq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DepsUsageEvidence ID in the query.
// Returns a *NotSingularError when more than one DepsUsageEvidence ID is found.
// Returns a *NotFoundError when no entities are found.
func (dueq *DepsUsageEvidenceQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dueq.Limit(2).IDs(setContextOp(ctx, dueq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{depsusageevidence.Label}
	default:
		err = &NotSingularError{depsusageevidence.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) OnlyIDX(ctx context.Context) int {
	id, err := dueq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DepsUsageEvidences.
func (dueq *DepsUsageEvidenceQuery) All(ctx context.Context) ([]*DepsUsageEvidence, error) {
	ctx = setContextOp(ctx, dueq.ctx, ent.OpQueryAll)
	if err := dueq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*DepsUsageEvidence, *DepsUsageEvidenceQuery]()
	return withInterceptors[[]*DepsUsageEvidence](ctx, dueq, qr, dueq.inters)
}

// AllX is like All, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) AllX(ctx context.Context) []*DepsUsageEvidence {
	nodes, err := dueq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DepsUsageEvidence IDs.
func (dueq *DepsUsageEvidenceQuery) IDs(ctx context.Context) (ids []int, err error) {
	if dueq.ctx.Unique == nil && dueq.path != nil {
		dueq.Unique(true)
	}
	ctx = setContextOp(ctx, dueq.ctx, ent.OpQueryIDs)
	if err = dueq.Select(depsusageevidence.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) IDsX(ctx context.Context) []int {
	ids, err := dueq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dueq *DepsUsageEvidenceQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, dueq.ctx, ent.OpQueryCount)
	if err := dueq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, dueq, querierCount[*DepsUsageEvidenceQuery](), dueq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) CountX(ctx context.Context) int {
	count, err := dueq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dueq *DepsUsageEvidenceQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, dueq.ctx, ent.OpQueryExist)
	switch _, err := dueq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (dueq *DepsUsageEvidenceQuery) ExistX(ctx context.Context) bool {
	exist, err := dueq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DepsUsageEvidenceQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dueq *DepsUsageEvidenceQuery) Clone() *DepsUsageEvidenceQuery {
	if dueq == nil {
		return nil
	}
	return &DepsUsageEvidenceQuery{
		config:     dueq.config,
		ctx:        dueq.ctx.Clone(),
		order:      append([]depsusageevidence.OrderOption{}, dueq.order...),
		inters:     append([]Interceptor{}, dueq.inters...),
		predicates: append([]predicate.DepsUsageEvidence{}, dueq.predicates...),
		withUsedIn: dueq.withUsedIn.Clone(),
		// clone intermediate query.
		sql:  dueq.sql.Clone(),
		path: dueq.path,
	}
}

// WithUsedIn tells the query-builder to eager-load the nodes that are connected to
// the "used_in" edge. The optional arguments are used to configure the query builder of the edge.
func (dueq *DepsUsageEvidenceQuery) WithUsedIn(opts ...func(*CodeSourceFileQuery)) *DepsUsageEvidenceQuery {
	query := (&CodeSourceFileClient{config: dueq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	dueq.withUsedIn = query
	return dueq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		PackageHint string `json:"package_hint,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.DepsUsageEvidence.Query().
//		GroupBy(depsusageevidence.FieldPackageHint).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dueq *DepsUsageEvidenceQuery) GroupBy(field string, fields ...string) *DepsUsageEvidenceGroupBy {
	dueq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &DepsUsageEvidenceGroupBy{build: dueq}
	grbuild.flds = &dueq.ctx.Fields
	grbuild.label = depsusageevidence.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		PackageHint string `json:"package_hint,omitempty"`
//	}
//
//	client.DepsUsageEvidence.Query().
//		Select(depsusageevidence.FieldPackageHint).
//		Scan(ctx, &v)
func (dueq *DepsUsageEvidenceQuery) Select(fields ...string) *DepsUsageEvidenceSelect {
	dueq.ctx.Fields = append(dueq.ctx.Fields, fields...)
	sbuild := &DepsUsageEvidenceSelect{DepsUsageEvidenceQuery: dueq}
	sbuild.label = depsusageevidence.Label
	sbuild.flds, sbuild.scan = &dueq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a DepsUsageEvidenceSelect configured with the given aggregations.
func (dueq *DepsUsageEvidenceQuery) Aggregate(fns ...AggregateFunc) *DepsUsageEvidenceSelect {
	return dueq.Select().Aggregate(fns...)
}

func (dueq *DepsUsageEvidenceQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range dueq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, dueq); err != nil {
				return err
			}
		}
	}
	for _, f := range dueq.ctx.Fields {
		if !depsusageevidence.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dueq.path != nil {
		prev, err := dueq.path(ctx)
		if err != nil {
			return err
		}
		dueq.sql = prev
	}
	return nil
}

func (dueq *DepsUsageEvidenceQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DepsUsageEvidence, error) {
	var (
		nodes       = []*DepsUsageEvidence{}
		withFKs     = dueq.withFKs
		_spec       = dueq.querySpec()
		loadedTypes = [1]bool{
			dueq.withUsedIn != nil,
		}
	)
	if dueq.withUsedIn != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, depsusageevidence.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*DepsUsageEvidence).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &DepsUsageEvidence{config: dueq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dueq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := dueq.withUsedIn; query != nil {
		if err := dueq.loadUsedIn(ctx, query, nodes, nil,
			func(n *DepsUsageEvidence, e *CodeSourceFile) { n.Edges.UsedIn = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (dueq *DepsUsageEvidenceQuery) loadUsedIn(ctx context.Context, query *CodeSourceFileQuery, nodes []*DepsUsageEvidence, init func(*DepsUsageEvidence), assign func(*DepsUsageEvidence, *CodeSourceFile)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*DepsUsageEvidence)
	for i := range nodes {
		if nodes[i].deps_usage_evidence_used_in == nil {
			continue
		}
		fk := *nodes[i].deps_usage_evidence_used_in
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(codesourcefile.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "deps_usage_evidence_used_in" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (dueq *DepsUsageEvidenceQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dueq.querySpec()
	_spec.Node.Columns = dueq.ctx.Fields
	if len(dueq.ctx.Fields) > 0 {
		_spec.Unique = dueq.ctx.Unique != nil && *dueq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, dueq.driver, _spec)
}

func (dueq *DepsUsageEvidenceQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(depsusageevidence.Table, depsusageevidence.Columns, sqlgraph.NewFieldSpec(depsusageevidence.FieldID, field.TypeInt))
	_spec.From = dueq.sql
	if unique := dueq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if dueq.path != nil {
		_spec.Unique = true
	}
	if fields := dueq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, depsusageevidence.FieldID)
		for i := range fields {
			if fields[i] != depsusageevidence.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := dueq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dueq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dueq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dueq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dueq *DepsUsageEvidenceQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dueq.driver.Dialect())
	t1 := builder.Table(depsusageevidence.Table)
	columns := dueq.ctx.Fields
	if len(columns) == 0 {
		columns = depsusageevidence.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dueq.sql != nil {
		selector = dueq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dueq.ctx.Unique != nil && *dueq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range dueq.predicates {
		p(selector)
	}
	for _, p := range dueq.order {
		p(selector)
	}
	if offset := dueq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dueq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// DepsUsageEvidenceGroupBy is the group-by builder for DepsUsageEvidence entities.
type DepsUsageEvidenceGroupBy struct {
	selector
	build *DepsUsageEvidenceQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (duegb *DepsUsageEvidenceGroupBy) Aggregate(fns ...AggregateFunc) *DepsUsageEvidenceGroupBy {
	duegb.fns = append(duegb.fns, fns...)
	return duegb
}

// Scan applies the selector query and scans the result into the given value.
func (duegb *DepsUsageEvidenceGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, duegb.build.ctx, ent.OpQueryGroupBy)
	if err := duegb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DepsUsageEvidenceQuery, *DepsUsageEvidenceGroupBy](ctx, duegb.build, duegb, duegb.build.inters, v)
}

func (duegb *DepsUsageEvidenceGroupBy) sqlScan(ctx context.Context, root *DepsUsageEvidenceQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(duegb.fns))
	for _, fn := range duegb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*duegb.flds)+len(duegb.fns))
		for _, f := range *duegb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*duegb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := duegb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// DepsUsageEvidenceSelect is the builder for selecting fields of DepsUsageEvidence entities.
type DepsUsageEvidenceSelect struct {
	*DepsUsageEvidenceQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (dues *DepsUsageEvidenceSelect) Aggregate(fns ...AggregateFunc) *DepsUsageEvidenceSelect {
	dues.fns = append(dues.fns, fns...)
	return dues
}

// Scan applies the selector query and scans the result into the given value.
func (dues *DepsUsageEvidenceSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, dues.ctx, ent.OpQuerySelect)
	if err := dues.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DepsUsageEvidenceQuery, *DepsUsageEvidenceSelect](ctx, dues.DepsUsageEvidenceQuery, dues, dues.inters, v)
}

func (dues *DepsUsageEvidenceSelect) sqlScan(ctx context.Context, root *DepsUsageEvidenceQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(dues.fns))
	for _, fn := range dues.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*dues.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dues.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
