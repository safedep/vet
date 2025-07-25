// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/predicate"
	"github.com/safedep/vet/ent/reportproject"
	"github.com/safedep/vet/ent/reportscorecard"
	"github.com/safedep/vet/ent/reportscorecardcheck"
)

// ReportScorecardUpdate is the builder for updating ReportScorecard entities.
type ReportScorecardUpdate struct {
	config
	hooks    []Hook
	mutation *ReportScorecardMutation
}

// Where appends a list predicates to the ReportScorecardUpdate builder.
func (rsu *ReportScorecardUpdate) Where(ps ...predicate.ReportScorecard) *ReportScorecardUpdate {
	rsu.mutation.Where(ps...)
	return rsu
}

// SetScore sets the "score" field.
func (rsu *ReportScorecardUpdate) SetScore(f float32) *ReportScorecardUpdate {
	rsu.mutation.ResetScore()
	rsu.mutation.SetScore(f)
	return rsu
}

// SetNillableScore sets the "score" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableScore(f *float32) *ReportScorecardUpdate {
	if f != nil {
		rsu.SetScore(*f)
	}
	return rsu
}

// AddScore adds f to the "score" field.
func (rsu *ReportScorecardUpdate) AddScore(f float32) *ReportScorecardUpdate {
	rsu.mutation.AddScore(f)
	return rsu
}

// SetScorecardVersion sets the "scorecard_version" field.
func (rsu *ReportScorecardUpdate) SetScorecardVersion(s string) *ReportScorecardUpdate {
	rsu.mutation.SetScorecardVersion(s)
	return rsu
}

// SetNillableScorecardVersion sets the "scorecard_version" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableScorecardVersion(s *string) *ReportScorecardUpdate {
	if s != nil {
		rsu.SetScorecardVersion(*s)
	}
	return rsu
}

// SetRepoName sets the "repo_name" field.
func (rsu *ReportScorecardUpdate) SetRepoName(s string) *ReportScorecardUpdate {
	rsu.mutation.SetRepoName(s)
	return rsu
}

// SetNillableRepoName sets the "repo_name" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableRepoName(s *string) *ReportScorecardUpdate {
	if s != nil {
		rsu.SetRepoName(*s)
	}
	return rsu
}

// SetRepoCommit sets the "repo_commit" field.
func (rsu *ReportScorecardUpdate) SetRepoCommit(s string) *ReportScorecardUpdate {
	rsu.mutation.SetRepoCommit(s)
	return rsu
}

// SetNillableRepoCommit sets the "repo_commit" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableRepoCommit(s *string) *ReportScorecardUpdate {
	if s != nil {
		rsu.SetRepoCommit(*s)
	}
	return rsu
}

// SetDate sets the "date" field.
func (rsu *ReportScorecardUpdate) SetDate(s string) *ReportScorecardUpdate {
	rsu.mutation.SetDate(s)
	return rsu
}

// SetNillableDate sets the "date" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableDate(s *string) *ReportScorecardUpdate {
	if s != nil {
		rsu.SetDate(*s)
	}
	return rsu
}

// ClearDate clears the value of the "date" field.
func (rsu *ReportScorecardUpdate) ClearDate() *ReportScorecardUpdate {
	rsu.mutation.ClearDate()
	return rsu
}

// SetCreatedAt sets the "created_at" field.
func (rsu *ReportScorecardUpdate) SetCreatedAt(t time.Time) *ReportScorecardUpdate {
	rsu.mutation.SetCreatedAt(t)
	return rsu
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableCreatedAt(t *time.Time) *ReportScorecardUpdate {
	if t != nil {
		rsu.SetCreatedAt(*t)
	}
	return rsu
}

// ClearCreatedAt clears the value of the "created_at" field.
func (rsu *ReportScorecardUpdate) ClearCreatedAt() *ReportScorecardUpdate {
	rsu.mutation.ClearCreatedAt()
	return rsu
}

// SetUpdatedAt sets the "updated_at" field.
func (rsu *ReportScorecardUpdate) SetUpdatedAt(t time.Time) *ReportScorecardUpdate {
	rsu.mutation.SetUpdatedAt(t)
	return rsu
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableUpdatedAt(t *time.Time) *ReportScorecardUpdate {
	if t != nil {
		rsu.SetUpdatedAt(*t)
	}
	return rsu
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (rsu *ReportScorecardUpdate) ClearUpdatedAt() *ReportScorecardUpdate {
	rsu.mutation.ClearUpdatedAt()
	return rsu
}

// SetProjectID sets the "project" edge to the ReportProject entity by ID.
func (rsu *ReportScorecardUpdate) SetProjectID(id int) *ReportScorecardUpdate {
	rsu.mutation.SetProjectID(id)
	return rsu
}

// SetNillableProjectID sets the "project" edge to the ReportProject entity by ID if the given value is not nil.
func (rsu *ReportScorecardUpdate) SetNillableProjectID(id *int) *ReportScorecardUpdate {
	if id != nil {
		rsu = rsu.SetProjectID(*id)
	}
	return rsu
}

// SetProject sets the "project" edge to the ReportProject entity.
func (rsu *ReportScorecardUpdate) SetProject(r *ReportProject) *ReportScorecardUpdate {
	return rsu.SetProjectID(r.ID)
}

// AddCheckIDs adds the "checks" edge to the ReportScorecardCheck entity by IDs.
func (rsu *ReportScorecardUpdate) AddCheckIDs(ids ...int) *ReportScorecardUpdate {
	rsu.mutation.AddCheckIDs(ids...)
	return rsu
}

// AddChecks adds the "checks" edges to the ReportScorecardCheck entity.
func (rsu *ReportScorecardUpdate) AddChecks(r ...*ReportScorecardCheck) *ReportScorecardUpdate {
	ids := make([]int, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return rsu.AddCheckIDs(ids...)
}

// Mutation returns the ReportScorecardMutation object of the builder.
func (rsu *ReportScorecardUpdate) Mutation() *ReportScorecardMutation {
	return rsu.mutation
}

// ClearProject clears the "project" edge to the ReportProject entity.
func (rsu *ReportScorecardUpdate) ClearProject() *ReportScorecardUpdate {
	rsu.mutation.ClearProject()
	return rsu
}

// ClearChecks clears all "checks" edges to the ReportScorecardCheck entity.
func (rsu *ReportScorecardUpdate) ClearChecks() *ReportScorecardUpdate {
	rsu.mutation.ClearChecks()
	return rsu
}

// RemoveCheckIDs removes the "checks" edge to ReportScorecardCheck entities by IDs.
func (rsu *ReportScorecardUpdate) RemoveCheckIDs(ids ...int) *ReportScorecardUpdate {
	rsu.mutation.RemoveCheckIDs(ids...)
	return rsu
}

// RemoveChecks removes "checks" edges to ReportScorecardCheck entities.
func (rsu *ReportScorecardUpdate) RemoveChecks(r ...*ReportScorecardCheck) *ReportScorecardUpdate {
	ids := make([]int, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return rsu.RemoveCheckIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (rsu *ReportScorecardUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, rsu.sqlSave, rsu.mutation, rsu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (rsu *ReportScorecardUpdate) SaveX(ctx context.Context) int {
	affected, err := rsu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (rsu *ReportScorecardUpdate) Exec(ctx context.Context) error {
	_, err := rsu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rsu *ReportScorecardUpdate) ExecX(ctx context.Context) {
	if err := rsu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (rsu *ReportScorecardUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(reportscorecard.Table, reportscorecard.Columns, sqlgraph.NewFieldSpec(reportscorecard.FieldID, field.TypeInt))
	if ps := rsu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := rsu.mutation.Score(); ok {
		_spec.SetField(reportscorecard.FieldScore, field.TypeFloat32, value)
	}
	if value, ok := rsu.mutation.AddedScore(); ok {
		_spec.AddField(reportscorecard.FieldScore, field.TypeFloat32, value)
	}
	if value, ok := rsu.mutation.ScorecardVersion(); ok {
		_spec.SetField(reportscorecard.FieldScorecardVersion, field.TypeString, value)
	}
	if value, ok := rsu.mutation.RepoName(); ok {
		_spec.SetField(reportscorecard.FieldRepoName, field.TypeString, value)
	}
	if value, ok := rsu.mutation.RepoCommit(); ok {
		_spec.SetField(reportscorecard.FieldRepoCommit, field.TypeString, value)
	}
	if value, ok := rsu.mutation.Date(); ok {
		_spec.SetField(reportscorecard.FieldDate, field.TypeString, value)
	}
	if rsu.mutation.DateCleared() {
		_spec.ClearField(reportscorecard.FieldDate, field.TypeString)
	}
	if value, ok := rsu.mutation.CreatedAt(); ok {
		_spec.SetField(reportscorecard.FieldCreatedAt, field.TypeTime, value)
	}
	if rsu.mutation.CreatedAtCleared() {
		_spec.ClearField(reportscorecard.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := rsu.mutation.UpdatedAt(); ok {
		_spec.SetField(reportscorecard.FieldUpdatedAt, field.TypeTime, value)
	}
	if rsu.mutation.UpdatedAtCleared() {
		_spec.ClearField(reportscorecard.FieldUpdatedAt, field.TypeTime)
	}
	if rsu.mutation.ProjectCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   reportscorecard.ProjectTable,
			Columns: []string{reportscorecard.ProjectColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportproject.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsu.mutation.ProjectIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   reportscorecard.ProjectTable,
			Columns: []string{reportscorecard.ProjectColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportproject.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if rsu.mutation.ChecksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsu.mutation.RemovedChecksIDs(); len(nodes) > 0 && !rsu.mutation.ChecksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsu.mutation.ChecksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, rsu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{reportscorecard.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	rsu.mutation.done = true
	return n, nil
}

// ReportScorecardUpdateOne is the builder for updating a single ReportScorecard entity.
type ReportScorecardUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ReportScorecardMutation
}

// SetScore sets the "score" field.
func (rsuo *ReportScorecardUpdateOne) SetScore(f float32) *ReportScorecardUpdateOne {
	rsuo.mutation.ResetScore()
	rsuo.mutation.SetScore(f)
	return rsuo
}

// SetNillableScore sets the "score" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableScore(f *float32) *ReportScorecardUpdateOne {
	if f != nil {
		rsuo.SetScore(*f)
	}
	return rsuo
}

// AddScore adds f to the "score" field.
func (rsuo *ReportScorecardUpdateOne) AddScore(f float32) *ReportScorecardUpdateOne {
	rsuo.mutation.AddScore(f)
	return rsuo
}

// SetScorecardVersion sets the "scorecard_version" field.
func (rsuo *ReportScorecardUpdateOne) SetScorecardVersion(s string) *ReportScorecardUpdateOne {
	rsuo.mutation.SetScorecardVersion(s)
	return rsuo
}

// SetNillableScorecardVersion sets the "scorecard_version" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableScorecardVersion(s *string) *ReportScorecardUpdateOne {
	if s != nil {
		rsuo.SetScorecardVersion(*s)
	}
	return rsuo
}

// SetRepoName sets the "repo_name" field.
func (rsuo *ReportScorecardUpdateOne) SetRepoName(s string) *ReportScorecardUpdateOne {
	rsuo.mutation.SetRepoName(s)
	return rsuo
}

// SetNillableRepoName sets the "repo_name" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableRepoName(s *string) *ReportScorecardUpdateOne {
	if s != nil {
		rsuo.SetRepoName(*s)
	}
	return rsuo
}

// SetRepoCommit sets the "repo_commit" field.
func (rsuo *ReportScorecardUpdateOne) SetRepoCommit(s string) *ReportScorecardUpdateOne {
	rsuo.mutation.SetRepoCommit(s)
	return rsuo
}

// SetNillableRepoCommit sets the "repo_commit" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableRepoCommit(s *string) *ReportScorecardUpdateOne {
	if s != nil {
		rsuo.SetRepoCommit(*s)
	}
	return rsuo
}

// SetDate sets the "date" field.
func (rsuo *ReportScorecardUpdateOne) SetDate(s string) *ReportScorecardUpdateOne {
	rsuo.mutation.SetDate(s)
	return rsuo
}

// SetNillableDate sets the "date" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableDate(s *string) *ReportScorecardUpdateOne {
	if s != nil {
		rsuo.SetDate(*s)
	}
	return rsuo
}

// ClearDate clears the value of the "date" field.
func (rsuo *ReportScorecardUpdateOne) ClearDate() *ReportScorecardUpdateOne {
	rsuo.mutation.ClearDate()
	return rsuo
}

// SetCreatedAt sets the "created_at" field.
func (rsuo *ReportScorecardUpdateOne) SetCreatedAt(t time.Time) *ReportScorecardUpdateOne {
	rsuo.mutation.SetCreatedAt(t)
	return rsuo
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableCreatedAt(t *time.Time) *ReportScorecardUpdateOne {
	if t != nil {
		rsuo.SetCreatedAt(*t)
	}
	return rsuo
}

// ClearCreatedAt clears the value of the "created_at" field.
func (rsuo *ReportScorecardUpdateOne) ClearCreatedAt() *ReportScorecardUpdateOne {
	rsuo.mutation.ClearCreatedAt()
	return rsuo
}

// SetUpdatedAt sets the "updated_at" field.
func (rsuo *ReportScorecardUpdateOne) SetUpdatedAt(t time.Time) *ReportScorecardUpdateOne {
	rsuo.mutation.SetUpdatedAt(t)
	return rsuo
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableUpdatedAt(t *time.Time) *ReportScorecardUpdateOne {
	if t != nil {
		rsuo.SetUpdatedAt(*t)
	}
	return rsuo
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (rsuo *ReportScorecardUpdateOne) ClearUpdatedAt() *ReportScorecardUpdateOne {
	rsuo.mutation.ClearUpdatedAt()
	return rsuo
}

// SetProjectID sets the "project" edge to the ReportProject entity by ID.
func (rsuo *ReportScorecardUpdateOne) SetProjectID(id int) *ReportScorecardUpdateOne {
	rsuo.mutation.SetProjectID(id)
	return rsuo
}

// SetNillableProjectID sets the "project" edge to the ReportProject entity by ID if the given value is not nil.
func (rsuo *ReportScorecardUpdateOne) SetNillableProjectID(id *int) *ReportScorecardUpdateOne {
	if id != nil {
		rsuo = rsuo.SetProjectID(*id)
	}
	return rsuo
}

// SetProject sets the "project" edge to the ReportProject entity.
func (rsuo *ReportScorecardUpdateOne) SetProject(r *ReportProject) *ReportScorecardUpdateOne {
	return rsuo.SetProjectID(r.ID)
}

// AddCheckIDs adds the "checks" edge to the ReportScorecardCheck entity by IDs.
func (rsuo *ReportScorecardUpdateOne) AddCheckIDs(ids ...int) *ReportScorecardUpdateOne {
	rsuo.mutation.AddCheckIDs(ids...)
	return rsuo
}

// AddChecks adds the "checks" edges to the ReportScorecardCheck entity.
func (rsuo *ReportScorecardUpdateOne) AddChecks(r ...*ReportScorecardCheck) *ReportScorecardUpdateOne {
	ids := make([]int, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return rsuo.AddCheckIDs(ids...)
}

// Mutation returns the ReportScorecardMutation object of the builder.
func (rsuo *ReportScorecardUpdateOne) Mutation() *ReportScorecardMutation {
	return rsuo.mutation
}

// ClearProject clears the "project" edge to the ReportProject entity.
func (rsuo *ReportScorecardUpdateOne) ClearProject() *ReportScorecardUpdateOne {
	rsuo.mutation.ClearProject()
	return rsuo
}

// ClearChecks clears all "checks" edges to the ReportScorecardCheck entity.
func (rsuo *ReportScorecardUpdateOne) ClearChecks() *ReportScorecardUpdateOne {
	rsuo.mutation.ClearChecks()
	return rsuo
}

// RemoveCheckIDs removes the "checks" edge to ReportScorecardCheck entities by IDs.
func (rsuo *ReportScorecardUpdateOne) RemoveCheckIDs(ids ...int) *ReportScorecardUpdateOne {
	rsuo.mutation.RemoveCheckIDs(ids...)
	return rsuo
}

// RemoveChecks removes "checks" edges to ReportScorecardCheck entities.
func (rsuo *ReportScorecardUpdateOne) RemoveChecks(r ...*ReportScorecardCheck) *ReportScorecardUpdateOne {
	ids := make([]int, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return rsuo.RemoveCheckIDs(ids...)
}

// Where appends a list predicates to the ReportScorecardUpdate builder.
func (rsuo *ReportScorecardUpdateOne) Where(ps ...predicate.ReportScorecard) *ReportScorecardUpdateOne {
	rsuo.mutation.Where(ps...)
	return rsuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (rsuo *ReportScorecardUpdateOne) Select(field string, fields ...string) *ReportScorecardUpdateOne {
	rsuo.fields = append([]string{field}, fields...)
	return rsuo
}

// Save executes the query and returns the updated ReportScorecard entity.
func (rsuo *ReportScorecardUpdateOne) Save(ctx context.Context) (*ReportScorecard, error) {
	return withHooks(ctx, rsuo.sqlSave, rsuo.mutation, rsuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (rsuo *ReportScorecardUpdateOne) SaveX(ctx context.Context) *ReportScorecard {
	node, err := rsuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (rsuo *ReportScorecardUpdateOne) Exec(ctx context.Context) error {
	_, err := rsuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rsuo *ReportScorecardUpdateOne) ExecX(ctx context.Context) {
	if err := rsuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (rsuo *ReportScorecardUpdateOne) sqlSave(ctx context.Context) (_node *ReportScorecard, err error) {
	_spec := sqlgraph.NewUpdateSpec(reportscorecard.Table, reportscorecard.Columns, sqlgraph.NewFieldSpec(reportscorecard.FieldID, field.TypeInt))
	id, ok := rsuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "ReportScorecard.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := rsuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, reportscorecard.FieldID)
		for _, f := range fields {
			if !reportscorecard.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != reportscorecard.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := rsuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := rsuo.mutation.Score(); ok {
		_spec.SetField(reportscorecard.FieldScore, field.TypeFloat32, value)
	}
	if value, ok := rsuo.mutation.AddedScore(); ok {
		_spec.AddField(reportscorecard.FieldScore, field.TypeFloat32, value)
	}
	if value, ok := rsuo.mutation.ScorecardVersion(); ok {
		_spec.SetField(reportscorecard.FieldScorecardVersion, field.TypeString, value)
	}
	if value, ok := rsuo.mutation.RepoName(); ok {
		_spec.SetField(reportscorecard.FieldRepoName, field.TypeString, value)
	}
	if value, ok := rsuo.mutation.RepoCommit(); ok {
		_spec.SetField(reportscorecard.FieldRepoCommit, field.TypeString, value)
	}
	if value, ok := rsuo.mutation.Date(); ok {
		_spec.SetField(reportscorecard.FieldDate, field.TypeString, value)
	}
	if rsuo.mutation.DateCleared() {
		_spec.ClearField(reportscorecard.FieldDate, field.TypeString)
	}
	if value, ok := rsuo.mutation.CreatedAt(); ok {
		_spec.SetField(reportscorecard.FieldCreatedAt, field.TypeTime, value)
	}
	if rsuo.mutation.CreatedAtCleared() {
		_spec.ClearField(reportscorecard.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := rsuo.mutation.UpdatedAt(); ok {
		_spec.SetField(reportscorecard.FieldUpdatedAt, field.TypeTime, value)
	}
	if rsuo.mutation.UpdatedAtCleared() {
		_spec.ClearField(reportscorecard.FieldUpdatedAt, field.TypeTime)
	}
	if rsuo.mutation.ProjectCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   reportscorecard.ProjectTable,
			Columns: []string{reportscorecard.ProjectColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportproject.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsuo.mutation.ProjectIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   reportscorecard.ProjectTable,
			Columns: []string{reportscorecard.ProjectColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportproject.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if rsuo.mutation.ChecksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsuo.mutation.RemovedChecksIDs(); len(nodes) > 0 && !rsuo.mutation.ChecksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rsuo.mutation.ChecksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   reportscorecard.ChecksTable,
			Columns: []string{reportscorecard.ChecksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &ReportScorecard{config: rsuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, rsuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{reportscorecard.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	rsuo.mutation.done = true
	return _node, nil
}
