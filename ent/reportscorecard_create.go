// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/reportproject"
	"github.com/safedep/vet/ent/reportscorecard"
	"github.com/safedep/vet/ent/reportscorecardcheck"
)

// ReportScorecardCreate is the builder for creating a ReportScorecard entity.
type ReportScorecardCreate struct {
	config
	mutation *ReportScorecardMutation
	hooks    []Hook
}

// SetScore sets the "score" field.
func (rsc *ReportScorecardCreate) SetScore(f float32) *ReportScorecardCreate {
	rsc.mutation.SetScore(f)
	return rsc
}

// SetScorecardVersion sets the "scorecard_version" field.
func (rsc *ReportScorecardCreate) SetScorecardVersion(s string) *ReportScorecardCreate {
	rsc.mutation.SetScorecardVersion(s)
	return rsc
}

// SetRepoName sets the "repo_name" field.
func (rsc *ReportScorecardCreate) SetRepoName(s string) *ReportScorecardCreate {
	rsc.mutation.SetRepoName(s)
	return rsc
}

// SetRepoCommit sets the "repo_commit" field.
func (rsc *ReportScorecardCreate) SetRepoCommit(s string) *ReportScorecardCreate {
	rsc.mutation.SetRepoCommit(s)
	return rsc
}

// SetDate sets the "date" field.
func (rsc *ReportScorecardCreate) SetDate(s string) *ReportScorecardCreate {
	rsc.mutation.SetDate(s)
	return rsc
}

// SetNillableDate sets the "date" field if the given value is not nil.
func (rsc *ReportScorecardCreate) SetNillableDate(s *string) *ReportScorecardCreate {
	if s != nil {
		rsc.SetDate(*s)
	}
	return rsc
}

// SetCreatedAt sets the "created_at" field.
func (rsc *ReportScorecardCreate) SetCreatedAt(t time.Time) *ReportScorecardCreate {
	rsc.mutation.SetCreatedAt(t)
	return rsc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rsc *ReportScorecardCreate) SetNillableCreatedAt(t *time.Time) *ReportScorecardCreate {
	if t != nil {
		rsc.SetCreatedAt(*t)
	}
	return rsc
}

// SetUpdatedAt sets the "updated_at" field.
func (rsc *ReportScorecardCreate) SetUpdatedAt(t time.Time) *ReportScorecardCreate {
	rsc.mutation.SetUpdatedAt(t)
	return rsc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (rsc *ReportScorecardCreate) SetNillableUpdatedAt(t *time.Time) *ReportScorecardCreate {
	if t != nil {
		rsc.SetUpdatedAt(*t)
	}
	return rsc
}

// SetProjectID sets the "project" edge to the ReportProject entity by ID.
func (rsc *ReportScorecardCreate) SetProjectID(id int) *ReportScorecardCreate {
	rsc.mutation.SetProjectID(id)
	return rsc
}

// SetNillableProjectID sets the "project" edge to the ReportProject entity by ID if the given value is not nil.
func (rsc *ReportScorecardCreate) SetNillableProjectID(id *int) *ReportScorecardCreate {
	if id != nil {
		rsc = rsc.SetProjectID(*id)
	}
	return rsc
}

// SetProject sets the "project" edge to the ReportProject entity.
func (rsc *ReportScorecardCreate) SetProject(r *ReportProject) *ReportScorecardCreate {
	return rsc.SetProjectID(r.ID)
}

// AddCheckIDs adds the "checks" edge to the ReportScorecardCheck entity by IDs.
func (rsc *ReportScorecardCreate) AddCheckIDs(ids ...int) *ReportScorecardCreate {
	rsc.mutation.AddCheckIDs(ids...)
	return rsc
}

// AddChecks adds the "checks" edges to the ReportScorecardCheck entity.
func (rsc *ReportScorecardCreate) AddChecks(r ...*ReportScorecardCheck) *ReportScorecardCreate {
	ids := make([]int, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return rsc.AddCheckIDs(ids...)
}

// Mutation returns the ReportScorecardMutation object of the builder.
func (rsc *ReportScorecardCreate) Mutation() *ReportScorecardMutation {
	return rsc.mutation
}

// Save creates the ReportScorecard in the database.
func (rsc *ReportScorecardCreate) Save(ctx context.Context) (*ReportScorecard, error) {
	return withHooks(ctx, rsc.sqlSave, rsc.mutation, rsc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (rsc *ReportScorecardCreate) SaveX(ctx context.Context) *ReportScorecard {
	v, err := rsc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rsc *ReportScorecardCreate) Exec(ctx context.Context) error {
	_, err := rsc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rsc *ReportScorecardCreate) ExecX(ctx context.Context) {
	if err := rsc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rsc *ReportScorecardCreate) check() error {
	if _, ok := rsc.mutation.Score(); !ok {
		return &ValidationError{Name: "score", err: errors.New(`ent: missing required field "ReportScorecard.score"`)}
	}
	if _, ok := rsc.mutation.ScorecardVersion(); !ok {
		return &ValidationError{Name: "scorecard_version", err: errors.New(`ent: missing required field "ReportScorecard.scorecard_version"`)}
	}
	if _, ok := rsc.mutation.RepoName(); !ok {
		return &ValidationError{Name: "repo_name", err: errors.New(`ent: missing required field "ReportScorecard.repo_name"`)}
	}
	if _, ok := rsc.mutation.RepoCommit(); !ok {
		return &ValidationError{Name: "repo_commit", err: errors.New(`ent: missing required field "ReportScorecard.repo_commit"`)}
	}
	return nil
}

func (rsc *ReportScorecardCreate) sqlSave(ctx context.Context) (*ReportScorecard, error) {
	if err := rsc.check(); err != nil {
		return nil, err
	}
	_node, _spec := rsc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rsc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	rsc.mutation.id = &_node.ID
	rsc.mutation.done = true
	return _node, nil
}

func (rsc *ReportScorecardCreate) createSpec() (*ReportScorecard, *sqlgraph.CreateSpec) {
	var (
		_node = &ReportScorecard{config: rsc.config}
		_spec = sqlgraph.NewCreateSpec(reportscorecard.Table, sqlgraph.NewFieldSpec(reportscorecard.FieldID, field.TypeInt))
	)
	if value, ok := rsc.mutation.Score(); ok {
		_spec.SetField(reportscorecard.FieldScore, field.TypeFloat32, value)
		_node.Score = value
	}
	if value, ok := rsc.mutation.ScorecardVersion(); ok {
		_spec.SetField(reportscorecard.FieldScorecardVersion, field.TypeString, value)
		_node.ScorecardVersion = value
	}
	if value, ok := rsc.mutation.RepoName(); ok {
		_spec.SetField(reportscorecard.FieldRepoName, field.TypeString, value)
		_node.RepoName = value
	}
	if value, ok := rsc.mutation.RepoCommit(); ok {
		_spec.SetField(reportscorecard.FieldRepoCommit, field.TypeString, value)
		_node.RepoCommit = value
	}
	if value, ok := rsc.mutation.Date(); ok {
		_spec.SetField(reportscorecard.FieldDate, field.TypeString, value)
		_node.Date = value
	}
	if value, ok := rsc.mutation.CreatedAt(); ok {
		_spec.SetField(reportscorecard.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := rsc.mutation.UpdatedAt(); ok {
		_spec.SetField(reportscorecard.FieldUpdatedAt, field.TypeTime, value)
		_node.UpdatedAt = value
	}
	if nodes := rsc.mutation.ProjectIDs(); len(nodes) > 0 {
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
		_node.report_project_scorecard = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := rsc.mutation.ChecksIDs(); len(nodes) > 0 {
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ReportScorecardCreateBulk is the builder for creating many ReportScorecard entities in bulk.
type ReportScorecardCreateBulk struct {
	config
	err      error
	builders []*ReportScorecardCreate
}

// Save creates the ReportScorecard entities in the database.
func (rscb *ReportScorecardCreateBulk) Save(ctx context.Context) ([]*ReportScorecard, error) {
	if rscb.err != nil {
		return nil, rscb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(rscb.builders))
	nodes := make([]*ReportScorecard, len(rscb.builders))
	mutators := make([]Mutator, len(rscb.builders))
	for i := range rscb.builders {
		func(i int, root context.Context) {
			builder := rscb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ReportScorecardMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, rscb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rscb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, rscb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rscb *ReportScorecardCreateBulk) SaveX(ctx context.Context) []*ReportScorecard {
	v, err := rscb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rscb *ReportScorecardCreateBulk) Exec(ctx context.Context) error {
	_, err := rscb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rscb *ReportScorecardCreateBulk) ExecX(ctx context.Context) {
	if err := rscb.Exec(ctx); err != nil {
		panic(err)
	}
}
