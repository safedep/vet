// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/reportscorecard"
	"github.com/safedep/vet/ent/reportscorecardcheck"
)

// ReportScorecardCheckCreate is the builder for creating a ReportScorecardCheck entity.
type ReportScorecardCheckCreate struct {
	config
	mutation *ReportScorecardCheckMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (rscc *ReportScorecardCheckCreate) SetName(s string) *ReportScorecardCheckCreate {
	rscc.mutation.SetName(s)
	return rscc
}

// SetScore sets the "score" field.
func (rscc *ReportScorecardCheckCreate) SetScore(f float32) *ReportScorecardCheckCreate {
	rscc.mutation.SetScore(f)
	return rscc
}

// SetReason sets the "reason" field.
func (rscc *ReportScorecardCheckCreate) SetReason(s string) *ReportScorecardCheckCreate {
	rscc.mutation.SetReason(s)
	return rscc
}

// SetNillableReason sets the "reason" field if the given value is not nil.
func (rscc *ReportScorecardCheckCreate) SetNillableReason(s *string) *ReportScorecardCheckCreate {
	if s != nil {
		rscc.SetReason(*s)
	}
	return rscc
}

// SetCreatedAt sets the "created_at" field.
func (rscc *ReportScorecardCheckCreate) SetCreatedAt(t time.Time) *ReportScorecardCheckCreate {
	rscc.mutation.SetCreatedAt(t)
	return rscc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rscc *ReportScorecardCheckCreate) SetNillableCreatedAt(t *time.Time) *ReportScorecardCheckCreate {
	if t != nil {
		rscc.SetCreatedAt(*t)
	}
	return rscc
}

// SetUpdatedAt sets the "updated_at" field.
func (rscc *ReportScorecardCheckCreate) SetUpdatedAt(t time.Time) *ReportScorecardCheckCreate {
	rscc.mutation.SetUpdatedAt(t)
	return rscc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (rscc *ReportScorecardCheckCreate) SetNillableUpdatedAt(t *time.Time) *ReportScorecardCheckCreate {
	if t != nil {
		rscc.SetUpdatedAt(*t)
	}
	return rscc
}

// SetScorecardID sets the "scorecard" edge to the ReportScorecard entity by ID.
func (rscc *ReportScorecardCheckCreate) SetScorecardID(id int) *ReportScorecardCheckCreate {
	rscc.mutation.SetScorecardID(id)
	return rscc
}

// SetNillableScorecardID sets the "scorecard" edge to the ReportScorecard entity by ID if the given value is not nil.
func (rscc *ReportScorecardCheckCreate) SetNillableScorecardID(id *int) *ReportScorecardCheckCreate {
	if id != nil {
		rscc = rscc.SetScorecardID(*id)
	}
	return rscc
}

// SetScorecard sets the "scorecard" edge to the ReportScorecard entity.
func (rscc *ReportScorecardCheckCreate) SetScorecard(r *ReportScorecard) *ReportScorecardCheckCreate {
	return rscc.SetScorecardID(r.ID)
}

// Mutation returns the ReportScorecardCheckMutation object of the builder.
func (rscc *ReportScorecardCheckCreate) Mutation() *ReportScorecardCheckMutation {
	return rscc.mutation
}

// Save creates the ReportScorecardCheck in the database.
func (rscc *ReportScorecardCheckCreate) Save(ctx context.Context) (*ReportScorecardCheck, error) {
	return withHooks(ctx, rscc.sqlSave, rscc.mutation, rscc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (rscc *ReportScorecardCheckCreate) SaveX(ctx context.Context) *ReportScorecardCheck {
	v, err := rscc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rscc *ReportScorecardCheckCreate) Exec(ctx context.Context) error {
	_, err := rscc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rscc *ReportScorecardCheckCreate) ExecX(ctx context.Context) {
	if err := rscc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rscc *ReportScorecardCheckCreate) check() error {
	if _, ok := rscc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "ReportScorecardCheck.name"`)}
	}
	if _, ok := rscc.mutation.Score(); !ok {
		return &ValidationError{Name: "score", err: errors.New(`ent: missing required field "ReportScorecardCheck.score"`)}
	}
	return nil
}

func (rscc *ReportScorecardCheckCreate) sqlSave(ctx context.Context) (*ReportScorecardCheck, error) {
	if err := rscc.check(); err != nil {
		return nil, err
	}
	_node, _spec := rscc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rscc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	rscc.mutation.id = &_node.ID
	rscc.mutation.done = true
	return _node, nil
}

func (rscc *ReportScorecardCheckCreate) createSpec() (*ReportScorecardCheck, *sqlgraph.CreateSpec) {
	var (
		_node = &ReportScorecardCheck{config: rscc.config}
		_spec = sqlgraph.NewCreateSpec(reportscorecardcheck.Table, sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt))
	)
	if value, ok := rscc.mutation.Name(); ok {
		_spec.SetField(reportscorecardcheck.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := rscc.mutation.Score(); ok {
		_spec.SetField(reportscorecardcheck.FieldScore, field.TypeFloat32, value)
		_node.Score = value
	}
	if value, ok := rscc.mutation.Reason(); ok {
		_spec.SetField(reportscorecardcheck.FieldReason, field.TypeString, value)
		_node.Reason = value
	}
	if value, ok := rscc.mutation.CreatedAt(); ok {
		_spec.SetField(reportscorecardcheck.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := rscc.mutation.UpdatedAt(); ok {
		_spec.SetField(reportscorecardcheck.FieldUpdatedAt, field.TypeTime, value)
		_node.UpdatedAt = value
	}
	if nodes := rscc.mutation.ScorecardIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   reportscorecardcheck.ScorecardTable,
			Columns: []string{reportscorecardcheck.ScorecardColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(reportscorecard.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.report_scorecard_checks = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ReportScorecardCheckCreateBulk is the builder for creating many ReportScorecardCheck entities in bulk.
type ReportScorecardCheckCreateBulk struct {
	config
	err      error
	builders []*ReportScorecardCheckCreate
}

// Save creates the ReportScorecardCheck entities in the database.
func (rsccb *ReportScorecardCheckCreateBulk) Save(ctx context.Context) ([]*ReportScorecardCheck, error) {
	if rsccb.err != nil {
		return nil, rsccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(rsccb.builders))
	nodes := make([]*ReportScorecardCheck, len(rsccb.builders))
	mutators := make([]Mutator, len(rsccb.builders))
	for i := range rsccb.builders {
		func(i int, root context.Context) {
			builder := rsccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ReportScorecardCheckMutation)
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
					_, err = mutators[i+1].Mutate(root, rsccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rsccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, rsccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rsccb *ReportScorecardCheckCreateBulk) SaveX(ctx context.Context) []*ReportScorecardCheck {
	v, err := rsccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rsccb *ReportScorecardCheckCreateBulk) Exec(ctx context.Context) error {
	_, err := rsccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rsccb *ReportScorecardCheckCreateBulk) ExecX(ctx context.Context) {
	if err := rsccb.Exec(ctx); err != nil {
		panic(err)
	}
}
