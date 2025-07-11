// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/predicate"
	"github.com/safedep/vet/ent/reportscorecardcheck"
)

// ReportScorecardCheckDelete is the builder for deleting a ReportScorecardCheck entity.
type ReportScorecardCheckDelete struct {
	config
	hooks    []Hook
	mutation *ReportScorecardCheckMutation
}

// Where appends a list predicates to the ReportScorecardCheckDelete builder.
func (rscd *ReportScorecardCheckDelete) Where(ps ...predicate.ReportScorecardCheck) *ReportScorecardCheckDelete {
	rscd.mutation.Where(ps...)
	return rscd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (rscd *ReportScorecardCheckDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, rscd.sqlExec, rscd.mutation, rscd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (rscd *ReportScorecardCheckDelete) ExecX(ctx context.Context) int {
	n, err := rscd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (rscd *ReportScorecardCheckDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(reportscorecardcheck.Table, sqlgraph.NewFieldSpec(reportscorecardcheck.FieldID, field.TypeInt))
	if ps := rscd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, rscd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	rscd.mutation.done = true
	return affected, err
}

// ReportScorecardCheckDeleteOne is the builder for deleting a single ReportScorecardCheck entity.
type ReportScorecardCheckDeleteOne struct {
	rscd *ReportScorecardCheckDelete
}

// Where appends a list predicates to the ReportScorecardCheckDelete builder.
func (rscdo *ReportScorecardCheckDeleteOne) Where(ps ...predicate.ReportScorecardCheck) *ReportScorecardCheckDeleteOne {
	rscdo.rscd.mutation.Where(ps...)
	return rscdo
}

// Exec executes the deletion query.
func (rscdo *ReportScorecardCheckDeleteOne) Exec(ctx context.Context) error {
	n, err := rscdo.rscd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{reportscorecardcheck.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (rscdo *ReportScorecardCheckDeleteOne) ExecX(ctx context.Context) {
	if err := rscdo.Exec(ctx); err != nil {
		panic(err)
	}
}
