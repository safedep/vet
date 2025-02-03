// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/safedep/vet/ent/codesourcefile"
	"github.com/safedep/vet/ent/depsusageevidence"
)

// DepsUsageEvidenceCreate is the builder for creating a DepsUsageEvidence entity.
type DepsUsageEvidenceCreate struct {
	config
	mutation *DepsUsageEvidenceMutation
	hooks    []Hook
}

// SetPackageHint sets the "package_hint" field.
func (duec *DepsUsageEvidenceCreate) SetPackageHint(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetPackageHint(s)
	return duec
}

// SetNillablePackageHint sets the "package_hint" field if the given value is not nil.
func (duec *DepsUsageEvidenceCreate) SetNillablePackageHint(s *string) *DepsUsageEvidenceCreate {
	if s != nil {
		duec.SetPackageHint(*s)
	}
	return duec
}

// SetModuleName sets the "module_name" field.
func (duec *DepsUsageEvidenceCreate) SetModuleName(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetModuleName(s)
	return duec
}

// SetModuleItem sets the "module_item" field.
func (duec *DepsUsageEvidenceCreate) SetModuleItem(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetModuleItem(s)
	return duec
}

// SetNillableModuleItem sets the "module_item" field if the given value is not nil.
func (duec *DepsUsageEvidenceCreate) SetNillableModuleItem(s *string) *DepsUsageEvidenceCreate {
	if s != nil {
		duec.SetModuleItem(*s)
	}
	return duec
}

// SetModuleAlias sets the "module_alias" field.
func (duec *DepsUsageEvidenceCreate) SetModuleAlias(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetModuleAlias(s)
	return duec
}

// SetNillableModuleAlias sets the "module_alias" field if the given value is not nil.
func (duec *DepsUsageEvidenceCreate) SetNillableModuleAlias(s *string) *DepsUsageEvidenceCreate {
	if s != nil {
		duec.SetModuleAlias(*s)
	}
	return duec
}

// SetIsWildCardUsage sets the "is_wild_card_usage" field.
func (duec *DepsUsageEvidenceCreate) SetIsWildCardUsage(b bool) *DepsUsageEvidenceCreate {
	duec.mutation.SetIsWildCardUsage(b)
	return duec
}

// SetNillableIsWildCardUsage sets the "is_wild_card_usage" field if the given value is not nil.
func (duec *DepsUsageEvidenceCreate) SetNillableIsWildCardUsage(b *bool) *DepsUsageEvidenceCreate {
	if b != nil {
		duec.SetIsWildCardUsage(*b)
	}
	return duec
}

// SetIdentifier sets the "identifier" field.
func (duec *DepsUsageEvidenceCreate) SetIdentifier(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetIdentifier(s)
	return duec
}

// SetNillableIdentifier sets the "identifier" field if the given value is not nil.
func (duec *DepsUsageEvidenceCreate) SetNillableIdentifier(s *string) *DepsUsageEvidenceCreate {
	if s != nil {
		duec.SetIdentifier(*s)
	}
	return duec
}

// SetUsageFilePath sets the "usage_file_path" field.
func (duec *DepsUsageEvidenceCreate) SetUsageFilePath(s string) *DepsUsageEvidenceCreate {
	duec.mutation.SetUsageFilePath(s)
	return duec
}

// SetLine sets the "line" field.
func (duec *DepsUsageEvidenceCreate) SetLine(u uint) *DepsUsageEvidenceCreate {
	duec.mutation.SetLine(u)
	return duec
}

// SetUsedInID sets the "used_in" edge to the CodeSourceFile entity by ID.
func (duec *DepsUsageEvidenceCreate) SetUsedInID(id int) *DepsUsageEvidenceCreate {
	duec.mutation.SetUsedInID(id)
	return duec
}

// SetUsedIn sets the "used_in" edge to the CodeSourceFile entity.
func (duec *DepsUsageEvidenceCreate) SetUsedIn(c *CodeSourceFile) *DepsUsageEvidenceCreate {
	return duec.SetUsedInID(c.ID)
}

// Mutation returns the DepsUsageEvidenceMutation object of the builder.
func (duec *DepsUsageEvidenceCreate) Mutation() *DepsUsageEvidenceMutation {
	return duec.mutation
}

// Save creates the DepsUsageEvidence in the database.
func (duec *DepsUsageEvidenceCreate) Save(ctx context.Context) (*DepsUsageEvidence, error) {
	duec.defaults()
	return withHooks(ctx, duec.sqlSave, duec.mutation, duec.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (duec *DepsUsageEvidenceCreate) SaveX(ctx context.Context) *DepsUsageEvidence {
	v, err := duec.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (duec *DepsUsageEvidenceCreate) Exec(ctx context.Context) error {
	_, err := duec.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duec *DepsUsageEvidenceCreate) ExecX(ctx context.Context) {
	if err := duec.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (duec *DepsUsageEvidenceCreate) defaults() {
	if _, ok := duec.mutation.IsWildCardUsage(); !ok {
		v := depsusageevidence.DefaultIsWildCardUsage
		duec.mutation.SetIsWildCardUsage(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (duec *DepsUsageEvidenceCreate) check() error {
	if _, ok := duec.mutation.ModuleName(); !ok {
		return &ValidationError{Name: "module_name", err: errors.New(`ent: missing required field "DepsUsageEvidence.module_name"`)}
	}
	if _, ok := duec.mutation.UsageFilePath(); !ok {
		return &ValidationError{Name: "usage_file_path", err: errors.New(`ent: missing required field "DepsUsageEvidence.usage_file_path"`)}
	}
	if _, ok := duec.mutation.Line(); !ok {
		return &ValidationError{Name: "line", err: errors.New(`ent: missing required field "DepsUsageEvidence.line"`)}
	}
	if len(duec.mutation.UsedInIDs()) == 0 {
		return &ValidationError{Name: "used_in", err: errors.New(`ent: missing required edge "DepsUsageEvidence.used_in"`)}
	}
	return nil
}

func (duec *DepsUsageEvidenceCreate) sqlSave(ctx context.Context) (*DepsUsageEvidence, error) {
	if err := duec.check(); err != nil {
		return nil, err
	}
	_node, _spec := duec.createSpec()
	if err := sqlgraph.CreateNode(ctx, duec.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	duec.mutation.id = &_node.ID
	duec.mutation.done = true
	return _node, nil
}

func (duec *DepsUsageEvidenceCreate) createSpec() (*DepsUsageEvidence, *sqlgraph.CreateSpec) {
	var (
		_node = &DepsUsageEvidence{config: duec.config}
		_spec = sqlgraph.NewCreateSpec(depsusageevidence.Table, sqlgraph.NewFieldSpec(depsusageevidence.FieldID, field.TypeInt))
	)
	if value, ok := duec.mutation.PackageHint(); ok {
		_spec.SetField(depsusageevidence.FieldPackageHint, field.TypeString, value)
		_node.PackageHint = &value
	}
	if value, ok := duec.mutation.ModuleName(); ok {
		_spec.SetField(depsusageevidence.FieldModuleName, field.TypeString, value)
		_node.ModuleName = value
	}
	if value, ok := duec.mutation.ModuleItem(); ok {
		_spec.SetField(depsusageevidence.FieldModuleItem, field.TypeString, value)
		_node.ModuleItem = &value
	}
	if value, ok := duec.mutation.ModuleAlias(); ok {
		_spec.SetField(depsusageevidence.FieldModuleAlias, field.TypeString, value)
		_node.ModuleAlias = &value
	}
	if value, ok := duec.mutation.IsWildCardUsage(); ok {
		_spec.SetField(depsusageevidence.FieldIsWildCardUsage, field.TypeBool, value)
		_node.IsWildCardUsage = value
	}
	if value, ok := duec.mutation.Identifier(); ok {
		_spec.SetField(depsusageevidence.FieldIdentifier, field.TypeString, value)
		_node.Identifier = &value
	}
	if value, ok := duec.mutation.UsageFilePath(); ok {
		_spec.SetField(depsusageevidence.FieldUsageFilePath, field.TypeString, value)
		_node.UsageFilePath = value
	}
	if value, ok := duec.mutation.Line(); ok {
		_spec.SetField(depsusageevidence.FieldLine, field.TypeUint, value)
		_node.Line = value
	}
	if nodes := duec.mutation.UsedInIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   depsusageevidence.UsedInTable,
			Columns: []string{depsusageevidence.UsedInColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(codesourcefile.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.deps_usage_evidence_used_in = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// DepsUsageEvidenceCreateBulk is the builder for creating many DepsUsageEvidence entities in bulk.
type DepsUsageEvidenceCreateBulk struct {
	config
	err      error
	builders []*DepsUsageEvidenceCreate
}

// Save creates the DepsUsageEvidence entities in the database.
func (duecb *DepsUsageEvidenceCreateBulk) Save(ctx context.Context) ([]*DepsUsageEvidence, error) {
	if duecb.err != nil {
		return nil, duecb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(duecb.builders))
	nodes := make([]*DepsUsageEvidence, len(duecb.builders))
	mutators := make([]Mutator, len(duecb.builders))
	for i := range duecb.builders {
		func(i int, root context.Context) {
			builder := duecb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DepsUsageEvidenceMutation)
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
					_, err = mutators[i+1].Mutate(root, duecb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, duecb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, duecb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (duecb *DepsUsageEvidenceCreateBulk) SaveX(ctx context.Context) []*DepsUsageEvidence {
	v, err := duecb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (duecb *DepsUsageEvidenceCreateBulk) Exec(ctx context.Context) error {
	_, err := duecb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duecb *DepsUsageEvidenceCreateBulk) ExecX(ctx context.Context) {
	if err := duecb.Exec(ctx); err != nil {
		panic(err)
	}
}
