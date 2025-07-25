// Code generated by ent, DO NOT EDIT.

package reportproject

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/safedep/vet/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldID, id))
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldName, v))
}

// URL applies equality check predicate on the "url" field. It's identical to URLEQ.
func URL(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldURL, v))
}

// Description applies equality check predicate on the "description" field. It's identical to DescriptionEQ.
func Description(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldDescription, v))
}

// Stars applies equality check predicate on the "stars" field. It's identical to StarsEQ.
func Stars(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldStars, v))
}

// Forks applies equality check predicate on the "forks" field. It's identical to ForksEQ.
func Forks(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldForks, v))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldCreatedAt, v))
}

// UpdatedAt applies equality check predicate on the "updated_at" field. It's identical to UpdatedAtEQ.
func UpdatedAt(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldUpdatedAt, v))
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContainsFold(FieldName, v))
}

// URLEQ applies the EQ predicate on the "url" field.
func URLEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldURL, v))
}

// URLNEQ applies the NEQ predicate on the "url" field.
func URLNEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldURL, v))
}

// URLIn applies the In predicate on the "url" field.
func URLIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldURL, vs...))
}

// URLNotIn applies the NotIn predicate on the "url" field.
func URLNotIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldURL, vs...))
}

// URLGT applies the GT predicate on the "url" field.
func URLGT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldURL, v))
}

// URLGTE applies the GTE predicate on the "url" field.
func URLGTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldURL, v))
}

// URLLT applies the LT predicate on the "url" field.
func URLLT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldURL, v))
}

// URLLTE applies the LTE predicate on the "url" field.
func URLLTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldURL, v))
}

// URLContains applies the Contains predicate on the "url" field.
func URLContains(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContains(FieldURL, v))
}

// URLHasPrefix applies the HasPrefix predicate on the "url" field.
func URLHasPrefix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasPrefix(FieldURL, v))
}

// URLHasSuffix applies the HasSuffix predicate on the "url" field.
func URLHasSuffix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasSuffix(FieldURL, v))
}

// URLIsNil applies the IsNil predicate on the "url" field.
func URLIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldURL))
}

// URLNotNil applies the NotNil predicate on the "url" field.
func URLNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldURL))
}

// URLEqualFold applies the EqualFold predicate on the "url" field.
func URLEqualFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEqualFold(FieldURL, v))
}

// URLContainsFold applies the ContainsFold predicate on the "url" field.
func URLContainsFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContainsFold(FieldURL, v))
}

// DescriptionEQ applies the EQ predicate on the "description" field.
func DescriptionEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldDescription, v))
}

// DescriptionNEQ applies the NEQ predicate on the "description" field.
func DescriptionNEQ(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldDescription, v))
}

// DescriptionIn applies the In predicate on the "description" field.
func DescriptionIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldDescription, vs...))
}

// DescriptionNotIn applies the NotIn predicate on the "description" field.
func DescriptionNotIn(vs ...string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldDescription, vs...))
}

// DescriptionGT applies the GT predicate on the "description" field.
func DescriptionGT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldDescription, v))
}

// DescriptionGTE applies the GTE predicate on the "description" field.
func DescriptionGTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldDescription, v))
}

// DescriptionLT applies the LT predicate on the "description" field.
func DescriptionLT(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldDescription, v))
}

// DescriptionLTE applies the LTE predicate on the "description" field.
func DescriptionLTE(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldDescription, v))
}

// DescriptionContains applies the Contains predicate on the "description" field.
func DescriptionContains(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContains(FieldDescription, v))
}

// DescriptionHasPrefix applies the HasPrefix predicate on the "description" field.
func DescriptionHasPrefix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasPrefix(FieldDescription, v))
}

// DescriptionHasSuffix applies the HasSuffix predicate on the "description" field.
func DescriptionHasSuffix(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldHasSuffix(FieldDescription, v))
}

// DescriptionIsNil applies the IsNil predicate on the "description" field.
func DescriptionIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldDescription))
}

// DescriptionNotNil applies the NotNil predicate on the "description" field.
func DescriptionNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldDescription))
}

// DescriptionEqualFold applies the EqualFold predicate on the "description" field.
func DescriptionEqualFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEqualFold(FieldDescription, v))
}

// DescriptionContainsFold applies the ContainsFold predicate on the "description" field.
func DescriptionContainsFold(v string) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldContainsFold(FieldDescription, v))
}

// StarsEQ applies the EQ predicate on the "stars" field.
func StarsEQ(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldStars, v))
}

// StarsNEQ applies the NEQ predicate on the "stars" field.
func StarsNEQ(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldStars, v))
}

// StarsIn applies the In predicate on the "stars" field.
func StarsIn(vs ...int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldStars, vs...))
}

// StarsNotIn applies the NotIn predicate on the "stars" field.
func StarsNotIn(vs ...int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldStars, vs...))
}

// StarsGT applies the GT predicate on the "stars" field.
func StarsGT(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldStars, v))
}

// StarsGTE applies the GTE predicate on the "stars" field.
func StarsGTE(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldStars, v))
}

// StarsLT applies the LT predicate on the "stars" field.
func StarsLT(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldStars, v))
}

// StarsLTE applies the LTE predicate on the "stars" field.
func StarsLTE(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldStars, v))
}

// StarsIsNil applies the IsNil predicate on the "stars" field.
func StarsIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldStars))
}

// StarsNotNil applies the NotNil predicate on the "stars" field.
func StarsNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldStars))
}

// ForksEQ applies the EQ predicate on the "forks" field.
func ForksEQ(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldForks, v))
}

// ForksNEQ applies the NEQ predicate on the "forks" field.
func ForksNEQ(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldForks, v))
}

// ForksIn applies the In predicate on the "forks" field.
func ForksIn(vs ...int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldForks, vs...))
}

// ForksNotIn applies the NotIn predicate on the "forks" field.
func ForksNotIn(vs ...int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldForks, vs...))
}

// ForksGT applies the GT predicate on the "forks" field.
func ForksGT(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldForks, v))
}

// ForksGTE applies the GTE predicate on the "forks" field.
func ForksGTE(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldForks, v))
}

// ForksLT applies the LT predicate on the "forks" field.
func ForksLT(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldForks, v))
}

// ForksLTE applies the LTE predicate on the "forks" field.
func ForksLTE(v int32) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldForks, v))
}

// ForksIsNil applies the IsNil predicate on the "forks" field.
func ForksIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldForks))
}

// ForksNotNil applies the NotNil predicate on the "forks" field.
func ForksNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldForks))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldCreatedAt, v))
}

// CreatedAtIsNil applies the IsNil predicate on the "created_at" field.
func CreatedAtIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldCreatedAt))
}

// CreatedAtNotNil applies the NotNil predicate on the "created_at" field.
func CreatedAtNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldCreatedAt))
}

// UpdatedAtEQ applies the EQ predicate on the "updated_at" field.
func UpdatedAtEQ(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldEQ(FieldUpdatedAt, v))
}

// UpdatedAtNEQ applies the NEQ predicate on the "updated_at" field.
func UpdatedAtNEQ(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNEQ(FieldUpdatedAt, v))
}

// UpdatedAtIn applies the In predicate on the "updated_at" field.
func UpdatedAtIn(vs ...time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIn(FieldUpdatedAt, vs...))
}

// UpdatedAtNotIn applies the NotIn predicate on the "updated_at" field.
func UpdatedAtNotIn(vs ...time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotIn(FieldUpdatedAt, vs...))
}

// UpdatedAtGT applies the GT predicate on the "updated_at" field.
func UpdatedAtGT(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGT(FieldUpdatedAt, v))
}

// UpdatedAtGTE applies the GTE predicate on the "updated_at" field.
func UpdatedAtGTE(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldGTE(FieldUpdatedAt, v))
}

// UpdatedAtLT applies the LT predicate on the "updated_at" field.
func UpdatedAtLT(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLT(FieldUpdatedAt, v))
}

// UpdatedAtLTE applies the LTE predicate on the "updated_at" field.
func UpdatedAtLTE(v time.Time) predicate.ReportProject {
	return predicate.ReportProject(sql.FieldLTE(FieldUpdatedAt, v))
}

// UpdatedAtIsNil applies the IsNil predicate on the "updated_at" field.
func UpdatedAtIsNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldIsNull(FieldUpdatedAt))
}

// UpdatedAtNotNil applies the NotNil predicate on the "updated_at" field.
func UpdatedAtNotNil() predicate.ReportProject {
	return predicate.ReportProject(sql.FieldNotNull(FieldUpdatedAt))
}

// HasPackage applies the HasEdge predicate on the "package" edge.
func HasPackage() predicate.ReportProject {
	return predicate.ReportProject(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, PackageTable, PackageColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasPackageWith applies the HasEdge predicate on the "package" edge with a given conditions (other predicates).
func HasPackageWith(preds ...predicate.ReportPackage) predicate.ReportProject {
	return predicate.ReportProject(func(s *sql.Selector) {
		step := newPackageStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasScorecard applies the HasEdge predicate on the "scorecard" edge.
func HasScorecard() predicate.ReportProject {
	return predicate.ReportProject(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, ScorecardTable, ScorecardColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasScorecardWith applies the HasEdge predicate on the "scorecard" edge with a given conditions (other predicates).
func HasScorecardWith(preds ...predicate.ReportScorecard) predicate.ReportProject {
	return predicate.ReportProject(func(s *sql.Selector) {
		step := newScorecardStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.ReportProject) predicate.ReportProject {
	return predicate.ReportProject(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.ReportProject) predicate.ReportProject {
	return predicate.ReportProject(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.ReportProject) predicate.ReportProject {
	return predicate.ReportProject(sql.NotPredicates(p))
}
