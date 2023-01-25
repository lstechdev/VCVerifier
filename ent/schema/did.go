package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// DID holds the schema definition for the DID entity.
type DID struct {
	ent.Schema
}

// Fields of the DIDs.
func (DID) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("method").Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now),
	}
}

// Edges of the DIDs.
func (DID) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("dids").
			Unique(),
	}
}
