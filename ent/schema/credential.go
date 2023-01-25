package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Credential holds the schema definition for the Credential entity.
type Credential struct {
	ent.Schema
}

// Fields of the Credential.
func (Credential) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("type").Default("jwt_vc"),
		field.JSON("raw", []byte{}),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now),
	}
}

// Edges of the Credential.
func (Credential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("account", User.Type).
			Ref("credentials").
			Unique(),
	}
}
