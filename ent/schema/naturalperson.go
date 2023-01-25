package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// NaturalPerson holds the schema definition for the NaturalPerson entity.
type NaturalPerson struct {
	ent.Schema
}

// Fields of the NaturalPerson.
func (NaturalPerson) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique(),
		field.String("name").
			NotEmpty(),
		field.String("displayname").
			Optional(),
		field.String("type").
			NotEmpty(),
		field.Bytes("password").
			NotEmpty().Sensitive(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now),
	}
}

// Edges of the NaturalPerson.
func (NaturalPerson) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("keys", PrivateKey.Type),
		edge.To("credentials", Credential.Type),
	}
}
