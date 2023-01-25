package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PrivateKey holds the schema definition for the PrivateKey entity.
type PrivateKey struct {
	ent.Schema
}

// Fields of the PrivateKeys.
func (PrivateKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("kty"),
		field.String("alg").Optional(),
		field.JSON("jwk", []byte{}),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now),
	}
}

// Edges of the PrivateKeys.
func (PrivateKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("keys").
			Unique(),
	}
}
