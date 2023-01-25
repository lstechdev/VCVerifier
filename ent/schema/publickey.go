package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// PublicKey holds the schema definition for the PublicKey entity.
type PublicKey struct {
	ent.Schema
}

// Fields of the PublicKey.
func (PublicKey) Fields() []ent.Field {
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

// Edges of the PublicKey.
func (PublicKey) Edges() []ent.Edge {
	return nil
}
