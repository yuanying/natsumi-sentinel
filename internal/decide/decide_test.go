package decide_test

import (
	"context"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

func TestTheDefaultsDecideByTheDestinationsDefault(t *testing.T) {
	tests := []struct {
		def  routes.Action
		want audit.Verdict
	}{
		{routes.Allow, audit.Allow},
		{routes.Deny, audit.Deny},
	}
	for _, tt := range tests {
		t.Run(string(tt.def), func(t *testing.T) {
			got := decide.Defaults{}.Decide(context.Background(), decide.Request{
				Destination: routes.Destination{Name: "api.example.com", Treatment: routes.Open, Default: tt.def},
				Method:      "POST",
				Path:        "/",
			})
			if got.Verdict != tt.want {
				t.Errorf("Decide = %+v, want %s", got, tt.want)
			}
			if got.Reason == "" {
				t.Error("Decide gave no reason")
			}
		})
	}
}

func TestADestinationWithoutAKnownDefaultIsDenied(t *testing.T) {
	got := decide.Defaults{}.Decide(context.Background(), decide.Request{
		Destination: routes.Destination{Name: "api.example.com", Treatment: routes.Open},
	})
	if got.Verdict != audit.Deny {
		t.Errorf("Decide = %+v, want deny", got)
	}
}
