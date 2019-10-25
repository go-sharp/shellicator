package shellicator

import (
	"errors"
	"testing"
)

func TestErr_Is(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		e    error
		args args
		want bool
	}{
		{
			name: "Same Err",
			e:    ErrTokenNotFound,
			args: args{err: ErrTokenNotFound},
			want: true,
		},
		{
			name: "Other Err",
			e:    ErrTokenNotFound,
			args: args{err: ErrGeneric},
			want: false,
		},
		{
			name: "Embedded Err",
			e:    &sherr{Err: ErrTokenNotFound, message: "some token not found"},
			args: args{err: ErrTokenNotFound},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.e, tt.args.err); got != tt.want {
				t.Errorf("Err.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
