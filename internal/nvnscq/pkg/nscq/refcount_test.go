package nscq

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefcount(t *testing.T) {
	testCases := []struct {
		name             string
		workload         func(r *refcount)
		expectedRefcount refcount
	}{
		{
			name:             "no_inc_or_dec",
			workload:         func(r *refcount) {},
			expectedRefcount: refcount(0),
		},
		{
			name: "single_inc_no_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
			},
			expectedRefcount: refcount(1),
		},
		{
			name: "single_inc_with_error",
			workload: func(r *refcount) {
				r.IncOnNoError(errors.New(""))
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "double_inc_no_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(nil)
			},
			expectedRefcount: refcount(2),
		},
		{
			name: "double_inc_one_with_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(errors.New(""))
			},
			expectedRefcount: refcount(1),
		},
		{
			name: "single_dec_no_error",
			workload: func(r *refcount) {
				r.DecOnNoError(nil)
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "single_dec_with_error",
			workload: func(r *refcount) {
				r.DecOnNoError(errors.New(""))
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "single_inc_single_dec_no_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.DecOnNoError(nil)
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "double_inc_double_dec_no_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(nil)
				r.DecOnNoError(nil)
				r.DecOnNoError(nil)
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "double_inc_double_dec_one_inc_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(errors.New(""))
				r.DecOnNoError(nil)
				r.DecOnNoError(nil)
			},
			expectedRefcount: refcount(0),
		},
		{
			name: "double_inc_double_dec_one_dec_error",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(nil)
				r.DecOnNoError(nil)
				r.DecOnNoError(errors.New(""))
			},
			expectedRefcount: refcount(1),
		},
		{
			name: "double_inc_tripple_dec_one_dec_error_early_on",
			workload: func(r *refcount) {
				r.IncOnNoError(nil)
				r.IncOnNoError(nil)
				r.DecOnNoError(errors.New(""))
				r.DecOnNoError(nil)
				r.DecOnNoError(nil)
			},
			expectedRefcount: refcount(0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var r refcount
			tc.workload(&r)
			require.Equal(t, tc.expectedRefcount, r)
		})
	}
}
