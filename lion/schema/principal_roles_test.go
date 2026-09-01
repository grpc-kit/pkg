package schema

import "testing"

func TestPrincipalRolesPrincipalTypeValidator(t *testing.T) {
	var validator func(int) error
	for _, schemaField := range (PrincipalRoles{}).Fields() {
		descriptor := schemaField.Descriptor()
		if descriptor.Name != "principal_type" {
			continue
		}
		if len(descriptor.Validators) != 1 {
			t.Fatalf("principal_type validators = %d, want 1", len(descriptor.Validators))
		}
		var ok bool
		validator, ok = descriptor.Validators[0].(func(int) error)
		if !ok {
			t.Fatalf("unexpected validator type %T", descriptor.Validators[0])
		}
	}
	if validator == nil {
		t.Fatal("principal_type field not found")
	}
	for _, value := range []int{1, 2, 3} {
		if err := validator(value); err != nil {
			t.Fatalf("validator(%d): %v", value, err)
		}
	}
	for _, value := range []int{0, 4} {
		if err := validator(value); err == nil {
			t.Fatalf("validator(%d) expected error", value)
		}
	}
}
