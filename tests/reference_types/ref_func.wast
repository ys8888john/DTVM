;; Test ref.func instruction
;; Tests creation of function references

(module
  ;; Simple function to reference
  (func $f1 (export "f1") (result i32)
    (i32.const 1)
  )

  ;; Another function to reference
  (func $f2 (export "f2") (result i32)
    (i32.const 2)
  )

  ;; Return reference to f1
  (func (export "get_f1_ref") (result funcref)
    (ref.func $f1)
  )

  ;; Return reference to f2
  (func (export "get_f2_ref") (result funcref)
    (ref.func $f2)
  )

  ;; Check that ref.func produces non-null reference
  (func (export "f1_ref_is_not_null") (result i32)
    (ref.func $f1)
    (ref.is_null)
  )

  ;; Check that ref.func produces non-null reference
  (func (export "f2_ref_is_not_null") (result i32)
    (ref.func $f2)
    (ref.is_null)
  )
)

;; Verify that ref.func produces non-null references
(assert_return (invoke "f1_ref_is_not_null") (i32.const 0))
(assert_return (invoke "f2_ref_is_not_null") (i32.const 0))

;; Verify the function references
(assert_return (invoke "get_f1_ref") (ref.func 0))
(assert_return (invoke "get_f2_ref") (ref.func 1))