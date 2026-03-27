;; Test ref.null instruction
;; Tests both funcref and externref null references

(module
  ;; Test ref.null funcref
  (func (export "ref_null_funcref") (result funcref)
    (ref.null func)
  )

  ;; Test ref.null externref
  (func (export "ref_null_externref") (result externref)
    (ref.null extern)
  )
)

;; Verify that null references are produced
(assert_return (invoke "ref_null_funcref") (ref.null func))
(assert_return (invoke "ref_null_externref") (ref.null extern))