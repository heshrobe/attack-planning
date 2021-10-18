;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; macros for describing environment
;;; makes the telling of the whole description atomic.

(in-package :aplan)

(defprogram safari-v12
    :generic safari
    :cpe "cpe:*.*")

(defcomputer safari-runner mac-computer)

(defprocess safari 
    :process-type safari-process 
    :machine safari-runner
    :program safari-v12)

(define-action modify-data-structures-example (?process ?data-set ?foothold-machine ?foothold-role)
  :capecs ((?process cape-3323 ?cve-1))
  :bindings ([attacker-and-machine ?attacker ?])
  :prerequisites ([has-control-of ?attacker execution ?process])
  :post-conditions ([modified-by ?attacker ?data-set])
  )

(defun get-cves (filename)
  (let ((cves (json:decode-json-from-source (pathname filename))))
    (coerce cves 'list)))

(define-predicate vulnerable-to-capec (thing capec cve-number) (ltms:ltms-predicate-model))

(define-predicate-method (ask-data vulnerable-to-capec) (truth-value continuation)
  (with-statement-destructured (object capec cve-variable) self
    (let* ((cpe (cpe (program object)))
           (file-name <sam code to invoke BRON>)
           (cves (get-cves filename)))
      (loop for cve in cves
          do (with-unification
              (unfiy cve cve-variable)
              (stack-let ((backward-support (list self +true+ (attacker-and-machine-pred this-state) '(ask-data vulnerable-to-capec))))
                (funcall continuation backward-support)))))))

      
      