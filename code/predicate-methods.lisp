;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

(defclass search-context ()
  ((footholds-held :accessor footholds-held :initform nil :initarg :footholds-held)
   (places-visited :accessor places-visited :initform nil :initarg :places-visited)
   (attacker :accessor attacker :initarg :attacker)
   (attacker-machine :accessor attacker-machine :initarg :attacker-machine)
   ))

(defmethod print-object ((sc search-context) stream)
  (with-slots (footholds-held places-visited) sc
    (format stream "<sc ~d ~d>" (length footholds-held) (length places-visited))))

(defun make-initial-search-context (&key (attacker (follow-path '(typical-attacker)))
					 (attacker-machine (follow-path '(typical-attacker-machine))))
  (let ((initial-foothold (list attacker-machine attacker)))
    (make-instance 'search-context
      :attacker attacker
      :attacker-machine attacker-machine
      :footholds-held (list initial-foothold)
      :places-visited nil)))

(defun copy-search-context (existing-context)
  (make-instance 'search-context
		 :attacker (attacker existing-context)
		 :attacker-machine (attacker-machine existing-context)
		 :footholds-held (footholds-held existing-context)
		 :places-visited (places-visited existing-context)))

(define-predicate-method (ask-data attacker-and-machine) (truth-value continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query self
	   :model (type-of self)))
  (with-statement-destructured (input-context attacker attacker-machine) self
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (with-unification 
     (unify attacker-machine (attacker-machine input-context))
     (unify attacker (attacker input-context))
     (stack-let ((backward-support (list self +true+ '(ask-data attacker-and-machine))))
       (funcall continuation backward-support)))))

(define-predicate-method (ask-data current-foothold) (truth-value continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query self
	   :model (type-of self)))
  (with-statement-destructured (input-context foothold-machine foothold-role) self
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (destructuring-bind (machine role) (first (footholds-held input-context))
      (with-unification 
       (unify machine foothold-machine)
       (unify role foothold-role)
       (stack-let ((backward-support (list self +true+ '(ask-data current-foothold))))
	 (funcall continuation backward-support))))))


(define-predicate-method (ask-data foothold-exists) (truth-value continuation)
  (with-statement-destructured (input-context foothold-machine) self
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (cond
     ((eql truth-value +true+)
      (when (member foothold-machine (footholds-held input-context) :key #'first)
	(stack-let ((backward-support (list self +true+ '(ask-data foothold-exists))))
	  (funcall continuation backward-support))))
     ((eql truth-value +false+)
      (unless (member foothold-machine (footholds-held input-context) :key #'first)
	(stack-let ((backward-support (list self +true+ '(ask-data foothold-exists))))
	  (funcall continuation backward-support))))
     (t (error 'model-cant-handle-query
	       :query self
	       :model (type-of self))))))

(define-predicate-method (ask-data has-foothold) (truth-value continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query self
	   :model (type-of self)))
  (with-statement-destructured (input-context foothold-machine foothold-role output-context) self
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (with-unification 
     (if (member foothold-machine (footholds-held input-context) :key #'first)
	 (unify output-context input-context)
       (let ((new-context (copy-search-context input-context)))
	 (push (list foothold-machine foothold-role) (footholds-held new-context))
	 (unify output-context new-context)))
     ;; (format *error-output* "~%Adding foothold ~a to ~a yielding ~a" foothold-machine input-context output-context)
     (stack-let ((backward-support (list self +true+ '(ask-data has-foothold))))
       (funcall continuation backward-support)))))


;;; If the purpose is remote-execution all we check is that there is a previous
;;; entry for the same machine.
(define-predicate-method (ask-data place-already-visited?) (truth-value continuation)
  (with-statement-destructured (input-context machine purpose protocol) self
    (declare (ignore protocol))
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (let ((it-exists (case purpose
		       ;; For remote execution, if you got here as a subgoal of getting a foothold for this machine
		       ;; you're in a loop.  Obviously if you got here as a subgoal of getting remote execution that's 
		       ;; a loop as well
		       (remote-execution (loop for (visited-machine) in (places-visited input-context)
					     thereis (eql machine visited-machine)))
		       ;; For foothold, we might be here as a subgoal of getting remote execution so we only look
		       ;; at foothold entries.  We consider recursing with a different protocol to also be a loop
		       ;; so protocol is actually ignored.
		       (foothold (loop for (visited-machine visited-purpose) in (places-visited input-context)
				       thereis (and (eql machine visited-machine) (eql purpose visited-purpose)))))))
      (cond
       ((eql truth-value +true+)
	(when it-exists
	  (stack-let ((backward-support (list self +true+ '(ask-data place-already-visited?))))
	    (funcall continuation backward-support))))
       ((eql truth-value +false+)
	(unless it-exists
	  (stack-let ((backward-support (list self +false+ '(ask-data place-already-visited?))))
	    (funcall continuation backward-support))))
       (t (error 'model-cant-handle-query
		 :query self
		 :model (type-of self)))))))

;;; This includes the machine, the purpose (either remote-execution or foothold) an the protocol 
;;; protocol is used on foothold.
(define-predicate-method (ask-data note-place-visited) (truth-value continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query self
	   :model (type-of self)))
  (with-statement-destructured (input-context machine purpose protocol output-context) self
    (when (unbound-logic-variable-p input-context)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    (with-unification 
     (unless 
	 ;; check to see if an equal entry already exists in the output-context
	 (loop for (visited-machine visited-purpose visited-protocol) in (places-visited input-context)
	     thereis (and (eql machine visited-machine) (eql purpose visited-purpose) (eql protocol visited-protocol)))
       ;; if not make a new entry in the output contex
       (let ((new-context (copy-search-context input-context)))
	 (push (list machine purpose protocol) (places-visited new-context))
	 (unify output-context new-context)
	 (stack-let ((backward-support (list self +true+ '(ask-data note-place-visited))))
	   (funcall continuation backward-support)))))))


;;; How to do the supertyping
(defun is-vulnerable-to (process attack)
  (labels ((do-one-type (type)
             (let ((type-name (ji::object-type-name type)))
               (ask `[protected-from ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values nil))))
               (ask `[vulnerable-to ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values t))))
               (loop for his-super in (ji::object-type-supertypes type)
                   do (do-one-type his-super)))))
    (let ((his-type (ji::basic-object-type process)))
      (do-one-type his-type))
    nil))

(defrule web-servers-are-vulnerable (:backward)
  then [vulnerable-to web-server-process buffer-overflow-attack]
  if t)

(defrule common-lisp-http-server-is-safe (:backward)
  then [protected-from cl-http-server-process buffer-overflow-attack]
  if t)