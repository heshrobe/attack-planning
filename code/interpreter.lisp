;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; States
;;;
;;; A world-state; 
;;; States form a di-graph with predecessor/successor relationships
;;; (most commonly it's actually a tree)
;;; And "contains" a set of predicatins true at that time
;;; There is an inheritance mechanism 
;;; Predications that are true in a predecessor state B are truth in this state A
;;; Unless they are false in a state C that is a successor of B and a predecessor of A
;;; And vice versa for false
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass specialized-search-context ()
  ((footholds-held :accessor footholds-held :initform nil :initarg :footholds-held)
   (places-visited :accessor places-visited :initform nil :initarg :places-visited)
   (attacker :accessor attacker :initarg :attacker)
   (attacker-computer :accessor attacker-computer :initarg :attacker-computer)
   ))

(defclass state (specialized-search-context)
  ((state-name :accessor state-name :initarg :state-name)
   (depth :accessor depth :initform 0 :initarg :depth)
   (predecessor :accessor predecessor :initarg :predecessor :initform nil)
   (successors :accessor successors :initarg :successors :initform nil)
   (prior-action :accessor prior-action :initarg :prior-action :initform nil)
   (next-action :accessor next-action :initarg :next-action :initform nil)
   ))

(defmethod print-object ((thing state) stream)
  (format stream "#<state ~a>" (state-name thing)))

(defparameter *initial-state* nil)
(defparameter *state-ht* (make-hash-table))

(defun make-initial-state ()
  (setq *initial-state* (make-instance 'state :state-name 'initial :depth 0))
  (setf (gethash (state-name *initial-state*) *state-ht*) *initial-state*))

(eval-when (:load-toplevel :execute)
  (make-initial-state))

;;; Note that when we intern a state with a prior state we copy
;;; the information from the prior stare into the new state
(defun intern-state (state-identifier &optional (prior-state nil prior-state-supplied-p))
  ;; For both prior-state and state
  ;; we could be called with either a state-identifier or a state
  (let ((state nil))
    (typecase state-identifier
      (state (setq state state-identifier))
      (symbol
       (setq state (gethash state-identifier *state-ht*))
       (when (null state)
	 (setq state (make-instance 'state :state-name state-identifier))
	 (setf (gethash state-identifier *state-ht*) state))))
    (if prior-state-supplied-p 
	(when (and (symbolp prior-state) (not (null prior-state)))
	  ;; if prior state is explictly NIL we don't want to intern 
	  ;; a state name NIL
	  (setq prior-state (intern-state prior-state)))
      (setq prior-state *initial-state*))
    (when prior-state
      (setf (attacker state) (attacker prior-state)
	    (attacker-computer state) (attacker-computer prior-state)
	    (footholds-held state) (footholds-held prior-state)
	    (places-visited state) (places-visited prior-state)
	    (predecessor state) prior-state
	    (depth state) (1+ (depth prior-state)))
      (push state (successors prior-state)))
    state))

(defun is-predecessor-of (state1 state2)
  (let ((target-depth (depth state1)))
    (loop for this-state = state2 then next-state
	for this-depth = (depth this-state)
	for next-state = (predecessor this-state)
	do (cond ((= this-depth target-depth)
		  (return-from is-predecessor-of (eql this-state state1)))
		 ((< this-depth target-depth)
		  (return-from is-predecessor-of nil)))
	until (null next-state))))

(defun state-of-pred (predication)
  (with-statement-destructured (embedded-pred state) predication
    (declare (ignore embedded-pred))
    state))

(defun depth-of-pred (predication)
  (depth (state-of-pred predication)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Stateful Predicates
;;;
;;; [in-state <internal-pred> <state>]
;;; where internal-pred can be any time of pred and is unaware of the statefulness
;;;
;;; There is a map (*truth-value-ht*) from the internal-pred to a structure that says which states the 
;;; internal pred is true/false in 
;;; There is also an interning ht (*stateful-pred-ht*) for the [in-state interanal-pred state] predications
;;;
;;; In the canonical form the internal-pred is never negated
;;; [in-state [not pred] state] = [not [in-state pred state]]
;;; This leads to a bit of fussy'ness in tell and ask
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass state-truth-map ()
  ((true-states :accessor true-states :initform nil :initarg :true-states)
   (false-states :accessor false-states :initform nil :initarg :false-states)))

(defparameter *truth-value-ht* (make-hash-table))
(defparameter *stateful-pred-ht* (make-hash-table :test #'equal))

(define-predicate-model stateful-predicate-mixin () ())

(define-predicate-method (after-clear stateful-predicate-mixin) (&optional clear-database undefrules)
  (declare (ignore undefrules))
  (when clear-database
    (clrhash *truth-value-ht*)
    (clrhash *stateful-pred-ht*)
    (clrhash *state-ht*)
    (make-initial-state)
    ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Tell'ing stateful predications
;;;
;;; We try to just wrap elements of the protocol where necessary to handle
;;; the unique features of this type of predication
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate-method (tell stateful-predicate-mixin :around) (truth-value justification)
  (with-statement-destructured (internal-pred state) self
    (let ((real-pred self)
	  (real-truth-value truth-value))
      ;; canonicalize out negated internal preds
      (typecase internal-pred
	(ji::not-model
	 (with-statement-destructured (unnegated) internal-pred
	   (setq real-pred `[,(predication-predicate self) ,unnegated ,state]
		 real-truth-value (ji::negate-truth-value truth-value)))))
      (call-next-method real-pred real-truth-value justification))))

;;; This extra level dispatch is to allow inserts of special kinds of predicates
;;; particularly those in the object model
;;; And our special ones releated to footholds and already-visited

(defgeneric insert-in-state (outer-predicate internal-pred state))

(define-predicate-method (insert stateful-predicate-mixin) ()
  (with-statement-destructured (internal-pred state) self
    (insert-in-state (predication-predicate self) internal-pred (intern-state state))))

;;; This is for vanilla assertions other than things like current-foothold
;;; and has-been-visited. 

(defmethod insert-in-state (outer-predicate (internal-pred predication) (state state))
  (let* ((canonicalized-internal-pred (insert internal-pred))
	 (canonicalized-pred (gethash (list canonicalized-internal-pred state) *stateful-pred-ht*))
	 (truth-map (gethash canonicalized-internal-pred *truth-value-ht*)))
    (let ((new-p (null canonicalized-pred)))
      (when new-p
	(setq canonicalized-pred `[,outer-predicate ,canonicalized-internal-pred ,state])
	(setf (gethash (list canonicalized-internal-pred state) *stateful-pred-ht*) canonicalized-pred))
      (when (null truth-map)
	(setq truth-map (make-instance 'state-truth-map))
	(setf (gethash canonicalized-internal-pred *truth-value-ht*) truth-map))
      (values canonicalized-pred new-p))))

;;; Fix: I'm ignoring transitions from true or false to unknown
;;; that would happen if you unjustify the thing
(define-predicate-method (notice-truth-value-change stateful-predicate-mixin :before) (old-truth-value)
  (declare (ignore old-truth-value))
  (with-statement-destructured (internal-pred state) self
    (let ((truth-value (predication-truth-value self))
	  (truth-map (gethash internal-pred *truth-value-ht*)))
      (cond ((eql truth-value +false+)
	     (Pushnew state (false-states truth-map)))
	    ((eql truth-value +true+)
	     (pushnew state (true-states truth-map)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Ask methods for Stateful Predicates
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defgeneric ask-in-state (query truth-value state continuation))

(define-predicate-method (ask-data stateful-predicate-mixin) (truth-value continuation)
  (with-statement-destructured (internal-pred state-descriptor) self
    (when (unbound-logic-variable-p internal-pred)
      (error 'ji:model-cant-handle-query
	     :query self
	     :model (type-of self)))
    ;; handle negated internal predication
    (when (typep internal-pred 'ji::not-model)
      (setq internal-pred (second (predication-statement internal-pred))
	    truth-value (negate-truth-value truth-value)))
    (ask-in-state internal-pred truth-value (intern-state state-descriptor) continuation)))
    
;;; This is the default way of retrieving stateful predications
(defmethod ask-in-state ((internal-pred predication) truth-value (state state) continuation)
  (fetch internal-pred
	 #'(lambda (interned-pred)
	     (block this-guy
	       (flet ((succeed ()
			(with-unification 
			 ;; this is necessary because slot-value-mixin interns
			 ;; a pred with the slot vs the path.  I.e. source pred
			 ;; won't unify with one another.  Maybe that could be fixed
			 ;; at the unify predication level except that's not a generic function
			 ;; Note that the path part of the query can't have logic variables
			 ;; except for the first thing, which is a query to map over everything
			 ;; which we don't support here.  This means that follow-path works correctly here
			 (if (typep internal-pred 'slot-value-mixin)
			     (with-statement-destructured (path value) internal-pred
			       (with-statement-destructured (his-path his-value) interned-pred
				 (unify (follow-path path nil) his-path)
				 (unify his-value value)))
			   (unify interned-pred internal-pred))
			 (stack-let ((backward-support (list internal-pred +true+ '(ask-data statefule-predicate-mixin))))
			   (funcall continuation backward-support)
			   (return-from this-guy)))))
		 (let* ((truth-map (gethash interned-pred *truth-value-ht*))
			(false-states (when truth-map (false-states truth-map)))
			(true-states (when truth-map (true-states truth-map)))
			(negated (eql truth-value +false+)))
		   ;; if the guy has never been told in a state then just check
		   ;; if it has the right truth-value
		   (if (and (null truth-map)
			    (eql (predication-truth-value interned-pred) truth-value))
		       (succeed)
		     (loop for this-state = state then (predecessor this-state)
			 until (null this-state)
			 if (or (and negated (member this-state false-states))
				(and (not negated) (member this-state true-states)))
			    ;; should build a justification
			 do (succeed)
			    ;; if it doesn't hit in any state but does hit in the "base" environment
			    ;; and it has the right truth-value then succeed
			 finally (when (eql (predication-truth-value interned-pred) truth-value)
				   (succeed))))))))))

(define-predicate in-state (predication state) (stateful-predicate-mixin default-predicate-model))

(defun consistent-state (state-set)
  (setq state-set (sort (copy-seq state-set) #'> :key #'depth))
  (loop for (first-state next-state . rest) on state-set by #'rest
      when (not (is-predecessor-of next-state first-state))
      do (return nil)
      when (null rest)
      return (first state-set)))

(define-predicate consistent-state (result &rest state-set) (tell-error-model default-predicate-model))

(define-predicate-method (expand-forward-rule-trigger consistent-state) (support-variable-name truth-value context bound-variables)
  (declare (ignore context))
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query self
	   :model (type-of self)))
  (with-predication-maker-destructured (final-variable &rest set) self
    `(:procedure 
      (let ((final-state (consistent-state (list ,@set))))
	(when final-state
	  (with-unification
	   (unify ,final-variable final-state)
	   (succeed nil))))
      ,support-variable-name
      ,bound-variables
      ,self)))

;;; An ask-data method for this just for completeness

(define-predicate-method (ask-data consistent-state) (truth-value continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
       :query self
       :model (type-of self)))
  (with-statement-destructured (final-state . other-states) self
    (when (find-if #'unbound-logic-variable-p other-states)
      (error 'ji:model-cant-handle-query
	      :query self
	      :model (type-of self)))
    (let ((answer (consistent-state other-states)))
      (when answer
	(with-unification
	 (unify final-state answer)
	 (stack-let ((backward-support (list self +true+ '(ask-data consistent-state))))
	   (funcall continuation backward-support)
	   ))))))


(defmacro define-fwrd-stateful-rule (name if if-part then then-part)
  (when (eql if 'then) (rotatef if-part then-part) (rotatef if then))
  (unless (and (eql if 'if) (eql then 'then)) (error "Must have if and then"))
  (destructuring-bind (pred . triggers) (predication-maker-statement if-part)
    (unless (eql pred 'and) (error "Must have and for trigger"))
    (loop for trigger in triggers
	for state-variable = `(logic-variable-maker ,(intern (gensym "?STATE-")))
	for real-trigger = `(predication-maker '(in-state ,trigger ,state-variable))
	collect real-trigger into real-triggers
	collect state-variable into state-variables
	finally ;; (break "~a ~a" real-triggers state-variables)
	  (let* ((final-state-variable `(logic-variable-maker ,(intern (gensym "?FINAL-STATE-"))))
		 (consistent-state-trigger `(predication-maker '(consistent-state ,final-state-variable ,@state-variables)))
		 (real-if-part `(predication-maker '(and ,@(append real-triggers (list consistent-state-trigger)))))
		 (real-then-part `(predication-maker '(in-state ,then-part ,final-state-variable))))
	    (return `(defrule ,name (:forward) if ,real-if-part then ,real-then-part))))))

#|

(define-fwrd-stateful-rule mumble
    if [and [foo 1 2 3]
	    [foo 2 3 4]]
    then [foo 3 4 5])

(defrule mumble (:forward) 
  if [and [in-state [foo 1 2 3] ?state-1000] 
	  [in-state [foo 2 3 4] ?state-1001]
	  [consistent-state ?final-state-1002 ?state-1000 ?state-1001]]
  then [in-state [foo 3 4 5] ?final-state-1002])

A test case for backward rules
(define-predicate foo (a b))

(clear)
(intern-state 'state-1)
(intern-state 'state-2 'state-1)
(intern-state 'state-3 'state-1)

(tell [in-state [foo 1 2] state-1])
(tell [in-state [foo 2 3] state-2])

(defrule state-chain (:backward)
  then [in-state [foo ?a ?c] ?state]
  if [and (not (unbound-logic-variable-p ?a))
	  (not (unbound-logic-variable-p ?c))
	  [in-state [foo ?a ?b] ?state]
	  (not (unbound-logic-variable-p ?b))
	  [in-state [foo ?b ?c] ?state]]
  )

(ask [in-state [foo 1 3] state-2] #'print-query)

This works but then goes into an infinite loop looking for other matches to [in-state [foo 1 ?b] state-2] which triggers 
the same rule but not ?c is unbound.  This has nothing to do with "in-state" it's a classic case of transitivity rules
not working in the backward direction for example:

(defrule chain (:backward)
  then [foo ?a ?c]
  if [and [foo ?a ?b]
	  (not (unbound-logic-variable-p ?b))
	  [foo ?b ?c]]
  )


(tell [foo 1 2])
(tell [foo 2 3])

also goes into infinite loop after finding the answer

|#




;;; Todo: I think backward rules should just work because they depend on the ask-data method
;;;       But needs to be checked.
;;; Forward Rules:
;;;  Outline (defrule xx (:forward) IF [and [in-state ... ?x] [in-state ...  ?x]] ...
;;;    turns into If [and [in-state ... ?x1] [in-state ... ?x2] (consistent-states ?x1 ?x2 pred-1 pred-2)
;;;  Where consistent states gets the deepest state out of ?x1 ?x2 and then checks that for all the 
;;;  embdeded preds they are have the desired truth-values in that deepest state.