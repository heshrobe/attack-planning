;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Componenets of attack planning
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; First a macro to make notation more abstract and clearer
;;; In this syntax in both the :to-achieve field and the :plan field
;;; there is a hidden last argument in the predications
;;; In the :to-achieve field this is ?plan
;;; In the :plan field it's the second part of the :goal :plan field
;;; The plan field is a nested set of :sequential :parallel constructions
;;; each one taking a list of (:goal :plan) pairs
;;; The macro rebuilds the predication-makers into ones with the last variable
;;; 
;;; In the :plan section, it traverses the structure, builds a buch of predication-makers
;;; for the sub-goal part of the rule and also builds up the plan list structure that 
;;; is unified with the plan logic-variable

(defun attach-logic-variable-to-predication-maker (predication-maker logic-variable-maker)
  (let ((new-statement (append (predication-maker-statement predication-maker)
			       (list logic-variable-maker))))
    `(predication-maker ',new-statement)))

(defun rebuild-plan-structure (plan-structure &optional (input-state `(logic-variable-maker .(intern (string-upcase "?input-state"))))
							(output-state `(logic-variable-maker ,(intern (string-upcase "?output-state")))))
  ;; as we traverse the plan-structure tree we accumulate the list structure
  ;; of the plan and push
  ;; each this returns 3 values.  I'm not sure why the third yet
  (labels ((do-next-level (structure connective input-state output-state)
	     ;; each level should either be a :sequential/:parallel
	     ;;  or a :goal/:plan pair
	     ;;  or maybe a :action item (to be dealth with later)
             (destructuring-bind (key . stuff) structure
               (case key
                 (:sequential
                  (loop for (thing . more-to-come) on stuff
		      for last = (not more-to-come)
		      for next-input-state = input-state then his-output-state
		      for next-output-state = (when last output-state)
		      for his-result = (do-next-level thing key next-input-state next-output-state)
                      for (his-stuff his-plan-structure his-output-state) = his-result
                      append his-stuff into stuff
		      when his-plan-structure  ;; a note provides no plan structure
                      collect his-plan-structure into plan-structure
                      finally (let* ((is-singleton? (null (rest plan-structure)))
				     (final-key (if is-singleton? :singleton key)))
				(return (list stuff `(list ,final-key ,@plan-structure) his-output-state)))))
		 (:parallel
                  (loop for thing in stuff
		      for (his-stuff his-plan-structure) = (do-next-level thing key input-state output-state)
		      append his-stuff into stuff
		      when his-plan-structure ;; a note provides no plan structure
		      collect his-plan-structure into plan-structure 
		      finally (return (list stuff `(list ,key ,@plan-structure) nil))))
		 (:bind
		  (let* ((the-binding (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (rebuilt-statement`(predication-maker '(in-state ,the-binding ,input-state))))
		    (list (list rebuilt-statement)
			  nil
			  input-state)))
		 (:note
		  (let* ((the-note (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (intermediate-state (or (getf structure :output-state)
						 output-state
						 (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
			 (statement the-note)
			 (rebuilt-statement `(prog1 t (let ((new-state (intern-state (intern (string-upcase (gentemp "intermediate-state-"))) ,input-state)))
							(setf (intermediate-state? new-state) t)
							(unify ,intermediate-state new-state)
							(tell (predication-maker '(in-state ,statement ,intermediate-state)))))))
		    (list (list rebuilt-statement)
			  nil
			  intermediate-state)))
		 (:break (list (list `(prog1 t (break ,@stuff)))
			       nil
			       input-state))
                 ((:goal :plan)
                  (let* ((goal (getf structure :goal))
                         (plan (getf structure :plan (ji::make-logic-variable-maker (gentemp (string-upcase "?plan-") ))))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (output-state (or (getf structure :output-state)
					   output-state
					   (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
                         (rebuilt-statement `(predication-maker '(achieve-goal ,goal ,input-state ,output-state ,plan))))
                    (list (list rebuilt-statement)
                          (if (null connective)
                              `(list :singleton
                                     (list :goal ,(fixup-syntax (predication-maker-statement goal))
                                           :plan ,plan))
                            `(list :goal ,(fixup-syntax (predication-maker-statement goal))
                                   :plan ,plan))
			  output-state)))
                 ((:action :repeated-action)
		  (let* ((statement (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji::make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (output-state (or (getf structure :output-state)
					   output-state
					   (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
			 (action-variable (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?action-")))))
			 (rebuilt-statement `(predication-maker '(take-action ,statement ,input-state ,output-state ,action-variable)))
			 )
		    ;; (break "Action ~a ~a ~a ~a" statement input-state output-state rebuilt-statement)
		    (list 
		     ;; The action requires no further sub-goaling
		     (list rebuilt-statement)
		   ;;; rebuilt action statement
		     (if (null connective)
			 `(list :singleton
				(list ,key ,(fixup-syntax (predication-maker-statement (first stuff))) ,action-variable))
		       `(list ,key ,(fixup-syntax (predication-maker-statement (first stuff))) ,action-variable))
		     output-state))))))
           (fixup-syntax (predication-maker-statement)
             `(list
               ,@(loop for thing in predication-maker-statement
                     collect (typecase thing
                               (logic-variable-maker thing)
                               (symbol `',thing)
                               (list (fixup-syntax thing)))))))
    (when plan-structure
      (do-next-level plan-structure nil input-state output-state))))

(defun process-post-conditions (assertions output-state)
  (when assertions
    `((prog1 t
	,@(loop for assertion in assertions
	      collect `(tell [in-state ,assertion ,output-state]))))))
						
(defun process-assertions (assertions input-state)
  (labels ((do-one (assertion)
	     (cond 
	      ;; special case for debugging
	      ((and (listp assertion) (not (predication-maker-p assertion)))
	       (if (eql (first assertion) 'break)
		   `(prog1 t ,assertion)
		 assertion))
	      ((eql (predication-maker-predicate assertion) 'or)
	       (with-predication-maker-destructured (&rest assertions) assertion
		 (loop for assertion in assertions 
		     collect (do-one assertion) into processed-assertions
		     finally (return `(predication-maker '(or ,@processed-assertions))))))
	      ((and (listp assertion) (not (predication-maker-p assertion))) assertion)
	      ((compile-without-state assertion) assertion)
	      (t `(predication-maker '(in-state ,assertion ,input-state))))))
    (loop for thing in assertions collect (do-one thing))))


(defun process-guards (assertions input-state) (process-assertions assertions input-state))

(defun is-pretty-binding (assertion)
  (when (and (predication-maker-p assertion)
	     (eql (predication-maker-predicate assertion) 'value-of)
	     (with-predication-maker-destructured (path value) assertion
	       (if (and (not (logic-variable-maker-p path))
			(listp path))
		   nil
		 (and (logic-variable-maker-p value)
		      (find #\. (string (if (logic-variable-maker-p path)
					    (logic-variable-maker-name path)
					  path))
			    :test #'char-equal)))))
    t))

(defun explode-string (string delim)
  ;; so it can handle a symbol
  (setq string (string string))
  (loop for last-pos = 0 then (1+ next-pos)
        for next-pos = (position delim string :start last-pos)
        collect (subseq string last-pos next-pos)
      until (null next-pos))
  )

(defun de-prettify-binding (assertion)
  (with-predication-maker-destructured  (path logic-variable) assertion
    (flet ((process-path (list-of-strings)
	     (loop for thing in list-of-strings
		   if (char-equal (aref thing 0) #\?)
		   collect (ji::make-logic-variable-maker (intern thing))
		   else collect (intern thing))))
      (if (logic-variable-maker-p path)
	  (let* ((name (logic-variable-maker-name path))
		 (exploded-path (explode-string name #\.))
		 (real-path (cons (ji::make-logic-variable-maker (intern (first exploded-path)))
				  (process-path (rest exploded-path)))))
	  `(predication-maker '(value-of ,real-path ,logic-variable)))
      (let ((expanded-path (process-path (explode-string path #\.))))

	`(predication-maker '(value-of ,expanded-path ,logic-variable)))))))

(defun process-bindings (assertions input-state)
  (let ((expanded-bindings (loop for assertion in assertions
			       collect (if (is-pretty-binding assertion)
					   (de-prettify-binding assertion)
					 assertion))))
    (process-assertions expanded-bindings input-state)))

(defun process-prerequisites (assertions input-state) (process-assertions assertions input-state))

(defun compile-without-state (form)
  (if (predication-maker-p form)
    (let ((predicate (predication-maker-predicate form)))
      (cond
       ((eql predicate 'not)
	  (with-predication-maker-destructured (internal-pred) form
	    (let ((internal-predicate (predication-maker-predicate internal-pred)))
	      (subtypep internal-predicate 'non-stateful-predicate-model))))
       (t
	(or (subtypep predicate 'non-stateful-predicate-model)
	    (subtypep predicate 'ji::named-part-of-mixin)))))
    nil))

(defun process-typing (forms)
  (loop for form in forms
      if (and (listp form) (= (length form) 2))
      collect `(predication-maker '(ltms:object-type-of ,@form))
      else collect form))

(defmacro defattack-method (method-name &key to-achieve 
					     (input-state `(logic-variable-maker ,(intern (string-upcase "?input-state"))))
					     (output-state `(logic-variable-maker ,(intern (string-upcase "?output-state"))))
					     guards 
					     bindings
					     prerequisites
					     typing
					     plan
					     post-conditions
					     )
  (let* ((plan-variable `(logic-variable-maker ,(gensym "?PLAN")))
         (real-head `(predication-maker '(achieve-goal ,to-achieve ,input-state  ,output-state ,plan-variable)))
	 (rebuilt-plan-structure (rebuild-plan-structure plan input-state output-state)))
    (destructuring-bind (stuff plan-structure thing) (or rebuilt-plan-structure (list nil nil nil))
      (declare (ignore thing))
      `(defrule ,method-name (:backward)
         then ,real-head
         if [and 
	     ,@(process-bindings bindings input-state)
	     ,@(process-guards guards input-state)
	     ,@(process-typing typing)
	     ,@(process-prerequisites prerequisites input-state)
	     ,@stuff
	     ,@(process-post-conditions post-conditions output-state)
	     ,@(when (null rebuilt-plan-structure)
	       `((unify ,input-state ,output-state)))
	     (unify ,plan-variable ,plan-structure)
	     ]))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-goal macro & achieve goal predicate
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmacro define-goal (name variables) `(define-predicate ,name ,variables (ltms:ltms-predicate-model)))

(define-predicate achieve-goal (goal-to-achieve input-state output-state plan) (ltms:ltms-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Classes for building a structured-backpointered plan object
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defclass has-parent-mixin ()
  ((parent :accessor parent :initform nil :initarg :parent)))

(defclass has-plan-mixin ()
  ((plan :accessor plan :initform nil :initarg nil)))

(defclass has-arguments-mixin ()
  ((arguments :accessor arguments :initarg :arguments)))

(defclass action (has-parent-mixin has-arguments-mixin print-nicely-mixin)
  ((action-name :accessor action-name :initarg :action-name)
   (prior-state :accessor prior-state :initarg :prior-state)
   (next-state :accessor next-state :initarg :next-state)
   (is-on-solution-path? :accessor is-on-solution-path? :initform nil)
   ))

(defclass goal (has-parent-mixin has-plan-mixin has-arguments-mixin)
  ((goal-name :accessor goal-name :initform nil :initarg :goal-name))
  )

(defclass plan (has-parent-mixin)
  ((connective :accessor connective :Initform nil :initarg :connective)
   (steps :accessor steps :initform nil :initarg :steps)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-action macro and take-action predicate & link-action function
;;;
;;; Similar to but simpler than def-attack-method
;;; and it uses some of the sub-routines from def-attack-method
;;;
;;; Actions are defined over a set of logic-variables
;;;  Have pre-conditions that are tested in the input-state
;;;  and post-conditions that are asserted in the output-state
;;;
;;; If the output state is not passed in a new successor of the input state
;;; is created and unified with the output-state logic-variable
;;;
;;; Given that it's a mix of asks and tells should it be a backward rule or just a procedure that returns
;;; the output state?
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate take-action (action-predicate input-state output-state action) (ltms:ltms-predicate-model))
   
(defun link-action (name arguments prior-state next-state)
  (let ((action (make-instance 'action
		  :action-name name
		  :arguments arguments
		  :prior-state prior-state
		  :next-state next-state)))
    (setf (next-action prior-state) action
	  (prior-action next-state) action)
    action))

(defmacro define-action (name variables &key bindings prerequisites post-conditions (define-predicate t) capecs) 
  (flet ((make-logic-variables (names)
	   (loop for var in names 
	       if (logic-variable-maker-p var)
	       collect var
	       else collect `(logic-variable-maker ,(intern (string-upcase (format nil "?~a" var))))))
	 (make-symbols-from-lvs (lvs)
	   (loop for lv in lvs
	       for name = (logic-variable-maker-name lv)
	       for pname-string = (subseq (string name) 1) ;; strip off the ?
	       collect (intern pname-string))))
    (let* ((logic-variables (make-logic-variables variables))
	   (names (make-symbols-from-lvs logic-variables))
	   (rule-name (intern (string-upcase (format nil "do-~a" name))))
	   (state-logic-variables (make-logic-variables '(input-state output-state)))
	   (capec-statements (loop for (victim capec-num cve-variable) in capecs
                                 collect `(predication-maker '(vulnerable-to-capec ,victim ,capec-num ,cve-variable))))
           (action-variable (first (make-logic-variables '(action)))))
      (destructuring-bind (input-state-variable output-state-variable) state-logic-variables
        `(eval-when (:compile-toplevel :load-toplevel :execute)
           ,@(when define-predicate `((define-predicate ,name ,names (ltms:ltms-predicate-model))))
           (defrule ,rule-name (:backward)
             then [take-action [,name ,@logic-variables] ,@state-logic-variables ,action-variable]
             if [and ,@(process-bindings bindings input-state-variable)
                     ,@(process-guards prerequisites input-state-variable)
                     ,@capec-statements
                     (prog1 t
                       (when (unbound-logic-variable-p ,output-state-variable)
                         (unify ,output-state-variable 
                                (intern-state (intern (string-upcase (gensym "state-"))) ,input-state-variable))))
                     (prog1 t (unify ,action-variable (link-action ',name (list,@logic-variables) ,input-state-variable ,output-state-variable)))
                     ,@(process-post-conditions post-conditions output-state-variable)
                     ]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Converting the list structured attack plan into a fully backpointered
;;; plan linking in the actions and states
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun structure-attack-plan (top-level)
  (labels ((make-goal (goal-element &optional parent)
	     (let ((goal-statement (getf goal-element :goal))
		   (sub-plan (getf goal-element :plan)))
	       ;; (format t "~%Working on goal ~a" goal-statement)
	       (destructuring-bind (goal-name . arguments) goal-statement
		 (let* ((goal-object (make-instance 'goal :goal-name goal-name :arguments arguments :parent parent))
			(plan-object (make-plan sub-plan goal-object)))
		   (setf (plan goal-object) plan-object)
		   goal-object))))
	   (make-plan (plan-element parent)
	     (let ((connective (first plan-element))
		   (steps (rest plan-element)))
	       ;; (format t "~%For goal ~a with connective ~a there are ~a steps" parent connective (length steps))
	       (let* ((plan-object (make-instance 'plan
				  :connective connective
				  :parent parent))
		      (the-steps (loop for step in steps
				     for type = (first step)
				     for step-object = (case type
							 (:goal (make-goal step plan-object))
							 (:action (make-action step plan-object)))
				     ;; do (format t "~%For type ~a step ~a" type step-object)
				     collect step-object)))
		 ;; (format t "~%Steps for plan ~a ~{~a~^, ~}" plan-object the-steps)
		 (setf (steps plan-object) the-steps)
		 plan-object)))
	   (make-action (step parent)
	     (destructuring-bind (head list-version actual-action) step
	       (declare (ignore head list-version))
	       (setf (parent actual-action) parent)
	       actual-action)))
    (make-goal top-level)))