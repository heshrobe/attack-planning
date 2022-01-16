;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Componenets of attack planning
;;;
;;; First some useful utilitires for def-attack-method
;;;
;;; In this syntax in both the :to-achieve field and the :plan field
;;; there is a hidden last argument in the predications
;;; In the :to-achieve field this is ?plan
;;; In the :plan field it's the second part of the :goal :plan field
;;; The plan field is a nested set of :sequential :parallel constructions
;;; each one taking a list of (:goal :plan) pairs
;;; The macro rebuilds the predication-makers into ones with the last variable
;;;
;;; In the :plan section, it traverses the structure, builds a bunch of predication-makers
;;; for the sub-goal part of the rule and also builds up the plan list structure that
;;; is unified with the plan logic-variable
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defvar name-to-number-hash-table (make-hash-table))

(defun make-name (lead-in)
  (let ((existing-number (gethash lead-in name-to-number-hash-table)))
    (unless existing-number
      (setf (gethash lead-in name-to-number-hash-table) 0))
    (intern (string-upcase (format nil "~a-~d" lead-in (incf (gethash lead-in name-to-number-hash-table)))))))

(defun smash (&rest names)
  (let ((strings (loop for (name . rest) on names
                     for string = (string name)
                     collect string
                     when rest
                          collect "-")))
    (intern (string-upcase (apply #'concatenate 'string strings)))))

(defun explode-string (string delim)
  ;; so it can handle a symbol
  (setq string (string string))
  (loop for last-pos = 0 then (1+ next-pos)
        for next-pos = (position delim string :start last-pos)
        collect (subseq string last-pos next-pos)
      until (null next-pos))
  )

(defmethod explode ((thing symbol) delimeter)
  (let ((*package* (symbol-package thing)))
    (if (find delimeter (string thing) :test #'char-equal)
        (loop for string in (explode-string thing delimeter)
            collect (intern string))
      (list thing))))

(defmethod explode ((thing list) delimeter)
  (if (logic-variable-maker-p thing)
      (destructuring-bind (first . rest) (explode (logic-variable-maker-name thing) delimeter)
        (list* (ji:make-logic-variable-maker first) rest))
    thing))



(defun attach-logic-variable-to-predication-maker (predication-maker logic-variable-maker)
  (let ((new-statement (append (predication-maker-statement predication-maker)
			       (list logic-variable-maker))))
    `(predication-maker ',new-statement)))

;;; This is the heart of the compiler from PDDL style to Joshua style
;;; It's recursive descent framework with a dispatch on the type (i.e. the first token) of the form
;;; being processed

(defparameter *method-tracing* nil)
(defun rebuild-plan-structure (method-name plan-structure &optional (input-state `(logic-variable-maker .(intern (string-upcase "?input-state"))))
							(output-state `(logic-variable-maker ,(intern (string-upcase "?output-state")))))
  ;; traverse the plan-structure accumulating the forms to put in the Joshua rule
  ;; and the list-structure for the eventual plan
  ;; Every sublevel of structure is supposed to return 3 things:
  ;; 1) The code to emit in the matching part (i.e. in the prologue of the IF part of the rule), typically
  ;;     something to match like a sub-goal predication, but occasionally lisp forms (e.g. break)
  ;; 2) The plan structure for this level (i.e. the stuff that gets unified with the plan logic-variable)
  ;; 3) The output state at the end of this level
  (labels ((do-next-level (structure connective input-state output-state)
	     ;; each level should either be a :sequential/:parallel/:repeat
	     ;;  or a :goal/:plan pair
             ;;  or an :action item
             ;; or pseudo things like a :note :bind or :break
             (destructuring-bind (key . stuff) structure
               (ecase key
                 ((:sequential :repeat)
                  (loop for (thing . more-to-come) on stuff
		      for last = (or (not more-to-come)
                                     (not (loop for (key) in more-to-come
                                              thereis (member key '(:sequential :parallel :repeat :goal :action)))))
		      for next-input-state = input-state then his-output-state
		      for next-output-state = (when last output-state)
                      for (his-stuff his-plan-structure his-output-state) = (do-next-level thing key next-input-state next-output-state)
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
			 (rebuilt-statement (if (compile-without-state the-binding) the-binding `(predication-maker '(in-state ,the-binding ,input-state)))))
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
                 (:trace (list (list `(prog1 t (when *method-tracing*
                                                 (format t "~%~vtIn ~a, " (* 2 ji::*rule-depth*) ',method-name)
                                                 (format t ,@stuff))))
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



(defun process-post-conditions (assertions output-state &optional support)
  (when assertions
    (if support
        (loop for assertion in assertions
	      collect `(tell [in-state ,assertion ,output-state]
                             ,@(when support
                                 `(:justification ,support))))
    `((prog1 t
	,@(loop for assertion in assertions collect `(tell [in-state ,assertion ,output-state])))))))

(defun process-assertions (method-name assertions input-state)
  (labels ((do-one (assertion)
	     (cond
	       ;; special cases for debugging
	       ((and (listp assertion) (not (predication-maker-p assertion)) (eql (first assertion) :break))
		`(prog1 t (break ,@(rest assertion))))
               ((and (listp assertion) (not (predication-maker-p assertion)) (eql (first assertion) :trace))
                `(prog1 t (when *method-tracing*
                            (format t "~%~vtIn ~a, " (* 2 ji::*rule-depth*) ',method-name)
                            (format t ,@(rest assertion)))))
	       ((and (listp assertion) (predication-maker-p assertion) (eql (predication-maker-predicate assertion) 'or))
	        (with-predication-maker-destructured (&rest assertions) assertion
		  (loop for assertion in assertions
		        collect (do-one assertion) into processed-assertions
		        finally (return `(predication-maker '(or ,@processed-assertions))))))
	       ((and (listp assertion) (not (predication-maker-p assertion))) assertion)
	       ((compile-without-state assertion) assertion)
	       (t `(predication-maker '(in-state ,assertion ,input-state))))))
    (loop for thing in assertions collect (do-one thing))))


(defun process-guards (method-name assertions input-state)
  (loop for assertion in assertions
        if (and (predication-maker-p assertion) (eql (predication-maker-predicate assertion) 'unknown))
        collect (second (predication-maker-statement assertion)) into unknown-guards
      else collect assertion into other-guards
      finally (return (append (loop for assertion in (process-assertions method-name unknown-guards input-state)
                                  collect `(predication-maker '(not (predication-maker '(known ,assertion)))))
                              (process-assertions method-name other-guards input-state)))))



(defun is-pretty-binding (assertion)
  (cond
   ((and (predication-maker-p assertion)
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
    t)
   ((listp assertion)
    (and (logic-variable-maker-p (first assertion))
         (eql (length assertion) 2)))
   (t nil)))

(defun de-prettify-binding (assertion)
  (flet ((process-path (list-of-strings)
           (loop for thing in list-of-strings
               if (char-equal (aref thing 0) #\?)
               collect (ji::make-logic-variable-maker (intern thing))
               else collect (intern thing))))
    (cond
     ((predication-maker-p assertion)
      (with-predication-maker-destructured  (path logic-variable) assertion
        (if (logic-variable-maker-p path)
            (let* ((name (logic-variable-maker-name path))
                   (exploded-path (explode-string name #\.))
                   (real-path (cons (ji::make-logic-variable-maker (intern (first exploded-path)))
                                    (process-path (rest exploded-path)))))
              (ji:make-predication-maker `(value-of ,real-path ,logic-variable)))
          (let ((expanded-path (process-path (explode-string path #\.))))
            (ji:make-predication-maker `(value-of ,expanded-path ,logic-variable))))))
     ((and (listp assertion) (eql (length assertion) 2) (logic-variable-maker-p (first assertion)))
      (destructuring-bind (logic-variable path) assertion
        (if (logic-variable-maker-p path)
            (let* ((name (logic-variable-maker-name path))
                   (exploded-path (explode-string name #\.))
                   (real-path (cons (ji::make-logic-variable-maker (intern (first exploded-path)))
                                    (process-path (rest exploded-path)))))
              (ji:make-predication-maker `(value-of ,real-path ,logic-variable)))
          (let ((expanded-path (process-path (explode-string path #\.))))
            (ji:make-predication-maker `(value-of ,expanded-path ,logic-variable)))))))))


(defun process-bindings (method-name assertions input-state)
  (let ((expanded-bindings (loop for assertion in assertions
			       collect (if (is-pretty-binding assertion)
					   (de-prettify-binding assertion)
					 assertion))))
    (process-assertions method-name expanded-bindings input-state)))



(defun process-prerequisites (method-name assertions input-state) (process-assertions method-name assertions input-state))

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

;;; As far as I can see, all the typing forms
;;; are the simple (thing type) so there might not
;;; need be an escape hatch for more complex forms
;;; Except that it allows break forms
(defun process-typing (method-name forms)
  (loop for form in forms
      if (and (listp form) (eql (first form) :break))
      collect `(prog1 t (break ,@(rest form)))
      else if (and (listp form) (eql (first form) :trace))
      collect `(prog1 t (when *method-tracing*
                          (format t "~%~vtIn ~a, " (* 2 ji::*rule-depth*) ',method-name)
                          (format t ,@(rest form))))
      else if (and (listp form) (= (length form) 2))
      collect (destructuring-bind (thing type) form
                (ji:make-predication-maker `(object-type-of ,thing ,type)))
      else collect form))

(defun mentioned-in? (lv-maker set-of-forms)
  (let ((name (if (symbolp lv-maker) lv-maker (logic-variable-maker-name lv-maker))))
    (labels ((in? (form)
               (cond
                ((logic-variable-maker-p form)
                 (if (eql name (logic-variable-maker-name form))
                     (return-from mentioned-in? t)
                   nil))
                ((predication-maker-p form)
                 (loop for term in (predication-maker-statement form)
                     do (in? term)))
                ((listp form)
                 (loop for term in form do (in? term)))
                ((eql name form)
                 (return-from mentioned-in? t))
                (t nil))))
      (in? set-of-forms))))

(defun bound-in? (lv-maker set-of-forms)
  (let ((name (logic-variable-maker-name lv-maker)))
    (loop for form in set-of-forms
        when (and (predication-maker-p form)
                  (member (predication-maker-predicate form) '(unify value-of))
                  (with-predication-maker-destructured (path value) form
                    (declare (ignore path))
                    (and (logic-variable-maker-p value)
                         (eql (logic-variable-maker-name value) name))))
        do (return-from bound-in? t))
      nil))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; defattack-method: The Macro for defining attack planning methods
;;;
;;; This takes the declarative PDDL style definition of a HTM planning method
;;; and translates it into a Joshua backward chaining rule
;;;
;;; Does a modest amount of analysis to figure out where the type
;;; constraints can be placed.
;;;
;;; Also does a modest amount of analysis to find logic-variables that are introduced but never reference
;;; and ones that are referenced but never defined.
;;;
;;; Allows one to refer to parts of data-structures through use of "dotted-path" notation
;;;  e.g.  ?foo.bar.baz.  Whenever one of these is found a binding of the form [value-of (?foo bar bar) ?lv-xxx]
;;; is generated and all references to ?foo.bar.baz are replaced by ?lv-xxx.  This is just a notational convenience.
;;; If ?foo.bar.baz is frequently referenced, it's easier to make an explicit binding in the bindings section.
;;; These implicit bindings are placed just in front of the first reference to ?foo.bar.baz.
;;;
;;; The order of the generated code:
;;; Early typing: typing that only references the inputs
;;; Bindings:
;;;   Implicit bindings in the bindings code
;;;   Implicit bindings in the typing code
;;;   The rest of the explicit bindings
;;; Guards (an idea to consider is to move guards that only refer to the inputs
;;;         to the front as we do with typing)
;;; Typing: Types that refer to things other than the inputs
;;; Implicit bindings reference by the prerequisites
;;; Prerequisites
;;; Implicit bindings in the plan
;;; The sub-goals and actions
;;; Implicit bindings in the post-conditions
;;; Postconditions
;;; Code to unify the plan variable with the plan data-structure
;;;
;;; Bindings can include any predication that would have the effect of binding some variable
;;; But there is a simplified notation when you just want to bind a variable to the value
;;; indicated by a dotted-path.  In that case, you can just use a list of length 2
;;; with the variable coming first and the path second.
;;; Fix: When you use this simplified notation and they chain, for example:
;;; (?a ...) (? ?a.xxx) this screws up the ordering, but no when you use
;;; explicit value-of assertions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-attack-methods* nil)
(defparameter *compile-for-debugging* t)

(defmacro defattack-method (method-name &key to-achieve
					     (input-state `(logic-variable-maker ,(intern (string-upcase "?input-state"))))
					     (output-state `(logic-variable-maker ,(intern (string-upcase "?output-state"))))
					     bindings
					     guards
					     typing
					     prerequisites
					     plan
					     post-conditions
                                             output-variables ;; Marks that variables in the to-achieve that are bound during execution
                                             attack-identifier
					  )
  (setq bindings (loop for thing in bindings
                     if (and (listp thing) (eql (first thing) :trace))
                     collect `(prog1 t (when *method-tracing*
                                         (format t "~%~vtIn ~a " (* 2 ji::*rule-depth*) ',method-name)
                                         (format t ,@(rest thing))))
                     else collect thing))
  (let* ((plan-variable `(logic-variable-maker ,(gensym "?PLAN")))
         (real-head `(predication-maker '(achieve-goal ,to-achieve ,input-state  ,output-state ,plan-variable)))
         (rebuilt-plan-structure (rebuild-plan-structure method-name plan input-state output-state))
         )
    ;; Pull out all typing that refers only to the inputs
    ;; And then leave the rest as late-typing.
    ;; This makes the first category act as prerequisites because they will be the first thing checked.
    ;; The reason for constraining them to only refer to inputs is that the generate code is an [objec-type-of xxx yyy]
    ;; form and if xxx is an unbound variable, this will successively bind xxx to all possible objects of type yyy
    ;; which isn't what we intended for a typing statement.  This requires us to declare any variable in the to-achieve
    ;; form that won't be bound as an "output".  That's probably a good thing to do anyhow, rather than just have it in a comment.
    (let ((usage-map (build-usage-map to-achieve bindings typing guards prerequisites post-conditions plan output-variables)))
      (perform-usage-checks usage-map method-name))
    (multiple-value-bind (early-typing late-typing)
        (loop for type in typing
            for variable = (first type)
            if (and (eql variable :break) (loop for var in (rest (rest type)) thereis (mentioned-in? var real-head)))
            collect type into early
            else when (and (mentioned-in? variable real-head) (not (member (logic-variable-maker-name variable) output-variables :key #'logic-variable-maker-name)))
            collect type into early
            else collect type into late
            finally (return (values early late)))
      ;; First find all implicit bindings i.e. things of the form ?foo.bar.baz and note where the first reference occurs
      ;; Also for each generate a new logic-variable-maker
      (multiple-value-bind (all-refs hidden-bindings-alist) (find-hidden-bindings guards prerequisites post-conditions late-typing plan bindings)
        ;; (format t "~%All refs: ~a~%Binding Alist: ~{~a~^~%~}" all-refs hidden-bindings-alist)
        (destructuring-bind (goals-to-achieve plan-structure thing) (or rebuilt-plan-structure (list nil nil nil))
          (declare (ignore thing))
          (setq plan-structure (substitute-hidden-bindings plan-structure all-refs))
          (push `(list :attack-identifier ',attack-identifier :method-name ',method-name) (rest (rest plan-structure)))
          `(eval-when (:load-toplevel :execute)
             (pushnew ',method-name *all-attack-methods*)
             ;; Now generate the backward rule
             ;; Note that by this time, any dotted notation in a binding form
             ;; will have been removed so the process-bindings code can be simplified.
             (defrule ,method-name (:backward)
               then ,real-head
               if [and;;; -*- Mode: LISP
                   ,@(process-typing method-name early-typing)
                   ,@(process-assertions method-name (merge-and-substitute-hidden-bindings bindings all-refs hidden-bindings-alist 'bindings) input-state)
                   ,@(merge-and-substitute-hidden-bindings (process-guards method-name guards input-state) all-refs hidden-bindings-alist 'guards)
                   ,@(merge-and-substitute-hidden-bindings (process-typing method-name late-typing) all-refs hidden-bindings-alist 'typing)
                   ,@(merge-and-substitute-hidden-bindings (process-prerequisites method-name prerequisites input-state) all-refs hidden-bindings-alist 'prerequsities)
                   ,@(merge-and-substitute-hidden-bindings goals-to-achieve all-refs hidden-bindings-alist 'plan)
                   ,@(merge-and-substitute-hidden-bindings (process-post-conditions post-conditions output-state) all-refs hidden-bindings-alist 'post-conditions)
                   ,@(when (null rebuilt-plan-structure)
                       `((unify ,input-state ,output-state)))
                   (unify ,plan-variable ,plan-structure)
                   ])))))))






;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dealing with dotted notation
;;; Expand into a binding of a new variable
;;; and replace all references
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; To do:
;;; Keep a list of all bindings and make sure you.
;;; don't make an entry if it's already there
;;; need to distinguish what you need to substitute vs
;;; what new bindings need to be introduced for each category
;;; Because this records the first mention of each variable it's important
;;; that the scanning happens in the same order as the generated code, which is:
;;;
;;; Early typing that depends only input variables.
;;; bindings
;;; guards
;;; Late typing that might apply to anything
;;; Prerequisites
;;; Goals to achieve
;;; Post-Conditions
;;; Plan-structure that is the "return value"

;;; Also when handling bindings, there is a special concern not to create
;;; a binding for a simple value-of of or (?variable ?path) binding
;;; (which the second is just syntactic sugar for the first)
;;; so as not to create a superfluous binding that would occur out of order.

(defun find-hidden-bindings (guards prerequisites post-conditions typing plan bindings)
  (let ((bindings-by-set-type nil) (master-alist nil))
    (labels ((do-one (form set-type)
               (cond
                ((and (predication-maker-p form)
                      (eql (predication-maker-predicate form) 'value-of))
                 (when  (not (eql set-type 'bindings))
                   ;; don't scan value-of forms if we're doing bindings
                   (with-predication-maker-destructured (slot value) form
                     (declare (ignore value))
                     (do-one slot set-type))))
                ((predication-maker-p form)
                 (do-one (predication-maker-statement form) set-type))
                ((logic-variable-maker-p form)
                 (do-one (logic-variable-maker-name form) set-type))
                ((and (listp form) (= (length form) 2) (eql set-type 'bindings))
                 ;; if it's the short syntax and we're doing bindings, then do nothing
                 )
                ((listp form)
                 (loop for token in form do (do-one token set-type)))
                ((and (symbolp form) (find #\. (string form) :test #'char-equal))
                 ;; master-alist holds bindings across everything to avoid duplication
                 ;; Bindings-By-Set-Type is an Alist set-typeed by the name of the set.  It only
                 ;; gets an entry if this was a new symbol
                 (let ((entry (assoc set-type bindings-by-set-type)))
                   (unless entry
                     (setq entry (list set-type nil))
                     (push entry bindings-by-set-type))
                   (unless (member form master-alist :key #'first :test #'equal)
                     ;; it's a new symbol
                     (let ((pair (list form (ji:make-logic-variable-maker (make-name '?lv)))))
                       ;; add it to the master alist
                       (push pair master-alist)
                       ;; and to the alist of new entries for this set-type
                       (push pair (second entry)))))))))
      (loop for binding in bindings do (do-one binding 'bindings))
      (loop for guard in guards do (do-one guard 'guards))
      (loop for type in typing do (do-one type 'typing))
      (Loop for prereq in prerequisites do (do-one prereq 'prerequisites))
      (loop for postcon in post-conditions do (do-one postcon 'post-conditions))
      (loop for plan-element in plan do (do-one plan-element 'plan))
      )
    ;; Reverse the entries so that they are in the order of occurence
    (loop for entry in bindings-by-set-type
        do (setf (second entry) (nreverse (second entry))))
    (values master-alist bindings-by-set-type)))

(defun normal-binding? (form)
  (or (and (predication-maker-p form)
           (eql (predication-maker-predicate form) 'value-of))
      (and (listp form)
           (= (length form) 2)
           (logic-variable-maker-p (first form)))))

;;; Put the hidden bindings in line just before the first usage
;;; Then substitute the hidden-variables into each form
(defun merge-and-substitute-hidden-bindings (set-of-stuff reference-alist bindings-by-set-type set-type)
  ;; (break "~{~a~^, ~}~%~a~%~{~a~^,~}~%~a" set-of-stuff reference-alist bindings-by-set-type set-type)
  (let ((bindings-for-set-type (second (assoc set-type bindings-by-set-type))))
    (cond
      ((and (null reference-alist) (eql set-type 'bindings))
       (loop for thing in set-of-stuff
             if (normal-binding? thing)
               collect (de-prettify-binding thing)
             else collect thing))
      ((null reference-alist) set-of-stuff)
      ((and (null bindings-for-set-type) (eql set-type 'bindings))
       (loop for thing in set-of-stuff
             if (normal-binding? thing)
               collect (de-prettify-binding thing)
             else collect (substitute-hidden-bindings thing reference-alist)))
      ((null bindings-for-set-type)
       (substitute-hidden-bindings set-of-stuff reference-alist))
      (t (let ((already-emitted nil))
           ;; loop over the forms
           ;; for each check all the implicit bindings
           ;; and if it's already been emitted skip it
           ;; otherwise if it's in the form, emit it and remember that it's been emitted
           (loop for thing in set-of-stuff
                 append (loop for (implicit-binding lv) in bindings-for-set-type
                              when (and (mentioned-in? implicit-binding thing)
                                        (not (member lv already-emitted)))
                                collect (de-prettify-binding (ji:make-predication-maker `(value-of ,implicit-binding ,lv)))
                                and do (push lv already-emitted))
                 if (normal-binding? thing)
                   collect (de-prettify-binding thing)
                 else collect (substitute-hidden-bindings thing reference-alist)))))))

(defun substitute-hidden-bindings (set-of-stuff reference-alist)
  (labels ((do-one (form)
             (cond
              ((and (predication-maker-p form) (eql (predication-maker-predicate form) 'value-of))
               (with-predication-maker-destructured (slot value) form
                 (ji:make-predication-maker
                  (list (predication-maker-predicate form)
                        (explode slot #\.)
                        (do-one value)))))
              ((predication-maker-p form)
               (ji:make-predication-maker
                (loop for token in (predication-maker-statement form)
                    collect (do-one token))))
              ((and (logic-variable-maker-p form) (find #\. (string (logic-variable-maker-name form)) :test #'char-equal))
               (let* ((entry (assoc (logic-variable-maker-name form) reference-alist)))
                 (second entry)))
              ((logic-variable-maker-p form) form)
              ((listp form)
               (loop for token in form collect (do-one token)))
              ((and (symbolp form) (find #\. (string form) :test #'char-equal))
               (let* ((entry (assoc form reference-alist)))
                 (second entry)))
              (t form))))
    (do-one set-of-stuff)
    ))

;;; Just a convenience for doing most of the substitutions all at once

(defun substitute-all-hidden-bindings (prerequisites post-conditions typing bindings plan reference-alist)
  (values
   (substitute-hidden-bindings prerequisites reference-alist)
   (substitute-hidden-bindings post-conditions reference-alist)
   (substitute-hidden-bindings typing reference-alist)
   (substitute-hidden-bindings bindings reference-alist)
   (substitute-hidden-bindings plan reference-alist)
   ))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Checking for unbound variables and unused variables
;;;
;;; Rules:
;;; 1) Variables defined in the head should be referenced in bindings, pre-conditions, post-conditions or plan
;;; 2) Variables defined in bindings should be referenced in pre-reqs, post-conditions or plan or another binding
;;;    Variables referenced in the bindings should be defined in the head or another binding
;;; 3) Variable referenced in pre-reqs should have been defined in head or bindings or another pre-req
;;;    Variables defined in pre-reqs should be referenced in plan or post-conditon
;;; 4) Variables in post-conditions, or plan should have been in head or bindings (or pre-requisites)
;;;    Within the plan a new variable might be introduced but that's OK if it's used later in the plan
;;;
;;; FIX:To be addressed: An output variable in the head, isn't a def its a ref that should be defined somewhere later on
;;;  All the downstream sets with a def should check for a ref in the head.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass usage-record ()
  ((variable-name :accessor variable-name :initarg :variable-name)
   (ref :accessor ref :initarg :ref :initform nil)
   (def :accessor def :initarg :def :initform nil)))

(defmethod print-object ((record usage-record) stream)
  (format stream "#<usage ~a ref ~a def ~a>" (variable-name record) (ref record) (def record)))

(eval-when (:compile-toplevel :load-toplevel)
  (defparameter *set-names* '(head bindings guards prerequisites plan post-conditions)))

(defmacro compiler-warn (format-string &rest args)
  #+allegro
  `(compiler::warn ,format-string ,@args)
  #+sbcl
  `(sb-c:compiler-warn  ,format-string ,@args))

;;; The head is special: Any ref in the head should be def'd in the body
;;; All others anything def'd should be checked against all followers plus the head.
;;; Fix: I use compiler::warn here which is the right thing for ACL, need to shadow warn
;;; and import the right thing as warn for each implementation (mainly S-BCL).
(defun perform-usage-checks (alist method)
  (let* ((head (second (assoc 'head alist)))
         (bindings (second (assoc 'bindings alist)))
         (typing (second (assoc 'typing alist)))
         (plan (second (assoc 'plan alist)))
         (guards (second (assoc 'guards alist)))
         (prerequisites (second (assoc 'prerequisites alist)))
         (post-conditions (second (assoc 'post-conditions alist))))
    (macrolet ((do-checks (set-name)
                 (let* ((position (position set-name *set-names*))
                        (before (subseq *set-names* 0 (1+ position)))
                        (after (subseq *set-names* position)))
                   `(loop for entry in ,set-name
                        for var = (variable-name entry)
                        for def = (def entry)
                        for ref = (ref entry)
                        do ,(cond
                             ((eql set-name 'head)
                              `(cond
                                (ref (unless (or def (check-for-over-sets var (list ,@after) 'def))
                                       (compiler-warn "In ~a, Variable ~a is referenced in the head but is not defined after"
                                                       method var)))
                                (def (unless (or ref (check-for-over-sets var (list typing ,@after) 'ref))
                                       (compiler-warn "In ~a, Varable ~a is defined in the head but is not referenced after"
                                                       method var)))))
                             (t `(cond
                                  (ref (unless (or def (check-for-over-sets var (list ,@before) 'def))
                                         (compiler-warn "In ~a, Variable ~a is referenced in the ~a but is not defined earlier" method var ',set-name)))
                                  (def (unless (or ref (check-for-over-sets var (list head ,@after) 'ref))
                                         (compiler-warn "In ~a, Variable ~a is defined in the ~a but is not used"
                                                        method var ',set-name))))))))))
      (labels ((check-for (variable-name set type)
                 (let ((entry (find variable-name set :key #'variable-name)))
                   (cond ((null entry) nil)
                         ((eql type 'def) (def entry))
                         ((eql type 'ref) (ref entry)))))
               (check-for-over-sets (variable-name sets type)
                 (loop for set in sets thereis (check-for variable-name set type))))
        ;; 1) for variables in the head, make sure that all variables are referenced
        (do-checks head)
        ;; 2) for variables in bindings, if it's defined make sure it's referenced somewhere
        ;; if it's reference make sure it was defined in the head.or in another binding.
        (do-checks bindings)
        ;; 3) Variables referenced in the prereqs should have been defined in the head, bindings or another prereq
        ;;    Variables defined in the prereqs should be referenced in the plan, post-conditions or another prereq
        (do-checks guards)
        (do-checks prerequisites)
        ;; 4) Variable referenced in plan should have defined in head, bindings, prereqs, or plan
        ;;    Variables defined in the plan should be used in the plan or the post-conditions
        (do-checks plan)
        ;; 5) Variables referenced in the post-conditions should have been defined in head, bindings, prerequs, plan or post-conditions
        ;;    Variables defined in the post-conditions should be used in the post-conditions
        (do-checks post-conditions)
        ))))

(defun build-usage-map (head bindings typing guards prerequisites post-conditions plan output-variables)
  ;; Do we really want to ignore the typing
  ;; or do we want to treat it as a usage
  ;; (declare (ignore typing))
  (let ((alist nil) (all-refs nil))
    (macrolet ((do-one (name)
                 `(multiple-value-bind (entry updated-all-ref)
                      (find-all-variables ,name ',name all-refs output-variables)
                    (push entry alist)
                    (setq all-refs updated-all-ref))))
      (do-one head)
      (do-one bindings)
      (do-one guards)
      (do-one prerequisites)
      (do-one typing)
      (do-one plan)
      (do-one post-conditions))
  alist))

(defun find-all-variables (set-of-stuff tag already-seen output-variables)
  (let ((answers nil))
    (labels ((do-one (stuff &optional predication-maker)
               (cond
                ((predication-maker-p stuff)
                 (do-one (predication-maker-statement stuff) (unless (eql tag 'head) stuff)))
                ((logic-variable-maker-p stuff)
                 (let ((string-of-name (string (logic-variable-maker-name stuff))))
                   (unless (search "anonymous" string-of-name :test #'string-equal)
                     (let* ((first-dot (position #\. string-of-name :test #'char-equal))
                            (symbol (if first-dot
                                        (intern (subseq string-of-name 0 first-dot))
                                      (intern string-of-name)))
                            (entry (find symbol answers :key #'variable-name))
;;;                            (abstract-variable (when predication-maker (corresponding-abstract-variable predication-maker stuff)))
;;;                            (predicate (when predication-maker (predication-maker-predicate predication-maker)))
;;;                            (is-output? (or (eql tag 'head)
;;;                                            (when predication-maker (lookup-predicate-output-variable predicate abstract-variable))))
;;;                            (is-new-locally (null entry))
                            )
                       ;; (format t "~%Var ~a Pred maker ~a Pred ~a Abs-var ~a Output? ~a" symbol predication-maker predicate abstract-variable is-output?)
                       (unless entry
                         (setq entry (make-instance 'usage-record :variable-name symbol))
                         (push entry answers))
                       ;; Maybe the logic should be simpler:
                       ;; Except for the head
                       ;; Any 2nd mention is a ref, Any 1st mention is a def
                       ;; For any normal predicate this seems true, it will bind the unbound variables.
                       ;; when pattern matching.
                       (cond
                        ((member symbol already-seen)
                         ;; a 2nd mention of an variable that is an output-variable of the predicate
                         ;; that's already defined in this set is taken to be a reference
                         ;; (unless (and (def entry) is-new-locally)
                         ;;   (setf (ref entry) t))
                         (if (member symbol output-variables :key #'logic-variable-maker-name)
                             (setf (def entry) t)
                           (setf (ref entry) t))
                         )
                        (t (push symbol already-seen)
                           ;; (if is-output?
                           ;;     (setf (def entry) t)
                           ;;   (setf (ref entry) t))
                           (cond ((eql tag 'head)
                                  (if (member symbol output-variables :key #'logic-variable-maker-name)
                                      (setf (ref entry) t)
                                    (setf (def entry) t)))
                                 (t (setf (def entry) t)))
                           ))))))
                ((and (listp stuff) (= (length stuff) 2) (eql tag 'bindings) (logic-variable-maker-p (first stuff))
                      (null (find #\. (string (logic-variable-maker-name (first stuff))))))
                 (let* ((name (logic-variable-maker-name (first stuff)))
                        (entry (find name answers :key #'variable-name)))
                   (unless entry
                     (setq entry (make-instance 'usage-record :variable-name name :def t))
                     (push entry answers))
                   (push name already-seen))
                 (do-one (rest stuff)) predication-maker)
                ((listp stuff)
                 (loop for thing in stuff do (do-one thing predication-maker))))))
      (do-one set-of-stuff))
    (values (list tag answers)
            already-seen)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-goal macro & achieve goal predicate
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-goals* nil)

(defmacro define-goal (name variables &key outputs)
  `(eval-when (:load-toplevel :execute :compile-toplevel)
     (pushnew ',name *all-goals*)
     (define-predicate ,name ,variables (ltms:ltms-predicate-model))
     (setf (gethash ',name *aplan-predicate-binding-map*) ',outputs)))

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
(define-predicate action-taken (action input-state output-state) (ltms:ltms-predicate-model))

(defun link-action (name arguments prior-state next-state)
  (let ((action (make-instance 'action
                  :role-name name
		  :action-name name
		  :arguments arguments
		  :prior-state prior-state
		  :next-state next-state)))
    (setf (next-action prior-state) action
	  (prior-action next-state) action)
    action))

(defun process-new-outputs (variable-list)
  (loop for (lv form) in variable-list
      collect `(unify ,lv ,form)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-action macro for declaratively definings actions
;;; in a PDDL like syntax
;;;
;;; Compiles the source form into a Joshua backward chaining rule
;;;
;;; Fix: Still needs to do the implicitly binding stuff in def-atttack-method
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-actions* nil)

(defmacro define-action (name variables &key bindings prerequisites post-conditions (define-predicate t) capecs outputs typing output-variables)
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
           (jusification-mnemonic (intern (string-upcase (format nil "prerequisites-satisfied-~a" name))))
	   (state-logic-variables (make-logic-variables '(input-state output-state)))
	   (capec-statements (loop for (victim capec-num cve-variable) in capecs
                                 collect `(predication-maker '(vulnerable-to-capec ,victim ,capec-num ,cve-variable))))
           (action-variable (first (make-logic-variables '(action))))
           (real-head (ji:make-predication-maker `(take-action [,name ,@logic-variables] ,@state-logic-variables ,action-variable))))
      (multiple-value-bind (early-typing late-typing)
          (loop for type in typing
              for variable = (first type)
              if (and (eql variable :break) (loop for var in (rest (rest type)) thereis (mentioned-in? var real-head)))
              collect type into early
              else when (and (mentioned-in? variable real-head)
                             (not (member (logic-variable-maker-name variable) outputs :key #'(lambda (thing) (logic-variable-maker-name (first thing)))))
                             (not (member (logic-variable-maker-name variable) output-variables :key #'logic-variable-maker-name)))
              collect type into early
              else collect type into late
              finally (return (values early late)))
        ;; First find all
        ;; implicit bindings i.e. things of the form ?foo.bar.baz and
        ;; note where the first reference occurs
        ;; Also for each generate a new logic-variable-maker
        (multiple-value-bind (all-refs hidden-bindings-alist) (find-hidden-bindings nil prerequisites post-conditions late-typing nil bindings)
          (destructuring-bind (input-state-variable output-state-variable) state-logic-variables
            `(eval-when (:compile-toplevel :load-toplevel :execute)
               (pushnew ',name *all-actions*)
               ,@(when define-predicate `((define-predicate ,name ,names (ltms:ltms-predicate-model))))
               ,@(loop for var in output-variables
                     for var-name = (string (logic-variable-maker-name var))
                     for stripped-name = (intern (subseq var-name 1))
                     collect `(record-predicate-output-variable ',name ',stripped-name))
               (defrule ,rule-name (:backward)
                 then ,real-head
                 if [and ,@(process-typing name early-typing)
                         ,@(merge-and-substitute-hidden-bindings (process-bindings name bindings input-state-variable) all-refs hidden-bindings-alist 'bindings)
                         ,@(merge-and-substitute-hidden-bindings (process-typing name late-typing) all-refs hidden-bindings-alist 'typing)
                         ,@(merge-and-substitute-hidden-bindings (process-prerequisites name prerequisites input-state-variable) all-refs hidden-bindings-alist 'prerequsities)
                         ,@capec-statements
                         ;; so at this point we've checked that the prerequisites are satisfied
                         (prog1 t
                           (when (unbound-logic-variable-p ,output-state-variable)
                             (unify ,output-state-variable
                                    (intern-state (intern (string-upcase (gensym "state-"))) ,input-state-variable)))
                           (let* ((action-taken-pred (tell [action-taken [,name ,@logic-variables] ,input-state-variable ,output-state-variable]
                                                           :justification :none))
                                  (justification (build-justification-from-backward-support ji::*backward-support*)))
                             (destructuring-bind (nothing true-stuff false-stuff unknown-stuff) justification
                               (declare (ignore nothing))
                               (justify action-taken-pred +true+ ',jusification-mnemonic true-stuff false-stuff unknown-stuff))
                             ,@(process-new-outputs outputs)
                             ,@(let* ((mnemonic (intern (string-upcase (format nil "action-taken-~A" name))))
                                      (justification-2 `(list ',mnemonic (list action-taken-pred))))
                                 (merge-and-substitute-hidden-bindings (process-post-conditions post-conditions output-state-variable justification-2)
                                                                       all-refs hidden-bindings-alist 'post-conditions))))
                         (unify ,action-variable (link-action ',name (list,@logic-variables) ,input-state-variable ,output-state-variable))
                         ]))))))))

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
