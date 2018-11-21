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

(defun rebuild-plan-structure (plan-structure)
  ;; as we traverse the plan-structure tree we accumulate the list structure
  ;; of the plan and push
  (labels ((do-next-level (structure connective)
             ;; each level should either be a :sequential/:parallel
             ;;  or a :goal/:plan pair
             ;;  or maybe a :action item (to be dealth with later)
             (destructuring-bind (key . stuff) structure
               (case key
                 ((:sequential :parallel)
                  (loop for thing in stuff
                      for (his-sub-goals his-plan-structure) = (do-next-level thing key)
                      append his-sub-goals into sub-goals
                      collect his-plan-structure into plan-structure
                      finally (return (list sub-goals `(list ,key ,@plan-structure)))))
                 ((:goal :plan)
                  (let* ((goal (getf structure :goal))
                         (plan (getf structure :plan (ji::make-logic-variable-maker (gentemp (string-upcase "?plan-") ))))
                         (rebuilt-statement (attach-logic-variable-to-predication-maker goal plan)))
                    (list (list rebuilt-statement)
                          (if (null connective)
                              `(list :singleton
                                     (list :goal ,(fixup-syntax (predication-maker-statement goal))
                                           :plan ,plan))
                            `(list :goal ,(fixup-syntax (predication-maker-statement goal))
                                   :plan ,plan)))))
                 ((:action :repeated-action)
                  (list 
                   ;; The action requires no further sub-goaling
                   nil
                   (if (null connective)
                       `(list :singleton
                              (list ,key ,(fixup-syntax (predication-maker-statement (first stuff)))))
                     `(list ,key ,(fixup-syntax (predication-maker-statement (first stuff))))))))))
           (fixup-syntax (predication-maker-statement)
             `(list
               ,@(loop for thing in predication-maker-statement
                     collect (typecase thing
                               (logic-variable-maker thing)
                               (symbol `',thing)
                               (list (fixup-syntax thing)))))))
    (do-next-level plan-structure nil)))

      
						
(defmacro defattack-method (method-name &key to-achieve prerequisites typing bindings post-bindings plan)
  (let* ((plan-variable `(logic-variable-maker ,(gensym "?PLAN")))
         (real-head (attach-logic-variable-to-predication-maker to-achieve plan-variable)))
    (destructuring-bind (sub-goals plan-structure) (rebuild-plan-structure plan)
      `(defrule ,method-name (:backward)
         then ,real-head
         if [and ,@bindings
                 ,@typing
                 ,@prerequisites
                 ,@post-bindings
                 ,@sub-goals
                 (unify ,plan-variable ,plan-structure)
                 ]))))
