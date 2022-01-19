;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)



;;; for editor support

;;; This tells emacs how to kill defattack-method forms (fi:kill-definition C-c C-y)
#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'defattack-method)))
  `(undefrule ',fspec))

;;; This tells emacs how to kill define-action forms (fi:kill-definition C-c C-y)
#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'define-action)))
  `(undefrule ',fspec))

#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'define-goal)))
  `(progn (undefine-predicate ',fspec)
          (remhash ',fspec *aplan-predicate-binding-map*)
          (setq *all-goals* (remove ',fspec *all-goals*))))

#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'define-aplan-predicate)))
  `(undefine-predicate ',fspec))

;;; This tells emacs how to kill define-aplan-object forms (fi:kill-definition C-c C-y)
#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'define-aplan-object)))
  `(ji::undefine-object-type ',fspec)
  )

#+allegro
(defparameter *aplans-predicates* '(value-of named-component object-type-of take-action in-state))

#+allegro
(defparameter *unused-predicates* nil)

#+allegro
(defun survey-predicates (&optional (stream *standard-output*))
  (let ((aplan (find-package :aplan)))
    (flet ((do-one-set (name the-set)
             (format stream "~2%Doing ~a" name)
             (let ((preds nil))
               (loop for pred in the-set
                   when (and (eql (symbol-package pred) aplan)
                             (not (member pred *aplans-predicates*)))
                   do (push pred preds))
               (setq preds (sort preds #'string-lessp :key #'string))
               (loop for pred in preds
                   do (print pred stream)
                      (let ((callers nil))
                        (loop for thing in (lep::who-calls pred)
                            for real-thing = (is-valid-caller pred thing)
                            when real-thing
                            do (pushnew real-thing callers))
                        (cond
                         ((null callers)
                          (pushnew pred *unused-predicates*)
                          (format stream " No callers"))
                         (t
                          (loop for caller in callers
                              do (format stream "~%~5t~a" caller)))))))))
      (do-one-set 'predicates *all-aplan-predicates*)
      (do-one-set 'goals *all-goals*)
      (do-one-set 'actions *all-actions*))))

(defparameter *bad-callers* '(define-action achieve-goal take-action in-state action-taken consistent-state))

(defun is-valid-caller (pred thing)
  (when (and (listp thing) (eql (second thing) :operator))
    (let* ((token (top-level-of (first thing))))
      (when (and (symbolp token)
                 (not (member pred *bad-callers*))
                 (not (member token *bad-callers*))
                 (not (invalid-caller-of-action token pred))
                 (not (caller-generated-by-joshua token)))
        token))))

(defun invalid-caller-of-action (caller action)
  (eql caller (intern (string-upcase (format nil "do-~A" ACTION)))))

(defun caller-generated-by-joshua (caller)
  (when (or (symbolp caller) (stringp caller))
    (setq caller (string caller))
    (or (search "FULL-MATCHER" caller)
        (search "SEMI-MATCHER" caller)
        (search "MERGER" caller)
        (search "INSTALL-PREDICATE" caller)
        )))

(defun top-level-of (form)
  (labels ((next-level (thing)
             (cond
              ((symbolp thing) (return-from top-level-of thing))
              ((listp thing) (next-level (second thing)))
              ((stringp thing) nil))))
    (next-level form)))
