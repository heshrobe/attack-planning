;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)

(defun graph-an-attack-plan (plan &optional (stream *standard-output*) (orientation :vertical) (text-size :very-small) (action-only nil))
  (let ((*print-object-nicely* t))
    (declare (special *print-object-nicely*))
    (clim:with-text-size (stream :small)
    (clim:format-graph-from-root
     plan
     #'(lambda (step stream) (print-plan-object step stream text-size))
     (if action-only #'plan-inferior-action-only #'plan-inferior)
     :graph-type :my-graph
     :stream stream
     :merge-duplicates t
     :orientation orientation
     :arc-drawer #'(lambda (stream from-object to-object x1 y1 x2 y2 &rest drawing-options)
                     (declare (ignore from-object to-object))
                     (apply #'clim:draw-arrow* stream x1 y1 x2 y2 :from-head t :to-head nil
                            :ink clim:+blue+ drawing-options))))))

(defun print-plan-object (step stream &optional (text-size :very-small))
  (clim:with-text-size (stream text-size)
    (clim:with-drawing-options (stream :line-thickness 2)
      (let ((connective (first step)))
        (case connective
	  ((:sequential :parallel)
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+green+)
	     (clim:with-text-face (stream :bold)
	       (format stream "~A" (first step)))))
	  (:singleton
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+green+)
	     (clim:with-text-face (stream :bold)
	       (format stream "reduces to"))))
          (:goal (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+blue+)
                   (destructuring-bind (goal-type &rest values) (second step)
		     ;; total hack to reduce space consumption
		     ;; (let* ((arglist (ji::find-predicate-arglist goal-type)))
		     (format stream "Goal: ~A" goal-type)
		     (loop for value in values
			 do (format stream "~%~a" value)))))
          ((:action :repeated-action)
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+red+)
	     (clim:with-text-face (stream :bold)
	       (destructuring-bind (action-type &rest rest) (second step)
		 (format stream "~:[Do:~;Repeatedly:~] ~A~%~{~a~^~%~}" (eql connective :repeated-action) action-type rest))))))))))

(defun plan-inferior (step)
  (case (first step)
    ((:sequential :parallel :singleton)
     (rest step))
    (:goal (let ((plan (getf step :plan)))
	     (when plan
             (list plan))))
    ((:action :repeated-action) nil)))

;;; Fix if possible: There must be a simpler way to construct this recursion
(defun plan-inferior-action-only (step)
  (labels ((collect-actions-below (step)
	     (case (first step)
	       ((:sequential :parallel)
		(loop for thing in (rest step)
		    append (if (member (first thing) '(:action :repeated-action :sequential :parallel))
			       (list thing)
			     (collect-actions-below thing))))
	       (:singleton (collect-actions-below (second step)))
	       (:goal (let ((plan (getf step :plan)))
			(when plan
			  (case (first plan)
			    (:singleton
			     (if (member (first (second plan)) '(:action :repeated-action))
				 (rest plan)
			       (collect-actions-below (second plan))))
			    ((:sequential :parallel :action :repeated-action)
			     (list plan))
			    (otherwise (break "~a" plan))
			    ))))
	       ((:action :repeated-action) nil))))
    (collect-actions-below step)
    ))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type computer ()))

(clim:define-presentation-method clim:accept ((type computer) stream (view clim:textual-view) &key)
  (let ((answers nil))
    (ask [ltms:object-type-of ?m computer]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?m answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for m in answers
            do (clim:suggest (string (role-name m)) m)))
    ))

(clim:define-presentation-method clim:present (item (type computer) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type desirable-property ()))

(clim:define-presentation-method clim:present (object (type desirable-property) stream (view clim:textual-view) &key)
  (write-string (string object) stream))

(clim:define-presentation-method clim:accept ((type desirable-property) stream (view clim:textual-view) &key)
  (let ((answers nil))
    (ask [desirable-property-of ? ?property]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?property answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for property in answers
            do (clim:suggest (string property) property)))))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type computer-resource (computer)))

(defun resources-on-machine (machine)
  (let ((answers nil))
    (ask `[value-of (,machine resources) ?resource]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?resource answers)))
    answers))

(clim:define-presentation-method clim:accept ((type computer-resource) stream (view clim:textual-view) &key)
  (let ((machine (clim:with-presentation-type-parameters (computer-resource type) (values computer))))
    (let ((answers (resources-on-machine machine)))
      (clim:completing-from-suggestions (stream :partial-completers '(#\-))
        (loop for resource in answers
              do (clim:suggest (string (role-name resource)) resource))))))

(clim:define-presentation-method clim:present (item (type computer-resource) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type attacker ()))

(clim:define-presentation-method clim:accept ((type attacker) stream (view clim:textual-view) &key)
  (let ((answers nil))
    (ask [ltms:object-type-of ?m attacker]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?m answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for m in answers
            do (clim:suggest (string (role-name m)) m)))
    ))

(clim:define-presentation-method clim:present (item (type attacker) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(define-aplan-command (com-load-model :name t :menu t)
    ((pathname 'clim:pathname))
  (clear)
  ;; clear makes the current version of *everywhere* invalid
  ;; by removing its parts.
  (setq *everywhere* (make-everywhere))
  (ji:with-joshua-readtable
      (load pathname)))

(define-aplan-command (com-find-plans :name t :menu t)
    ((computer 'computer)
     (property 'desirable-property :default 'performance)
     (resource `(computer-resource ,computer))
     &key (attacker 'attacker))
  (multiple-value-bind (answers final-states) (do-it :property property :machine computer :attacker attacker :resource resource)
    (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure )))
      (clim:with-text-face (stream :bold)
	(clim:with-text-size (stream :large)
	  (format stream "~%There are ~d plans" (length answers))
          ;; McClim seems to need this
          (force-output stream)
          )))
    (let ((collector (attack-plan-collector clim:*application-frame*)))
      (setf (attack-plans collector) answers
	    (final-states collector) final-states
	    (initial-state collector) *initial-state*
	    (merged-attack-plan collector) (merge-attack-plans answers)))))

(define-aplan-command (com-show-plan :name t :menu t)
    ((which 'integer)
     &key (orientation '(clim:member-alist (("horizontal" . :horizontal) ("vertical" . :vertical))) :default :vertical)
     (pdf? 'clim:boolean :default nil :prompt "Generate to a pdf file")
     (file-name 'clim:pathname)
     (text-size '(clim:member :very-small :small :normal :large :very-large))
     (actions-only 'clim:boolean :default nil :prompt "Only show actions?")
     )
  (let ((plan (nth which (attack-plans (attack-plan-collector clim:*application-frame*)))))
    (terpri)
    (when plan
      (flet ((body (stream)
               (clim:with-text-face (stream :bold)
                 (clim:with-text-size (stream text-size)
                   (format stream "~%Attack Plan ~d~%" which)
                   (graph-an-attack-plan plan stream orientation text-size actions-only))))
	     (make-pathname-with-type (file-name type)
	       (merge-pathnames (make-pathname :type type) file-name)))
        (cond
	 (pdf?
	  (let* ((real-name (translate-logical-pathname file-name))
		 (ps-pathname (make-pathname-with-type real-name "ps"))
		 (pdf-pathname (make-pathname-with-type real-name "pdf"))
		 (command (format nil "pstopdf ~a -o ~a " ps-pathname pdf-pathname)))
	    (with-open-file (file ps-pathname :direction :output :if-exists :supersede :If-does-not-exist :create)
	      (clim:with-output-to-postscript-stream (stream file)
		(body stream)))
	    #+Allegro
	    (excl:run-shell-command command :wait t :show-window :normal)
	    #+sbcl
	    (uiop:run-program command)
	    (delete-file ps-pathname)))
	 (t
          (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure)))
            (multiple-value-bind (x y) (clim:stream-cursor-position stream)
              (clim:stream-set-cursor-position stream x (+ y 10))
              (setf (clim:window-viewport-position stream) (values x (+ y 10))))
            (body stream))))
        (terpri)))))

(defun graph-merged-plans (top-level-goals &optional stream (direction :vertical) (text-size :very-small))
  (let ((*print-object-nicely* t))
    (clim:with-text-size (stream text-size)
      (clim:format-graph-from-roots
       top-level-goals
       #'print-merged-plan-object
       #'merged-plan-inferior
       :graph-type :my-graph
       :merge-duplicates t
       :maximize-generations nil
       :center-nodes t
       :generation-separation 15
       :within-generation-separation 10
       :stream stream
       :orientation direction
       :arc-drawer #'(lambda (stream from-object to-object x1 y1 x2 y2 &rest drawing-options)
		       (declare (ignore from-object to-object))
		       (apply #'clim:draw-arrow* stream x1 y1 x2 y2 :from-head t :to-head nil
			      :ink clim:+blue+ drawing-options))))))

(defmethod print-merged-plan-object ((goal attack-goal) stream)
    (clim:with-drawing-options (stream :line-thickness 2)
      (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+blue+)
        (destructuring-bind (goal-type &rest rest) (goal-name goal)
          (format stream "~&Goal: ~A~%~{ ~a~^~%~}" goal-type rest)))))

(defmethod print-merged-plan-object ((action attack-action) stream)
    (clim:with-drawing-options (stream :line-thickness 2)
      (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+red+)
        (clim:with-text-face (stream :bold)
          (destructuring-bind (action-type &rest rest) (action-name action)
            (format stream "~&~:[Do:~;Repeatedly~] ~A~%~{~a~^~%~}"
		    (typep action 'repeated-attack-action)
		    action-type rest))))))

(defmethod print-merged-plan-object ((plan attack-plan) stream)
  (clim:with-drawing-options (stream :line-thickness 2)
    (clim:surrounding-output-with-border (stream :shape :oval :ink clim:+green+)
      (clim:with-text-face (stream :bold)
	(let ((combinator (combinator plan)))
	  (format stream "~a" (case combinator
				((:sequential :parallel) combinator)
				(:singleton :reduces-to)
				(:otherwise (break "~a ~a" combinator plan)))))
        ))))

(defmethod print-merged-plan-object ((or-node plan-or-node) stream)
  (clim:with-drawing-options (stream :line-thickness 2)
    (clim:surrounding-output-with-border (stream :shape :oval :ink clim:+green+)
      (clim:with-text-face (stream :bold)
      (format stream "~&OR")))))


(defmethod merged-plan-inferior ((goal attack-goal)) (supporting-plans goal))

(defmethod merged-plan-inferior ((plan attack-plan)) (steps plan))

(defmethod merged-plan-inferior ((action attack-action)) nil)

(defmethod merged-plan-inferior ((or-node plan-or-node)) (supporting-plans or-node))

(define-aplan-command (com-show-merged-plans :name t :menu t)
    (&key (direction '(member :horizontal :vertical) :default :vertical)
	  (text-size '(member :small :very-small :normal :large) :default :very-small)
	  (pdf? 'clim:boolean :default nil :prompt "Generate to a pdf file")
	  (file-name 'clim:pathname))
  (flet ((body (stream)
	   (terpri)
	   (let ((goals (merged-attack-plan (attack-plan-collector clim:*application-frame*))))
	     (clim:with-text-size (stream :large)
	       (format stream "~%Merged Plans ~%"))
	     (clim:with-text-size (stream :small)
	       (graph-merged-plans goals stream direction text-size))
	     (terpri)))
	 (make-pathname-with-type (pathname type)
	   (merge-pathnames (make-pathname :type type) pathname)))
    (cond
     (pdf?
      (let* ((real-name (translate-logical-pathname file-name))
	     (ps-pathname (make-pathname-with-type real-name "ps"))
	     (pdf-pathname (make-pathname-with-type real-name "pdf"))
	     (command (format nil "pstopdf ~a -o ~a " ps-pathname pdf-pathname)))
      (with-open-file (file ps-pathname :direction :output :if-exists :supersede)
	(clim:with-output-to-postscript-stream (stream file)
	  (body stream)
	  ))
      #+Allegro
      (excl:run-shell-command command :wait t :show-window :normal)
      #+sbcl
      (uiop:run-program command)
      (delete-file ps-pathname)
      ))
     (t
      (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure)))
	(multiple-value-bind (x y) (clim:stream-cursor-position stream)
	  (clim:stream-set-cursor-position stream x (+ y 10))
	  (setf (clim:window-viewport-position stream) (values x (+ y 10))))
	(body stream))))))




;;; surgery on merged plans

;; A goal all of whose supporting plans support only this goal
;; which must be true by definition
;; and for each supporting plan they have a unique subgoal which only supports the plan
;; then the goal and all the subgoals of the subplans may be merged

(define-aplan-command (com-simplify-merged-plan :name t :menu t)
                    ()
  (clean-up-plan (merged-attack-plan (attack-plan-collector clim:*application-frame*))))

(define-aplan-command (com-clear-screen :name t :menu t)
    ()
  (clim:window-clear (clim:get-frame-pane clim:*application-frame* 'attack-structure)))

(define-aplan-command (com-clear-model :name t :menu t)
    ()
  (clear))

(define-aplan-command (com-dump-merged-plans-to-json :name t :menu t)
    (&key (file-name 'clim:pathname))
  (let ((goals (merged-attack-plan (attack-plan-collector clim:*application-frame*))))
    (dump-plan-to-file goals file-name)
    ))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Graphing the capability hiearchy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun get-root-capabilities (authorization-pool-name)
  (let* ((pool (object-named authorization-pool-name))
	 (capabilities (capabilities pool)))
    (loop for capability in capabilities
	when (null (more-general capability))
	collect capability)))


(defun graph-capabilities (authorization-pool-name &optional (stream *standard-output*))
  (let ((roots (get-root-capabilities authorization-pool-name)))
    (clim:format-graph-from-roots
     roots
     #'(lambda (object stream) (format stream "~a" (role-name object)))
     #'more-specific
     :merge-duplicates t
     :stream stream)
    (values)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Graphing Action Sequence
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun graph-states-and-actions (initial-state &key (orientation :horizontal) (stream *standard-output*))
  (clim:format-graph-from-roots
   (list initial-state)
   #'print-action-or-state
   #'child-of-action-or-state
   :orientation orientation
   :stream stream
   :merge-duplicates t))


(defmethod Print-action-or-state ((action action) stream)
  (clim:surrounding-output-with-border (stream :shape :oval)
    (format stream "~a ~{~%~a~^~}"
	    (action-name action)
	    (arguments action))))

(defmethod Print-action-or-state ((state state) stream)
  (clim:surrounding-output-with-border (stream :shape :rectangle)
    (format stream "~a" (state-name state))))

(defmethod child-of-action-or-state ((state state))
  (let ((next-action (next-action state)))
    (if next-action
	(list next-action)
	(loop for successor in (successors state)
	    append (child-of-action-or-state successor))))
  )

(defmethod child-of-action-or-state ((action action))
  (list (next-state action))
  )
