;;; -*- Mode: Lisp; package: aplan; readtable: joshua; syntax: joshua -*-

(in-package :aplan) 

;; (defvar *component-map* (make-hash-table))


(clim:define-application-frame aplan
  ()
  ((current-diagram :initform nil :accessor current-diagram)   ; the current system description under simulation
   (display-output-tick :initform 0 :accessor display-output-tick )
   (attack-plans :initform nil :accessor attack-plans)
   (merged-attack-plan :initform nil :accessor merged-attack-plan  )
   )
  (:top-level (aplan-top-level))
  (:menu-bar nil)
  (:panes
   ;; #-mcl
   ;; (title :title
   ;;        :max-height 28
   ;;        :display-string "APLAN") 
   (pointer :pointer-documentation 
	    :borders t
	    :height 12
            :max-height 12)
   (menu :command-menu 
	 :max-height '(3 :line)
         :display-function '(clim:display-command-menu :n-columns 6 :row-wise t)
         :scroll-bars nil
         :borders t)
   (interactor :interactor
	       :initial-cursor-visibility :off
	       :scroll-bars :vertical
	       :end-of-line-action :wrap
	       :borders t)   
   (attack-structure :application
		     #+sbcl :display-time #+allegro :display-after-command nil
		     :incremental-redisplay nil
		     :scroll-bars t
		     :borders t)
   )
  (:layouts
   (attack-viewing
    (clim:vertically ()
      ;; title
      (:fill attack-structure)
      pointer
      menu
      (.25 interactor))))
  (:command-definer define-aplan-command)
  ;; Note: McClim requires this to be a list
  ;; while Allegro's CLIM allows a bare symbol
  (:command-table (aplan)))


(defvar *editor* nil)
(defvar *process* nil)

(defun screen-size ()
  (let ((graft (clim:find-graft)))
    (clim:rectangle-size (clim:sheet-region graft))))

(defmethod aplan-top-level ((frame aplan) &REST OPTIONS)
  (let ((*package* (find-package (string-upcase "aplan"))))
    (ji:with-joshua-readtable
	(APPLY #'clim:default-frame-top-level
		frame
		:prompt ">"
		OPTIONS))))

(defun run-editor ()
  (#+allegro process-run-function #+sbcl sb-thread:make-thread
      #+allegro "Attack Planner"
    #'(lambda ()
	(multiple-value-bind (width height) (screen-size)
	  (setq *editor* (clim:make-application-frame 'aplan
						      :pretty-name "Attack Planner"
						      #-allegro :parent #-allegro (clim:find-port)
						      :width (floor (* .7 width))
						      :height (floor (* .8 height)))))
	(clim:run-frame-top-level *editor*))
    #+sbcl :name #+sbcl "Attack Planner"))

#+allegro
(clim-env::define-lisp-listener-command (com-start-aplan :name t)
                                        ()
                                        (run-editor))
#+mcclim
(clim-listener::define-listener-command (com-start-aplan :name t)
    ()
  (run-editor))
