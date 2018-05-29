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
   #-mcl
   (title :title
          :max-height 28
          :display-string "APLAN") 
   #-genera
   (pointer :pointer-documentation :borders t
	    :height '(1 :line)
            :max-height '(1 :line))
   (attacks :application
            :height .25 :width .5
            :redisply-after-commands t
            :incremental-redisplay t
            :display-function 'show-attacks
            :label "Attacks"
            :scroll-bars t
            :borders t)            
   (menu :command-menu 
	 :max-height '(3 :line)
         :height :compute
         :display-function '(clim:display-command-menu :n-columns 6 :row-wise t)
         :scroll-bars nil
         :borders t)
   (interactor :interactor
	       :max-height '(7 :line)
	       :min-height '(4 :line)
	       :initial-cursor-visibility :off
	       :scroll-bars :vertical
	       :end-of-line-action :wrap)
   
   (attack-structure :application
		     :redisplay-after-commands nil
		     :incrmental-redisplay nil
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
      interactor)))
  (:command-definer define-aplan-command)
  (:command-table aplan))


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
  (process-run-function 
      "Frame Top Level"
    #'(lambda ()
	(multiple-value-bind (width height) (screen-size)
	  (setq *editor* (clim:make-application-frame 'aplan
						      :pretty-name "Attack Planner"
						      #-allegro :parent #-allegro (clim:find-port)
						      :width (floor (* .7 width))
						      :height (floor (* .8 height)))))
	(clim:run-frame-top-level *editor*))))


(clim-env::define-lisp-listener-command (com-start-aplan :name t)
                                        ()
                                        (run-editor))