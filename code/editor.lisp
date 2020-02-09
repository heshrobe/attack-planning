;;; -*- Mode: Lisp; package: aplan; readtable: joshua; syntax: joshua -*-

(in-package :aplan) 

;; (defvar *component-map* (make-hash-table))

(clim:define-application-frame aplan
  ()
  ((current-diagram :initform nil :accessor current-diagram)   ; the current system description under simulation
   (display-output-tick :initform 0 :accessor display-output-tick )
   (attack-plan-collector :initform (make-instance 'attack-plan-collector) :accessor attack-plan-collector)
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
	 :max-height '(4 :line)
         :display-function '(clim:display-command-menu :n-columns 4 :row-wise t)
         :scroll-bars t
         :borders t
	 )
   (interactor :interactor
	       #-mcclim :initial-cursor-visibility #-mcclim :off
	       :scroll-bars :vertical
	       :end-of-line-action :wrap
	       :borders t)   
   (attack-structure :application
		     #+mcclim :display-time #+allegro :display-after-command nil
		     :incremental-redisplay nil
		     :scroll-bars t
		     :borders t
		     )
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

(defmethod final-states ((frame aplan))
  (let ((collector (attack-plan-collector frame)))
    (final-states collector)))

(defmethod all-action-sequences ((frame aplan))
  (all-action-sequences (attack-plan-collector frame)))

(defvar *editor* nil)
(defvar *process* nil)

(defun screen-size ()
  (let ((graft (clim:find-graft)))
    (clim:rectangle-size (clim:sheet-region graft))))

#+(and clim allegro)
(defun debugger-hook (condition hook)
  (declare (ignore hook))
  (let* ((*application-frame* *editor*)
	 (*error-output* (clim:frame-standard-output *application-frame*))
	 (stream (clim:get-frame-pane *application-frame* 'interactor)))
    (clim:stream-close-text-output-record stream)
    (clim-utils:letf-globally
        (((clim:stream-current-output-record stream) (clim:stream-output-history stream))
	 ((clim:stream-recording-p stream) t)
	 ((clim:stream-drawing-p stream) t)
	 ((clim-internals::stream-current-redisplay-record stream) nil))
      (setf (clim:command-menu-enabled 'clim-env:listener-restarts *application-frame*) t)
      (clim-env:enter-debugger condition stream :own-frame t ))))

(defmethod aplan-top-level ((frame aplan) &REST OPTIONS)
  (let ((*package* (find-package (string-upcase "aplan")))	
	(*debugger-hook* #+(and clim allegro) #'debugger-hook #-(and clim allegro) nil))
    (ji:with-joshua-readtable
	(APPLY #'clim:default-frame-top-level
		frame
		:prompt ">"
		OPTIONS))))

(defparameter *aplan-window-width* 900)
(defparameter *aplan-window-height* 700)
#-mcclim
(defun run-editor ()
  (#+allegro mp:process-run-function #+sbcl sb-thread:make-thread
      #+allegro "Attack Planner"
    #'(lambda ()
	(multiple-value-bind (width height) (screen-size)
	  (declare (ignore width height)) ;in case we do want to use screen size
	  (setq *editor* (clim:make-application-frame 'aplan
						      :pretty-name "Attack Planner"
						      #-allegro :parent #-allegro (clim:find-port)
						      :width *aplan-window-width*
						      :height *aplan-window-height*)))
	(clim:run-frame-top-level *editor*))
    #+sbcl :name #+sbcl "Attack Planner"))

#+mcclim
(defun run-editor (&key
		     (new-process t)
		     (debugger t)
		     (width 790)
		     (height 550)
		     port
		     frame-manager
		     (process-name "Attack-Planner")
		     (package :aplan))
  (let* ((fm (or frame-manager (clim:find-frame-manager :port (or port (clim:find-port)))))
	 (frame (clim:make-application-frame 'aplan
					     :pretty-name "Attack Planner"
					     :frame-manager fm
					     :width width
					     :height height)))
    (setq *editor* frame)
    (flet ((run ()
	     (let ((*package* (find-package package)))
	       (unwind-protect
		    (if debugger
			(clim-debugger:with-debugger () (clim:run-frame-top-level frame))
			(clim:disown-frame fm frame))))))
      (if new-process
	  (values (clim-sys:make-process #'run :name process-name)
		  frame)
	  (run)))))

#+clim-env
(clim-env::define-lisp-listener-command (com-start-aplan :name t)
    ()
  (run-editor))

#+mcclim
(clim-listener::define-listener-command (com-start-aplan :name t)
    ()
  (run-editor))
